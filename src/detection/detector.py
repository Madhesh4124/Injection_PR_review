"""Node 4: Structured Injection Detector implementation."""

import json
import re
import time
from typing import Any, Optional
from pydantic import ValidationError

from src.detection.models import (
    MAX_OUTPUT_CHARS,
    InjectionDetectionRequest,
    InjectionDetectionResult,
    InjectionDetectorOutput,
    MalformedDetectorOutputError,
    OversizedInputError,
    ProviderError,
    ProviderMetadata,
)
from src.detection.prompts import NODE4_SYSTEM_PROMPT, format_node4_user_prompt
from src.detection.provider import LLMProvider

FENCED_JSON_REGEX = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


class Node4InjectionDetector:
    """Node 4 of the PR Review Agent: Structured Injection Analysis.

    Guarantees:
    - No tools available, no shell execution, no arbitrary filesystem access.
    - Strict classification into exactly four configured injection classes.
    - Rejects malformed output, prose, and extra/unsupported fields.
    - Enforces input context limits and output text size limits.
    - Uses temperature 0.0 when supported.
    - Records sanitized provider metadata without logging secrets.
    - Never independently authorizes access, suppresses findings, or decides scores.
    """

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def detect_injections(
        self,
        raw_diff: str,
        pr_description: str,
        readme_content: Optional[str] = None,
        raise_on_error: bool = False,
        correlation_context: Optional[Any] = None,
        scenario_id: Optional[str] = None,
        run_index: int = 0,
    ) -> InjectionDetectionResult:
        """Analyze untrusted PR inputs and return structured InjectionRecord instances."""
        start_time = time.monotonic()
        fallback_metadata = ProviderMetadata(
            provider_name=getattr(self.provider, "provider_name", "unknown"),
            model_name=getattr(self.provider, "model_name", "unknown"),
            temperature=0.0,
        )

        ctx = correlation_context
        if ctx is None and (scenario_id is not None or hasattr(self.provider, "dispatch_inspector")):
            from src.detection.canary_telemetry import RequestCorrelationContext
            ctx = RequestCorrelationContext(
                scenario_id=scenario_id or "unknown",
                run_index=run_index,
                node_id="node4",
                model_name=getattr(self.provider, "model_name", "unknown"),
            )

        # 1. Validate inputs and enforce size limits
        try:
            req = InjectionDetectionRequest(
                raw_diff=raw_diff,
                pr_description=pr_description,
                readme_content=readme_content,
            )
        except (OversizedInputError, ValidationError) as err:
            duration = round(time.monotonic() - start_time, 3)
            err_str = str(err)
            is_oversized = "exceeds limit" in err_str or isinstance(err, OversizedInputError)
            if raise_on_error:
                if is_oversized:
                    raise OversizedInputError(err_str) from err
                raise
            return InjectionDetectionResult(
                records=[],
                provider_metadata=fallback_metadata,
                error=f"Input rejected due to context limits: {err_str}",
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = round(time.monotonic() - start_time, 3)
            if raise_on_error:
                raise
            return InjectionDetectionResult(
                records=[],
                provider_metadata=fallback_metadata,
                error=f"Invalid request parameters: {exc}",
                duration_seconds=duration,
            )

        # 2. Format user prompt with strict isolation delimiters
        user_prompt = format_node4_user_prompt(
            raw_diff=req.raw_diff,
            pr_description=req.pr_description,
            readme_content=req.readme_content,
        )

        # 3. Invoke provider at temperature 0.0 (no tools)
        try:
            call_kwargs = {}
            if ctx is not None:
                import inspect

                sig = inspect.signature(self.provider.complete)
                if "correlation_context" in sig.parameters or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                ):
                    call_kwargs["correlation_context"] = ctx

            resp = self.provider.complete(
                prompt=user_prompt,
                system_prompt=NODE4_SYSTEM_PROMPT,
                temperature=0.0,
                **call_kwargs,
            )
        except ProviderError as err:
            duration = round(time.monotonic() - start_time, 3)
            if raise_on_error:
                raise
            return InjectionDetectionResult(
                records=[],
                provider_metadata=fallback_metadata,
                error=f"LLM Provider failure: {err}",
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = round(time.monotonic() - start_time, 3)
            if raise_on_error:
                raise ProviderError(f"Unexpected provider invocation error: {exc}") from exc
            return InjectionDetectionResult(
                records=[],
                provider_metadata=fallback_metadata,
                error=f"Unexpected provider invocation error: {exc}",
                duration_seconds=duration,
            )

        duration = round(time.monotonic() - start_time, 3)
        raw_text = resp.content

        # 4. Enforce output text length limit
        if len(raw_text) > MAX_OUTPUT_CHARS:
            err_msg = f"Model output length ({len(raw_text)} chars) exceeds limit ({MAX_OUTPUT_CHARS} chars)."
            if raise_on_error:
                raise MalformedDetectorOutputError(err_msg)
            return InjectionDetectionResult(
                records=[],
                provider_metadata=resp.metadata,
                raw_response=raw_text[:1000] + "... [TRUNCATED]",
                error=err_msg,
                duration_seconds=duration,
            )

        # 5. Extract and parse JSON
        cleaned_json = raw_text.strip()
        fenced_match = FENCED_JSON_REGEX.search(cleaned_json)
        if fenced_match:
            cleaned_json = fenced_match.group(1).strip()

        try:
            parsed = json.loads(cleaned_json)
        except json.JSONDecodeError as json_err:
            err_msg = f"Model response could not be parsed as valid JSON: {json_err}"
            if raise_on_error:
                raise MalformedDetectorOutputError(err_msg) from json_err
            return InjectionDetectionResult(
                records=[],
                provider_metadata=resp.metadata,
                raw_response=raw_text[:MAX_OUTPUT_CHARS],
                error=err_msg,
                duration_seconds=duration,
            )

        # 6. Strictly validate against Pydantic schema
        try:
            if isinstance(parsed, dict) and "records" in parsed:
                detector_output = InjectionDetectorOutput.model_validate(parsed)
            elif isinstance(parsed, list):
                detector_output = InjectionDetectorOutput.model_validate({"records": parsed})
            else:
                raise ValueError("JSON root must be an object with a 'records' key or a list of records.")
        except (ValidationError, ValueError) as val_err:
            err_msg = f"Model output violated strict InjectionRecord schema: {val_err}"
            if raise_on_error:
                raise MalformedDetectorOutputError(err_msg) from val_err
            return InjectionDetectionResult(
                records=[],
                provider_metadata=resp.metadata,
                raw_response=raw_text[:MAX_OUTPUT_CHARS],
                error=err_msg,
                duration_seconds=duration,
            )

        return InjectionDetectionResult(
            records=detector_output.records,
            provider_metadata=resp.metadata,
            raw_response=raw_text[:MAX_OUTPUT_CHARS],
            error=None,
            duration_seconds=duration,
        )
