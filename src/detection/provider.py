"""Provider-independent interfaces and concrete adapters for LLM execution."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.detection.models import ProviderError, ProviderMetadata


class ProviderResponse(BaseModel):
    """Raw response and provenance metadata from an LLM provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str = Field(description="Raw text content returned by the model.")
    metadata: ProviderMetadata = Field(description="Provider and execution metadata.")


class LLMProvider(ABC):
    """Abstract provider-independent interface for LLM completions."""

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Execute a text completion or chat response at temperature 0.0."""
        pass


class MockLLMProvider(LLMProvider):
    """Mock LLM provider for deterministic, offline unit testing without external APIs."""

    def __init__(
        self,
        canned_response: Optional[str] = None,
        canned_responses: Optional[List[str]] = None,
        handler: Optional[Callable[[str, Optional[str], float], str]] = None,
        error: Optional[Exception] = None,
        provider_name: str = "mock",
        model_name: str = "mock-deterministic-v1",
        model_version: Optional[str] = "1.0.0",
        extra_config: Optional[Dict[str, Any]] = None,
        dispatch_inspector: Optional[Any] = None,
        enforce_canary_inspection: bool = False,
    ) -> None:
        self.canned_response = canned_response
        self.canned_responses = list(canned_responses) if canned_responses else []
        self.handler = handler
        self.error = error
        self.provider_name = provider_name
        self.model_name = model_name
        self.model_version = model_version
        self.extra_config = extra_config or {}
        self.dispatch_inspector = dispatch_inspector
        self.enforce_canary_inspection = enforce_canary_inspection
        self.call_history: List[Dict[str, Any]] = []

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        self.call_history.append({
            "prompt": prompt,
            "system_prompt": system_prompt,
            "temperature": temperature,
            "correlation_context": correlation_context,
        })

        requires_inspection = (
            self.enforce_canary_inspection
            or (
                correlation_context is not None
                and getattr(correlation_context, "enforce_canary_inspection", False)
            )
        )

        inspection_record = None
        if self.dispatch_inspector is not None:
            import json
            from src.detection.canary_telemetry import InspectionStatus, RequestCorrelationContext
            ctx = correlation_context
            if not isinstance(ctx, RequestCorrelationContext):
                ctx = RequestCorrelationContext(
                    scenario_id=getattr(ctx, "scenario_id", "mock"),
                    node_id=getattr(ctx, "node_id", "mock_node"),
                    model_name=self.model_name,
                )
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "system": system_prompt or "",
                "options": {"temperature": temperature},
            }
            payload_bytes = json.dumps(payload).encode("utf-8")
            try:
                inspection_record = self.dispatch_inspector.inspect_serialized_payload(
                    payload_bytes,
                    context=ctx,
                    dispatched=False,
                )
            except Exception as exc:
                clean_msg = f"MockLLMProvider canary inspection failed ({type(exc).__name__}); dispatch blocked fail-closed."
                raise ProviderError(clean_msg) from exc

            if (
                inspection_record is None
                or not hasattr(inspection_record, "inspection_status")
                or inspection_record.inspection_status != InspectionStatus.COMPLETED
            ):
                raise ProviderError(
                    "MockLLMProvider canary inspection did not complete successfully; dispatch blocked fail-closed."
                )
        elif requires_inspection:
            raise ProviderError(
                "MockLLMProvider cannot perform security-sensitive reviews without a configured dispatch_inspector."
            )

        if self.error:
            if isinstance(self.error, ProviderError):
                raise self.error
            raise ProviderError(f"Mock provider simulated failure: {self.error}") from self.error

        if self.handler:
            content = self.handler(prompt, system_prompt, temperature)
        elif self.canned_responses:
            content = self.canned_responses.pop(0)
        elif self.canned_response is not None:
            content = self.canned_response
        else:
            content = '{"records": []}'

        if inspection_record is not None and hasattr(inspection_record, "mark_dispatched"):
            inspection_record.mark_dispatched()

        metadata = ProviderMetadata(
            provider_name=self.provider_name,
            model_name=self.model_name,
            model_version=self.model_version,
            temperature=temperature,
            extra_config=dict(self.extra_config),
        )

        return ProviderResponse(content=content, metadata=metadata)


class LangChainProvider(LLMProvider):
    """Adapter wrapping LangChain chat models behind the provider-independent interface."""

    def __init__(
        self,
        chat_model: Any,
        provider_name: str = "langchain",
        model_name: Optional[str] = None,
        model_version: Optional[str] = None,
        extra_config: Optional[Dict[str, Any]] = None,
        enforce_canary_inspection: bool = False,
    ) -> None:
        self.chat_model = chat_model
        self.provider_name = provider_name
        self.model_name = model_name or getattr(chat_model, "model_name", None) or getattr(chat_model, "model", "langchain-model")
        self.model_version = model_version
        self.extra_config = extra_config or {}
        self.enforce_canary_inspection = enforce_canary_inspection

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        correlation_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        requires_inspection = (
            self.enforce_canary_inspection
            or correlation_context is not None
        )
        if requires_inspection:
            raise ProviderError(
                "LangChainProvider does not support wire-level canary telemetry inspection "
                "and is explicitly rejected for security-sensitive reviews."
            )
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
        except ImportError as err:
            raise ProviderError("langchain_core is not installed or available.") from err

        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=prompt))

        try:
            # Enforce temperature 0.0 when supported by the underlying model
            if hasattr(self.chat_model, "temperature"):
                try:
                    self.chat_model.temperature = 0.0
                except (AttributeError, TypeError):
                    pass

            response = self.chat_model.invoke(messages)
            content = response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            raise ProviderError(f"LangChain chat model invocation failed: {exc}") from exc

        # Sanitize metadata so no API keys or credentials can ever leak
        sanitized_config: Dict[str, Any] = {}
        for k, v in self.extra_config.items():
            if not any(s in k.lower() for s in ("key", "secret", "token", "auth")):
                sanitized_config[k] = v

        metadata = ProviderMetadata(
            provider_name=self.provider_name,
            model_name=str(self.model_name),
            model_version=self.model_version,
            temperature=0.0,
            extra_config=sanitized_config,
        )

        return ProviderResponse(content=content, metadata=metadata)


