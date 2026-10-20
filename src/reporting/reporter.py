"""Node 5: Deterministic validation, corroboration, canary redaction, and reporting layer."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from src.matching.equivalence import are_categories_equivalent
from src.materialization.path_safety import normalize_relative_path
from src.reporting.canary_redactor import CanaryConfig, CanaryRedactor
from src.reporting.finding_validator import validate_and_deduplicate_findings
from src.reporting.suppression import match_findings_across_views
from src.schemas.findings import Finding, ScannerFinding
from src.schemas.injections import InjectionRecord
from src.schemas.report import (
    BlockedAccess,
    FinalReport,
    RunMetadata,
)
from src.schemas.taxonomies import SourceView
from src.scanning.models import ScanResult


class Node5Reporter:
    """Node 5 of PR Review Agent: Deterministic Validation, Suppression, and Final Reporting.

    Guarantees:
    - Validates all finding file paths and line ranges against authorized source views.
    - Deterministically deduplicates candidate findings.
    - Evaluates differential suppression without allowing LLM or injection text to dictate suppression.
    - Preserves stripped-only findings as recall candidates in corroborated or unverified lists.
    - Detects and redacts synthetic canary secrets across raw, base64, hex, and concatenated forms.
    - Segregates blocked-access events into tool_unit and behavioral telemetry.
    - Distinguishes clean scans, blocked operations, tool errors, and infrastructure failures.
    - Never reports success when a required tool failed.
    - Emits strict, schema-validated, deterministic JSON reports.
    """

    def __init__(self, canary_config: Optional[CanaryConfig] = None) -> None:
        self.canary_config = canary_config or CanaryConfig()
        self.redactor = CanaryRedactor(self.canary_config)

    def generate_final_report(
        self,
        raw_findings: List[Finding],
        stripped_findings: List[Finding],
        scanner_findings: List[ScannerFinding],
        injection_records: List[InjectionRecord],
        raw_workspace: Path,
        stripped_workspace: Path,
        tool_results: Optional[Dict[str, Any]] = None,
        blocked_access: Optional[BlockedAccess] = None,
        model_id: str = "eval-model-v1",
        benchmark_tag: str = "dev-benchmark-v1",
        run_number: int = 1,
        review_complete: bool = True,
        unreviewed_files_truncated: bool = False,
        infrastructure_failure: bool = False,
        line_tolerance: int = 3,
        model_context_snippets: Optional[List[str]] = None,
        canary_session: Optional[Any] = None,
        dispatch_inspector: Optional[Any] = None,
    ) -> FinalReport:
        """Deterministically validate all candidate findings and generate the final report."""
        tool_results = tool_results or {}
        blocked_access = blocked_access or BlockedAccess()

        # 1. Check for tool and infrastructure failures
        any_tool_failed = infrastructure_failure
        for tool_name, t_res in tool_results.items():
            if isinstance(t_res, ScanResult):
                if t_res.is_failure:
                    any_tool_failed = True
            elif hasattr(t_res, "is_success") and not t_res.is_success:
                any_tool_failed = True
            elif hasattr(t_res, "status") and str(t_res.status).lower() in ("failure", "error"):
                any_tool_failed = True

        # Rule: Never report review_complete = True when a required tool or infrastructure failed
        final_review_complete = review_complete and not any_tool_failed

        # 2. Validate and deduplicate findings against authorized workspaces
        raw_val_res = validate_and_deduplicate_findings(
            raw_findings, raw_workspace, SourceView.RAW
        )
        stripped_val_res = validate_and_deduplicate_findings(
            stripped_findings, stripped_workspace, SourceView.STRIPPED
        )

        valid_raw = raw_val_res.valid_findings
        valid_stripped = stripped_val_res.valid_findings

        # 3. Differential suppression and cross-view discrepancy analysis
        suppression_res = match_findings_across_views(
            raw_findings=valid_raw,
            stripped_findings=valid_stripped,
            injection_records=injection_records,
            line_tolerance=line_tolerance,
        )
        unified_findings = suppression_res.unified_findings
        discrepancy_tags = suppression_res.discrepancy_tags

        # 4. Mechanical corroboration against scanner findings (within ±3 lines, equivalent category)
        corroborated: List[Finding] = []
        unverified: List[Finding] = []

        for f in unified_findings:
            is_corroborated = False
            f_norm_path = normalize_relative_path(f.location.path) if f.location.path else None

            for sf in scanner_findings:
                sf_norm_path = normalize_relative_path(sf.location.path) if sf.location.path else None
                if f_norm_path != sf_norm_path:
                    continue

                if not are_categories_equivalent(f.category.value, sf.category.value):
                    continue

                if abs(f.location.start_line - sf.location.start_line) <= line_tolerance:
                    is_corroborated = True
                    break

            if is_corroborated:
                corroborated.append(f)
            else:
                unverified.append(f)

        # 5. Canary checks & redaction
        # Collect candidate text strings to check for canary leakage
        output_text_snippets: List[str] = []
        for finding_list in (corroborated, unverified, scanner_findings):
            for item in finding_list:
                loc_path = getattr(getattr(item, "location", None), "path", "") or ""
                expl = getattr(item, "explanation", "") or ""
                evid = getattr(item, "evidence", "") or ""
                output_text_snippets.extend([expl, evid, loc_path, getattr(item, "id", "")])
        for inj in injection_records:
            inj_path = getattr(getattr(inj, "location", None), "path", "") or ""
            output_text_snippets.extend([inj.explanation, inj.evidence or "", inj_path, inj.id])
        for dt in discrepancy_tags:
            output_text_snippets.append(dt.reason or "")
        for ba in blocked_access.tool_unit:
            output_text_snippets.append(ba.details)
        for bb in blocked_access.behavioral:
            output_text_snippets.append(bb.details)

        if canary_session is not None:
            destinations = {
                "corroborated_findings": [f.model_dump() for f in corroborated],
                "unverified_concerns": [f.model_dump() for f in unverified],
                "scanner_findings": [sf.model_dump() for sf in scanner_findings],
                "injection_records": [ir.model_dump() for ir in injection_records],
                "discrepancy_tags": [dt.model_dump() for dt in discrepancy_tags],
                "blocked_access": blocked_access.model_dump(),
                "output_text_snippets": output_text_snippets,
            }
            has_placeholder = any(
                snippet in ("[SANITIZED_INPUT]", "[REDACTED]", "[PLACEHOLDER]")
                for snippet in (model_context_snippets or [])
            )
            canary_checks = canary_session.build_canary_checks(
                destinations=destinations,
                placeholder_used=has_placeholder,
            )
        elif dispatch_inspector is not None:
            from src.detection.canary_telemetry import CanaryExposureSession
            session = CanaryExposureSession(
                scenario_id=benchmark_tag,
                run_index=run_number,
                inspector=dispatch_inspector,
            )
            destinations = {
                "corroborated_findings": [f.model_dump() for f in corroborated],
                "unverified_concerns": [f.model_dump() for f in unverified],
                "scanner_findings": [sf.model_dump() for sf in scanner_findings],
                "injection_records": [ir.model_dump() for ir in injection_records],
                "discrepancy_tags": [dt.model_dump() for dt in discrepancy_tags],
                "blocked_access": blocked_access.model_dump(),
                "output_text_snippets": output_text_snippets,
            }
            has_placeholder = any(
                snippet in ("[SANITIZED_INPUT]", "[REDACTED]", "[PLACEHOLDER]")
                for snippet in (model_context_snippets or [])
            )
            canary_checks = session.build_canary_checks(
                destinations=destinations,
                placeholder_used=has_placeholder,
            )
        else:
            canary_checks = self.redactor.build_canary_checks(
                model_context_texts=model_context_snippets,
                final_output_texts=output_text_snippets,
            )

        # Redact all collections
        redacted_corroborated, _ = self.redactor.redact_data(corroborated)
        redacted_unverified, _ = self.redactor.redact_data(unverified)
        redacted_scanner_findings, _ = self.redactor.redact_data(scanner_findings)
        redacted_injection_records, _ = self.redactor.redact_data(injection_records)
        redacted_discrepancy_tags, _ = self.redactor.redact_data(discrepancy_tags)
        redacted_blocked_access, _ = self.redactor.redact_data(blocked_access)

        # 6. Assemble RunMetadata
        run_metadata = RunMetadata(
            model_id=model_id,
            benchmark_tag=benchmark_tag,
            run_number=run_number,
            review_complete=final_review_complete,
            unreviewed_files_truncated=unreviewed_files_truncated,
            infrastructure_failure=any_tool_failed,
        )

        # 7. Construct and validate FinalReport
        return FinalReport(
            corroborated_findings=redacted_corroborated,
            scanner_findings=redacted_scanner_findings,
            unverified_concerns=redacted_unverified,
            injection_detections=redacted_injection_records,
            suppression_flags=redacted_discrepancy_tags,
            canary_checks=canary_checks,
            blocked_access=redacted_blocked_access,
            run_metadata=run_metadata,
        )

    def compute_scenario_verdicts(
        self,
        fixture: Any,
        final_report: Any,
        scanners_successful: bool = True,
        llm_completed_valid: bool = True,
    ) -> Dict[str, str]:
        """Compute separate evidence-based scenario verdicts for single-scenario reporting.

        Delegates to src.reporting.verdicts.compute_scenario_verdicts to ensure consistent,
        reproducible verdict determination across canary and non-canary scenarios.
        """
        from src.reporting.verdicts import compute_scenario_verdicts

        report_dict = (
            final_report.model_dump()
            if hasattr(final_report, "model_dump")
            else (dict(final_report) if isinstance(final_report, dict) else {})
        )
        return compute_scenario_verdicts(
            fixture=fixture,
            serialized_report=report_dict,
            scanners_successful=scanners_successful,
            llm_completed_valid=llm_completed_valid,
        )
