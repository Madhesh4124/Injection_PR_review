"""Executable script running the official Frozen Benchmark Evaluation Protocol.

Protocol:
- 50 frozen scenarios x 2 systems (baseline & defended) x 3 runs = 300 planned evaluations.
- Caching is explicitly disabled (cache_enabled=False).
- Complete raw records preserved in benchmark/results/frozen_benchmark_report.json.
- Calculates baseline and defended metrics separately.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.harness import EvaluationConfig, FrozenEvaluationHarness


def main() -> None:
    print("=" * 80)
    print("EXECUTING FROZEN BENCHMARK EVALUATION PROTOCOL")
    print("=" * 80)
    print("Planned: 50 scenarios x 2 systems (baseline & defended) x 3 runs = 300 evaluations.")
    print("Caching: STRICTLY DISABLED (cache_enabled=False)")
    print()

    config = EvaluationConfig(
        scenarios_dir=Path("benchmark/scenarios"),
        output_dir=Path("benchmark/results"),
        runs_per_case=3,
        cache_enabled=False,
    )

    harness = FrozenEvaluationHarness(config=config)
    report = harness.execute_benchmark(systems=["baseline", "defended"])

    print("=" * 80)
    print("BENCHMARK EXECUTION COMPLETE")
    print("=" * 80)
    print(f"Git Commit         : {report.git_commit}")
    print(f"Model ID           : {report.model_id}")
    print(f"Ollama Version     : {report.ollama_version}")
    print(f"Docker Digest      : {report.docker_image_digest}")
    print(f"Total Evaluations  : {len(report.individual_run_results)}")
    print(f"Output Artifact    : {config.output_dir / 'frozen_benchmark_report.json'}")
    print()

    # Denominators and completion
    baseline_runs = [r for r in report.individual_run_results if r.system_id == "baseline"]
    defended_runs = [r for r in report.individual_run_results if r.system_id == "defended"]

    print("--- Completion Accounting ---")
    print(f"Baseline Planned   : 150 | Completed: {len(baseline_runs)} | Failures: {report.baseline_metrics.infrastructure_failures_count if report.baseline_metrics else 0}")
    print(f"Defended Planned   : 150 | Completed: {len(defended_runs)} | Failures: {report.defended_metrics.infrastructure_failures_count if report.defended_metrics else 0}")
    print(f"Total Completed    : {len(baseline_runs) + len(defended_runs)} / 300")
    print()

    print("--- Metric Denominators ---")
    if report.defended_metrics:
        dm = report.defended_metrics
        print(f"Base Bugs Denominator (all planned): {dm.base_bugs_total} (10 cases x 3 runs)")
        print(f"Base Bugs Denominator (completed)  : {dm.base_completed_bugs_total}")
        print(f"Twin Bugs Denominator (all planned): {dm.twin_bugs_total} (15 cases x 3 runs)")
        print(f"Twin Bugs Denominator (completed)  : {dm.twin_completed_bugs_total}")
        print(f"Planted Injections Denominator     : {dm.planted_injections_total} (15 twin cases x 3 runs)")
        print(f"Eligible Twin Pairs Denominator    : {dm.eligible_twin_pairs_count}")
        print(f"Clean PR Runs Denominator          : {dm.clean_prs_count * 3} (10 cases x 3 runs)")
        print(f"Hard Negative Runs Denominator     : {dm.hard_negatives_count * 3} (5 cases x 3 runs)")
        print(f"Canary Planned Runs Denominator    : {dm.canary_runs_total} (5 cases x 3 runs)")
        print(f"Scripted Access Probes Denominator : {dm.scripted_access_probe_runs} (5 cases x 3 runs)")
    print()


if __name__ == "__main__":
    main()
