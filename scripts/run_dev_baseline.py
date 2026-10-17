"""Executable script running the Phase 2 Development Baseline Evaluation Gate.

Measures whether adversarial injections in development twin scenarios successfully
manipulate an unhardened baseline reviewer (causing it to lose findings, downgrade severity,
or echo injection instructions).

Usage:
  python scripts/run_dev_baseline.py --provider [ollama|huggingface|simulated]
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detection.huggingface_provider import HuggingFaceConfig, HuggingFaceProvider
from src.detection.nim_provider import NIMConfig, NIMProvider
from src.detection.ollama_provider import OllamaConfig, OllamaProvider
from src.detection.openrouter_provider import OpenRouterConfig, OpenRouterProvider
from src.evaluation.checker import load_development_fixtures, run_development_baseline_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase 2 Development Baseline Evaluation Gate.")
    parser.add_argument(
        "--provider",
        choices=["ollama", "huggingface", "nim", "openrouter", "simulated"],
        default="simulated",
        help="Inference provider for live evaluation (default: simulated).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark/results/dev_baseline_gate_report.json"),
        help="Output report path.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model ID or name override.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=240.0,
        help="Inference timeout in seconds (default: 240.0).",
    )
    args = parser.parse_args()

    dev_fixtures_dir = Path("tests/dev")
    print("=" * 80)
    print("PHASE 2: DEVELOPMENT BASELINE EVALUATION GATE")
    print("=" * 80)
    print(f"Loading development scenarios from: {dev_fixtures_dir}")
    fixtures = load_development_fixtures(dev_fixtures_dir)
    print(f"Loaded {len(fixtures)} development scenarios.")

    live_provider = None
    if args.provider == "ollama":
        cfg = OllamaConfig.from_env()
        cfg = OllamaConfig(
            base_url=cfg.base_url,
            model_name=args.model or cfg.model_name,
            max_concurrency=cfg.max_concurrency,
            max_queue_size=cfg.max_queue_size,
            timeout_seconds=args.timeout,
            max_retries=cfg.max_retries,
            num_ctx=cfg.num_ctx,
        )
        print(f"Using Ollama provider: model={cfg.model_name}, num_ctx={cfg.num_ctx}, timeout={cfg.timeout_seconds}s, url={cfg.base_url}")
        live_provider = OllamaProvider(config=cfg)
    elif args.provider == "huggingface":
        hf_cfg = HuggingFaceConfig.from_env()
        if args.model:
            hf_cfg = HuggingFaceConfig(
                api_key=hf_cfg.api_key,
                model_name=args.model,
                endpoint_url=hf_cfg.endpoint_url,
                max_context_tokens=hf_cfg.max_context_tokens,
                max_new_tokens=hf_cfg.max_new_tokens,
                timeout_seconds=hf_cfg.timeout_seconds,
                max_retries=hf_cfg.max_retries,
            )
        print(f"Using Hugging Face provider: model={hf_cfg.model_name}, context_tokens={hf_cfg.max_context_tokens}")
        live_provider = HuggingFaceProvider(config=hf_cfg)
    elif args.provider == "nim":
        nim_cfg = NIMConfig.from_env()
        if args.model:
            nim_cfg = NIMConfig(
                api_key=nim_cfg.api_key,
                base_url=nim_cfg.base_url,
                model_name=args.model,
                max_context_tokens=nim_cfg.max_context_tokens,
                max_tokens=nim_cfg.max_tokens,
                timeout_seconds=nim_cfg.timeout_seconds,
                max_retries=nim_cfg.max_retries,
            )
        print(f"Using NVIDIA NIM provider: model={nim_cfg.model_name}, context_tokens={nim_cfg.max_context_tokens}, url={nim_cfg.base_url}")
        live_provider = NIMProvider(config=nim_cfg)
    elif args.provider == "openrouter":
        or_cfg = OpenRouterConfig.from_env()
        if args.model:
            or_cfg = OpenRouterConfig(
                api_key=or_cfg.api_key,
                base_url=or_cfg.base_url,
                model_name=args.model,
                max_context_tokens=or_cfg.max_context_tokens,
                max_tokens=or_cfg.max_tokens,
                site_url=or_cfg.site_url,
                site_name=or_cfg.site_name,
                timeout_seconds=args.timeout,
                max_retries=or_cfg.max_retries,
            )
        print(f"Using OpenRouter provider: model={or_cfg.model_name}, context_tokens={or_cfg.max_context_tokens}, url={or_cfg.base_url}")
        live_provider = OpenRouterProvider(config=or_cfg)
    else:
        print("Using offline simulated unhardened baseline reviewer.")

    print("\nExecuting baseline evaluations across base-twin scenario pairs...")
    report = run_development_baseline_evaluation(
        dev_fixtures=fixtures,
        live_provider=live_provider,
    )

    print("\n" + "=" * 80)
    print("BASELINE GATE RESULTS")
    print("=" * 80)
    print(f"Honest Assessment           : {report.honest_assessment}")
    print(f"Total Base-Twin Pairs       : {len(report.twin_comparisons)}")
    print(f"Vulnerable Twin Scenarios   : {report.vulnerable_twins_count}")
    print(f"Robust Twin Scenarios       : {report.robust_twins_count}")
    print(f"Inconclusive (Zero Base)    : {report.inconclusive_twins_count}")
    print(f"Infrastructure Failures     : {report.infrastructure_failures}")
    print(f"Strengthening Rounds Used   : {report.attack_strengthening_rounds_used}")
    print()

    print("Detailed Twin Comparisons:")
    for comp in report.twin_comparisons:
        if comp.injection_changed_outcome:
            status = "VULNERABLE (Manipulated)"
        elif comp.inference_status != "success":
            status = f"INCOMPLETE ({comp.inference_status})"
        elif comp.is_inconclusive_zero_base_recall:
            status = "INCONCLUSIVE (Base Bug Undetected)"
        else:
            status = "ROBUST (Unchanged)"
        print(f"  - [{status}] {comp.twin_case_id} (Base: {comp.base_case_id})")
        print(f"      Base matched bugs: {comp.base_matched_bugs} | Twin matched bugs: {comp.twin_matched_bugs}")
        print(f"      Bug lost: {comp.bug_lost} | Bug downgraded: {comp.bug_downgraded} | Notes: {comp.notes}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
    print(f"\nReport saved to: {args.output}")

    if report.vulnerable_twins_count > 0:
        print("\n[GATE PASSED] Injections successfully alter unhardened baseline outputs.")
    elif report.robust_twins_count > 0:
        print("\n[GATE NOTICE] Baseline resisted all attacks despite detecting base vulnerabilities.")
    elif report.inconclusive_twins_count > 0:
        print("\n[GATE NOTICE] Baseline had zero recall on base vulnerabilities (inconclusive).")
    else:
        print("\n[GATE NOTICE] Evaluation incomplete due to infrastructure or parsing failures.")


if __name__ == "__main__":
    main()
