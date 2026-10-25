"""Offline evaluation of ScamShield's deterministic detection layer.

Usage:
    python eval/run_eval.py             # deterministic layer only (offline, free)
    python eval/run_eval.py --with-llm  # full pipeline incl. cloud LLM (spends API credits)

Deterministic cases (layer="deterministic") are judged on heuristics only:
typosquat/punycode/IP-literal detection via tools.text_url_tool. The risk
prediction rule mirrors the production merge logic: any heuristic finding
raises the verdict to "high".

Cases marked layer="llm_required" (social engineering without URLs, shorteners,
raw-IP links) cannot be judged offline; they are counted and listed, and with
--with-llm they are evaluated through the full pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from tools.text_url_tool import _check_url_heuristics, _extract_urls  # noqa: E402


def load_dataset(path: Path) -> list[dict]:
    cases = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"dataset.jsonl:{line_number}: invalid JSON — {exc}")
    return cases


def deterministic_findings(text: str) -> list[str]:
    findings: list[str] = []
    for url in _extract_urls(text):
        findings.extend(_check_url_heuristics(url))
    return findings


def evaluate_deterministic(cases: list[dict]) -> dict:
    confusion = Counter()
    missed_must_find: list[str] = []
    false_positives: list[str] = []

    for case in cases:
        findings = deterministic_findings(case["content"])
        predicted = "high" if findings else "low"
        expected = case["expected"]["risk"]

        key = ("det" if predicted == expected else "mis", predicted, expected)
        confusion[key] += 1

        for needle in case["expected"].get("must_find", []):
            if not any(needle in finding for finding in findings):
                missed_must_find.append(case["id"])

        if predicted == "high" and expected == "low":
            false_positives.append(case["id"])

    total = len(cases)
    tp = sum(v for (ok, p, e), v in confusion.items() if ok == "det" and p == "high" and e == "high")
    fp = sum(v for (ok, p, e), v in confusion.items() if p == "high" and e == "low")
    fn = sum(v for (ok, p, e), v in confusion.items() if p == "low" and e == "high")
    tn = sum(v for (ok, p, e), v in confusion.items() if ok == "det" and p == "low" and e == "low")

    return {
        "total": total,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "missed_must_find": missed_must_find,
        "false_positives": false_positives,
    }


async def evaluate_full(cases: list[dict]) -> dict:
    from tools.text_url_tool import text_url_fraud_tool

    results = []
    for case in cases:
        result = await text_url_fraud_tool(case["content"], language="en")
        findings = result.get("text_findings", [])
        predicted = result.get("risk_level", "unknown")
        norm = "high" if predicted in {"high", "critical"} else ("low" if predicted == "low" else "unknown")
        expected = case["expected"]["risk"]
        results.append((case, norm, expected, findings))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-llm", action="store_true",
                        help="also evaluate the full pipeline with a cloud LLM (spends credits)")
    args = parser.parse_args()

    dataset_path = Path(__file__).resolve().parent / "dataset.jsonl"
    cases = load_dataset(dataset_path)

    deterministic_cases = [c for c in cases if c["layer"] == "deterministic"]
    llm_cases = [c for c in cases if c["layer"] == "llm_required"]

    print(f"ScamShield eval — dataset: {len(cases)} cases "
          f"({len(deterministic_cases)} deterministic, {len(llm_cases)} llm_required)")
    print()

    stats = evaluate_deterministic(deterministic_cases)
    print("── Deterministic layer (offline) ─────────────────────────")
    print(f"  accuracy : {stats['accuracy']:.1%}  ({stats['tp'] + stats['tn']}/{stats['total']})")
    print(f"  precision: {stats['precision']:.1%}  (tp={stats['tp']}, fp={stats['fp']})")
    print(f"  recall   : {stats['recall']:.1%}  (tp={stats['tp']}, fn={stats['fn']})")
    if stats["missed_must_find"]:
        print(f"  missed must_find ({len(stats['missed_must_find'])}): {', '.join(stats['missed_must_find'])}")
    if stats["false_positives"]:
        print(f"  false positives ({len(stats['false_positives'])}): {', '.join(stats['false_positives'])}")
    print()

    print(f"── LLM-required cases: {len(llm_cases)} (skipped offline; judged only with --with-llm)")
    if args.with_llm:
        if not os.environ.get("FIREWORKS_API_KEY") and not os.environ.get("GEMINI_API_KEY") \
                and not os.environ.get("ANTHROPIC_API_KEY"):
            print("  no provider key set — skipping full evaluation")
            return 1
        print("  running full pipeline…")
        results = asyncio.run(evaluate_full(cases))
        hits = sum(1 for _, norm, expected, _ in results
                   if (norm == "high") == (expected in {"high"}) and not (norm == "low" and expected == "low" and False))
        agree = sum(1 for _, norm, expected, _ in results
                    if (norm == "high" and expected == "high") or (norm == "low" and expected == "low"))
        print(f"  full-pipeline agreement on clear-cut cases: {agree}/{len(cases)}")
        for case, norm, expected, findings in results:
            if norm != expected and expected != "unknown":
                print(f"    mismatch {case['id']}: predicted={norm} expected={expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
