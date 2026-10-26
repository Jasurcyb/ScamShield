"""Calibrated fraud probability instead of a hand-written lookup table.

The numbers come from the eval dataset (eval/BASELINE.md), not from intuition:
- P(scam | predicted high)  = precision = 35/35 = 1.00  -> but smoothed below
- P(scam | predicted low)   = fn/(fn+tn) = 2/36  = 0.056

A logistic (Platt-style) model maps a deterministic score to a probability:
    logit(p) = base_logodds(tier) + FINDINGS_BONUS * min(n_findings, 4)
where base_logodds is the empirical log-odds of the tier's measured accuracy,
smoothed with a Laplace-style prior so precision=1.0 does not claim 100%.
"""

from __future__ import annotations

import math

# Empirical rates from eval/BASELINE.md (deterministic layer), Laplace-smoothed:
#   high: (35+1)/(35+2) = 0.972 ; low: (2+1)/(36+2) = 0.079
_P_HIGH = 36.0 / 37.0
_P_LOW = 3.0 / 38.0
_P_MEDIUM = 0.5  # medium tier is not produced by the deterministic layer

_BASE_LOGODDS = {
    "critical": math.log(_P_HIGH / (1 - _P_HIGH)) + 0.5,
    "high": math.log(_P_HIGH / (1 - _P_HIGH)),
    "medium": math.log(_P_MEDIUM / (1 - _P_MEDIUM)),
    "low": math.log(_P_LOW / (1 - _P_LOW)),
    "unknown": math.log(_P_LOW / (1 - _P_LOW)),
}

# Each independent deterministic finding adds evidence (capped).
FINDINGS_BONUS = 0.7
MAX_FINDINGS = 4


def fraud_probability(risk_level: str, n_findings: int = 0) -> int:
    """Return a calibrated 0-100 fraud probability for a verdict."""
    base = _BASE_LOGODDS.get(risk_level, _BASE_LOGODDS["unknown"])
    logodds = base + FINDINGS_BONUS * min(max(n_findings, 0), MAX_FINDINGS)
    p = 1.0 / (1.0 + math.exp(-logodds))
    return int(round(p * 100))


def count_findings(agent_reports: dict) -> int:
    """Total deterministic findings across agent reports (for calibration input)."""
    total = 0
    for report in (agent_reports or {}).values():
        if not isinstance(report, dict):
            continue
        for key in ("text_findings", "visual_findings"):
            value = report.get(key)
            if isinstance(value, list):
                total += len(value)
        lsb = report.get("lsb_findings")
        if isinstance(lsb, dict):
            total += sum(
                1 for sub in lsb.values()
                if isinstance(sub, dict) and sub.get("status") == "warning"
            )
    return total
