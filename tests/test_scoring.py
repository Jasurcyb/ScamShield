"""Calibrated probability behaviour (eval-derived, monotone, bounded)."""

from __future__ import annotations

from app import scoring


def test_probability_is_bounded_and_ordered():
    low = scoring.fraud_probability("low", 0)
    high = scoring.fraud_probability("high", 0)
    critical = scoring.fraud_probability("critical", 0)
    assert 0 <= low < high < critical <= 100


def test_findings_increase_probability_monotonically():
    values = [scoring.fraud_probability("high", k) for k in range(0, 8)]
    assert values == sorted(values)
    assert values[-1] > values[0]
    assert values[4] == values[5]  # capped at MAX_FINDINGS


def test_high_tier_reflects_measured_precision_not_certainty():
    # Empirical precision was 1.0 but smoothed: must not claim 100%.
    assert scoring.fraud_probability("high", 0) < 100
    assert scoring.fraud_probability("high", 0) > 80


def test_low_tier_reflects_measured_false_negative_rate():
    p = scoring.fraud_probability("low", 0)
    assert 0 < p < 20  # ~8% smoothed FN rate, not a flat 15


def test_count_findings_aggregates_agents():
    reports = {
        "text": {"text_findings": ["a", "b"]},
        "vision": {"visual_findings": ["c"]},
        "stego": {"lsb_findings": {"lsb_anomaly": {"status": "warning"}, "hist": {"status": "ok"}}},
    }
    assert scoring.count_findings(reports) == 4
