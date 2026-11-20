"""Data model."""

from __future__ import annotations

from web_enum.models import Severity


def test_severity_rank_orders_most_severe_first() -> None:
    shuffled = [Severity.INFO, Severity.HIGH, Severity.LOW, Severity.MEDIUM]
    assert sorted(shuffled, key=lambda s: s.rank) == [
        Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def test_severity_serialises_as_plain_string() -> None:
    assert Severity("medium") is Severity.MEDIUM
    assert Severity.HIGH.value == "high"
