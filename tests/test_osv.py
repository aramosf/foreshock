"""Tests puros del parseo OSV (rangos afectados y cap por recencia)."""

from __future__ import annotations

from app.sources.osv import _affected


def test_affected_multiple_introduced_fixed_pairs():
    """Un range con varios pares introduced/fixed produce UN VersionRangeInput
    por par (antes se colapsaban en uno solo y se perdían los intermedios)."""
    rec = {"affected": [{
        "package": {"ecosystem": "PyPI", "name": "acme"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.2"},
            {"introduced": "2.0"}, {"fixed": "2.5"},
        ]}],
    }]}
    items, _ = _affected(rec, is_malware=False)
    assert len(items) == 1
    ranges = items[0].ranges
    assert len(ranges) == 2
    assert (ranges[0].introduced, ranges[0].fixed) == ("0", "1.2")
    assert (ranges[1].introduced, ranges[1].fixed) == ("2.0", "2.5")


def test_affected_last_affected_closes_range():
    rec = {"affected": [{
        "package": {"ecosystem": "Go", "name": "acme/mod"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0"}, {"last_affected": "1.9"},
        ]}],
    }]}
    items, _ = _affected(rec, is_malware=False)
    (rng,) = items[0].ranges
    assert rng.introduced == "1.0" and rng.last_affected == "1.9" and rng.fixed is None


def test_affected_single_pair_unchanged():
    rec = {"affected": [{
        "package": {"ecosystem": "PyPI", "name": "acme"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "3.1.4"},
        ]}],
    }]}
    items, _ = _affected(rec, is_malware=False)
    (rng,) = items[0].ranges
    assert rng.introduced == "0" and rng.fixed == "3.1.4"
