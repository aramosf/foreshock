"""Tests del whitelist de flags aplicados a candidates (unit, sin BD)."""

from datetime import date

from app.core.models import Candidate
from app.ingest.service import _apply_flags


def test_apply_kev_flags():
    c = Candidate(status="emerging")
    _apply_flags(c, {"in_kev": True, "kev_date": date(2026, 7, 1), "kev_source": "cisa"})
    assert c.in_kev is True
    assert c.kev_date == date(2026, 7, 1)
    assert c.kev_source == "cisa"


def test_apply_flags_ignores_non_whitelisted():
    c = Candidate(status="emerging")
    _apply_flags(c, {"status": "hacked", "cve_id": "CVE-9999-9999"})
    assert c.status == "emerging"       # no lo pisa
    assert c.cve_id is None


def test_apply_flags_none_is_noop():
    c = Candidate(status="candidate")
    _apply_flags(c, None)
    assert c.in_kev is None
