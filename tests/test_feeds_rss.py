"""Tests puros de la lógica de conversión entrada RSS -> menciones."""

from __future__ import annotations

from app.sources.feeds_rss import _mentions_for_entry


def test_single_cve_bundles_aliases():
    # 1 CVE + ZDI-CAN en la misma entrada -> 1 mención, aliases juntos (misma vuln).
    ms = _mentions_for_entry("RCE in Foo (CVE-2026-1000, ZDI-CAN-26123)", "", "u", None)
    assert len(ms) == 1
    assert ms[0].cve_id == "CVE-2026-1000"
    assert ms[0].extra_ids == ["ZDI-CAN-26123"]


def test_multiple_cves_split():
    # Varias vulns en un boletín -> 1 mención por CVE, sin bundlear (no over-merge).
    ms = _mentions_for_entry("Siemens advisory",
                             "Fixes CVE-2026-1001 CVE-2026-1002 CVE-2026-1003", "u", None)
    assert {m.cve_id for m in ms} == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
    assert all(m.extra_ids is None for m in ms)


def test_zdi_can_only_pre_cve():
    # ZDI upcoming: sin CVE pero con ZDI-CAN -> ancla por ese código (pre-CVE).
    ms = _mentions_for_entry("Upcoming advisory ZDI-CAN-27000", "", "u", None)
    assert len(ms) == 1
    assert ms[0].cve_id is None
    assert ms[0].native_id == "ZDI-CAN-27000"


def test_no_recognized_id_is_dropped():
    ms = _mentions_for_entry("Generic security news, no identifiers", "blah blah", "u", None)
    assert ms == []
