"""Tests unitarios del parser de github_repo_advisories (sin red ni BD)."""

from datetime import UTC, datetime

from app.sources.github_repo_advisories import (
    _advisory_mention,
    _emit,
    _release_mentions,
)


def test_advisory_con_cve_y_ghsa_producto_del_paquete():
    adv = {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2013-1234",
        "summary": "Heap overflow en afpd",
        "published_at": "2013-05-10T00:00:00Z",
        "html_url": "https://github.com/Netatalk/netatalk/security/advisories/GHSA-xxxx-yyyy-zzzz",
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "foo"}}],
        "cwes": [{"cwe_id": "CWE-122"}],
    }
    m = _advisory_mention("Netatalk/netatalk", adv)
    assert m.cve_id == "CVE-2013-1234"
    assert m.extra_ids == ["GHSA-xxxx-yyyy-zzzz"]
    assert m.seen_at.year == 2013                      # seen_at real, no now()
    assert m.affected[0].product == "foo" and m.affected[0].ecosystem == "npm"
    assert m.cwe_ids == ["CWE-122"]


def test_advisory_sin_paquete_producto_es_el_repo():
    adv = {"ghsa_id": "GHSA-a", "cve_id": "CVE-2026-9", "summary": "s",
           "published_at": "2026-01-01T00:00:00Z"}
    m = _advisory_mention("Netatalk/netatalk", adv)
    assert m.affected[0].product == "netatalk" and m.affected[0].vendor == "Netatalk"


def test_advisory_sin_cve_ancla_por_ghsa():
    adv = {"ghsa_id": "GHSA-only", "cve_id": None, "summary": "s",
           "published_at": "2026-02-02T00:00:00Z"}
    m = _advisory_mention("o/r", adv)
    assert m.cve_id is None and m.native_id == "GHSA-only"


def test_advisory_fecha_cero_descartada_y_sin_ids_none():
    # fecha zero-value (< 1990) -> seen_at None (parse_advisory_date)
    adv = {"ghsa_id": "GHSA-z", "cve_id": "CVE-2026-1", "summary": "s",
           "published_at": "0001-01-01T00:00:00Z"}
    assert _advisory_mention("o/r", adv).seen_at is None
    # sin ghsa ni cve -> None
    assert _advisory_mention("o/r", {"summary": "nada"}) is None


def test_release_una_mencion_por_cve_producto_repo():
    rel = {
        "tag_name": "netatalk-4-5-1",
        "name": "4.5.1",
        "body": "Fixes CVE-2026-62318, CVE-2026-62319 and CVE-2026-62319 (dup).",
        "published_at": "2026-07-16T12:10:41Z",
        "html_url": "https://github.com/Netatalk/netatalk/releases/tag/netatalk-4-5-1",
    }
    ms = _release_mentions("Netatalk/netatalk", rel)
    assert sorted(m.cve_id for m in ms) == ["CVE-2026-62318", "CVE-2026-62319"]  # dedup
    assert all(m.seen_at.year == 2026 and m.seen_at.month == 7 for m in ms)
    assert all(m.affected[0].product == "netatalk" for m in ms)


def test_release_sin_cve_no_emite():
    assert _release_mentions("o/r", {"tag_name": "v1", "body": "solo mejoras"}) == []


def test_emit_watermark_y_ventana():
    cutoff = datetime(2026, 1, 1, tzinfo=UTC)
    wm = datetime(2026, 6, 1, tzinfo=UTC)
    older = datetime(2026, 5, 1, tzinfo=UTC)
    newer = datetime(2026, 7, 1, tzinfo=UTC)
    pre_cutoff = datetime(2025, 1, 1, tzinfo=UTC)
    # con watermark: solo lo estrictamente más nuevo
    assert _emit(newer, cutoff, wm) is True
    assert _emit(older, cutoff, wm) is False
    # sin watermark (primer escaneo): dentro de la ventana
    assert _emit(newer, cutoff, None) is True
    assert _emit(pre_cutoff, cutoff, None) is False
    # sin fecha: solo en el primer escaneo (wm None)
    assert _emit(None, cutoff, None) is True
    assert _emit(None, cutoff, wm) is False
