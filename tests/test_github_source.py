"""Tests unitarios de la fuente github_commits (detección; sin red)."""

from app.sources.github_commits import _CVE, _SECFIX


def test_secfix_matches_security_language():
    for msg in ["fix use-after-free in parser", "patch RCE in handler",
                "resolve SQL injection", "authentication bypass fix",
                "out-of-bounds read", "security fix for XSS"]:
        assert _SECFIX.search(msg), msg


def test_secfix_ignores_normal_commits():
    for msg in ["update README", "bump version to 1.2.3", "refactor tests"]:
        assert not _SECFIX.search(msg), msg


def test_cve_extraction_from_commit():
    m = _CVE.search("Fix for CVE-2026-12345 in the auth module")
    assert m and m.group(0).upper() == "CVE-2026-12345"


def test_cve_absent():
    assert _CVE.search("just a normal commit") is None


def test_parse_advisory_date_rejects_zero_date():
    """La fecha 'cero' de OSV/Debian (published='0001-01-01T00:00:00Z', el
    zero-value de Go) NO debe usarse como seen_at: parse_advisory_date la
    descarta (junto a fechas < 1990) y devuelve None."""
    from datetime import UTC, datetime

    from app.sources.base import parse_advisory_date

    assert parse_advisory_date("0001-01-01T00:00:00Z") is None
    assert parse_advisory_date("1989-12-31T23:59:59Z") is None
    assert parse_advisory_date(None) is None
    assert parse_advisory_date("") is None
    assert parse_advisory_date("no soy una fecha") is None
    ok = parse_advisory_date("2026-05-27T11:00:57Z")
    assert ok == datetime(2026, 5, 27, 11, 0, 57, tzinfo=UTC)
    # Naive -> se asume UTC.
    assert parse_advisory_date("2026-05-27T11:00:57").tzinfo == UTC


def test_osv_to_mention_ignora_fecha_cero():
    """El fetcher OSV con published='0001-...' cae al fallback 'modified'; si
    tampoco vale, seen_at queda None (nunca aterriza en el año 1)."""
    from app.sources.osv import OsvSource

    rec = {"id": "DEBIAN-CVE-2024-55919", "published": "0001-01-01T00:00:00Z",
           "modified": "2026-04-01T06:00:21Z",
           "affected": [{"package": {"ecosystem": "Debian:11", "name": "x"}}]}
    m = OsvSource._to_mention(rec, cutoff=None)
    assert m is not None and m.seen_at is not None
    assert m.seen_at.year == 2026

    rec2 = {**rec, "modified": "0001-01-01T00:00:00Z"}
    m2 = OsvSource._to_mention(rec2, cutoff=None)
    assert m2 is not None and m2.seen_at is None  # sin fecha válida -> None (no año 1)
