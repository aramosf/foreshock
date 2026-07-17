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
