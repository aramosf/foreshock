"""Tests de content_hash y canonicalización de URL (unit, sin BD)."""

from app.ingest.hashing import canonical_url, content_hash, normalize_text


def test_normalize_text_collapses_ws():
    assert normalize_text("  Hola   Mundo\n") == "hola mundo"


def test_canonical_url_strips_tracking_and_sorts():
    a = canonical_url("https://x.com/a?utm_source=t&b=2&a=1#frag")
    b = canonical_url("https://x.com/a/?a=1&b=2")
    assert a == b


def test_canonical_url_lowercases_host():
    assert canonical_url("https://EXAMPLE.com/Path") == "https://example.com/Path"


def test_hash_stable_for_same_extract():
    h1 = content_hash(cve="CVE-2026-1", native=None, title="T", snippet="S",
                      url="https://x.com/a?utm_x=1")
    h2 = content_hash(cve="CVE-2026-1", native=None, title="t", snippet="s ",
                      url="https://x.com/a")
    assert h1 == h2


def test_hash_changes_on_content_change():
    h1 = content_hash(cve="CVE-2026-1", native=None, title="A", snippet="x", url=None)
    h2 = content_hash(cve="CVE-2026-1", native=None, title="B", snippet="x", url=None)
    assert h1 != h2


def test_hash_differs_by_cve():
    h1 = content_hash(cve="CVE-2026-1", native=None, title="A", snippet="x", url=None)
    h2 = content_hash(cve="CVE-2026-2", native=None, title="A", snippet="x", url=None)
    assert h1 != h2


def test_hash_is_hex_sha256():
    h = content_hash(cve=None, native="ZDI-CAN-1", title=None, snippet=None, url=None)
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
