"""Tests puros del fetcher github_commits (sin red, sin BD)."""

from __future__ import annotations

from app.sources.github_commits import _FLD, _REC, _mentions_from_log


def _rec(sha: str, date: str, msg: str) -> str:
    return f"{sha}{_FLD}{date}{_FLD}{msg}{_REC}"


def test_git_log_parse_cve_only():
    log_out = (
        _rec("abc123def456", "2026-06-01T10:00:00+00:00", "fix CVE-2026-1000 rce")
        + _rec("0000aaaabbbb", "2026-06-02T10:00:00+00:00", "update readme")  # sin CVE -> fuera
    )
    mentions, newest = _mentions_from_log("acme/app", log_out, synthesize=False)
    assert len(mentions) == 1
    assert mentions[0].cve_id == "CVE-2026-1000"
    assert mentions[0].url == "https://github.com/acme/app/commit/abc123def456"
    assert newest == "2026-06-02T10:00:00+00:00"  # watermark = commit más reciente visto


def test_git_log_multi_cve_one_mention_per_cve():
    """Un commit que arregla varios CVEs -> UNA mención por CVE (todas anclan su
    propio candidate), no solo el primero. El mensaje completo va en el snippet."""
    log_out = _rec("sha1", "2026-06-01T00:00:00+00:00",
                   "batch: fix CVE-2026-1000, CVE-2026-1001 and CVE-2026-1002")
    mentions, _ = _mentions_from_log("acme/app", log_out, synthesize=False)
    assert {m.cve_id for m in mentions} == {"CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002"}
    assert all(m.url == "https://github.com/acme/app/commit/sha1" for m in mentions)
    # CVE repetido en el mensaje no duplica.
    log2 = _rec("sha2", "2026-06-02T00:00:00+00:00", "CVE-2026-2000 fix; retest CVE-2026-2000")
    m2, _ = _mentions_from_log("acme/app", log2, synthesize=False)
    assert len(m2) == 1 and m2[0].cve_id == "CVE-2026-2000"


def test_gitlog_cache_roundtrip(tmp_path):
    """El caché comprimido guarda solo commits relevantes y re-extrae idéntico
    (sin clonar), preservando multi-CVE y el nombre del repo."""
    from types import SimpleNamespace

    from app.sources.github_commits import _write_gitlog_cache, reextract_from_cache
    s = SimpleNamespace(cache_dir=str(tmp_path), github_synthesize_candidates=False)
    log_out = (
        _rec("sha1", "2026-06-01T00:00:00+00:00", "fix CVE-2026-1000 and CVE-2026-1001")
        + _rec("sha2", "2026-06-02T00:00:00+00:00", "chore: update readme")  # sin CVE -> no cachea
    )
    _write_gitlog_cache(s, "acme/app", log_out)
    mentions = reextract_from_cache(s)
    assert {m.cve_id for m in mentions} == {"CVE-2026-1000", "CVE-2026-1001"}
    assert all(m.url == "https://github.com/acme/app/commit/sha1" for m in mentions)
