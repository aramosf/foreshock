"""Tests del registro de repos (extracción de URLs + dedup + orden de batch)."""

from __future__ import annotations

import pytest

from app.sources.repo_registry import _extract_repo, next_batch, update_scan, upsert_repos


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/Netatalk/netatalk/commit/abc123", "Netatalk/netatalk"),
    ("https://github.com/openssl/openssl.git", "openssl/openssl"),
    ("http://github.com/acme/tool/issues/5", "acme/tool"),
    ("https://github.com/advisories/GHSA-xxxx", None),        # owner en blocklist
    ("https://gitlab.com/foo/bar", None),                      # no es github
    ("https://example.com/x", None),
    (None, None),
])
def test_extract_repo(url, expected):
    assert _extract_repo(url) == expected


def test_upsert_dedup_and_priority(session, db):
    # Mismo repo por dos estrategias -> UNA fila, prioridad = la mayor.
    upsert_repos(session, {"a/b": {"origin": "top_n", "stars": 100}})
    upsert_repos(session, {"a/b": {"origin": "past_cve"}})   # priority 20 > 0
    session.flush()
    from app.core.models import GithubRepo
    rows = session.query(GithubRepo).all() if hasattr(session, "query") else None
    from sqlalchemy import select
    got = session.execute(select(GithubRepo.full_name, GithubRepo.priority,
                                 GithubRepo.stars)).all()
    assert len(got) == 1
    assert got[0][0] == "a/b" and got[0][1] == 20 and got[0][2] == 100  # stars conservadas


def test_next_batch_orders_unscanned_then_priority(session, db):
    upsert_repos(session, {
        "pop/repo": {"origin": "top_n", "stars": 9999},
        "ref/repo": {"origin": "past_cve"},   # prioridad alta
    })
    session.flush()
    batch = next_batch(session, 10)
    names = [b[0] for b in batch]
    assert names[0] == "ref/repo"     # proven-relevant primero pese a menos estrellas
    # Tras escanear ref/repo, el siguiente lote lo pone al final (last_scanned_at).
    update_scan(session, "ref/repo", "2026-07-01T00:00:00+00:00")
    session.flush()
    assert next_batch(session, 10)[0][0] == "pop/repo"
