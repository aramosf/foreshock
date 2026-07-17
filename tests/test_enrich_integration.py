"""Tests de integración del enriquecimiento (LLM mock + CVSS). Requieren Postgres."""

import asyncio

import pytest
from sqlalchemy import select

from app.core.models import Candidate, CVSSScore
from app.enrichment.service import enrich_candidate
from app.ingest.service import FetchedMention, ingest_mention

pytestmark = pytest.mark.usefixtures("sources_seeded")


def _sid(session, name: str) -> int:
    from app.core.models import Source
    return session.execute(select(Source.id).where(Source.name == name)).scalar_one()


def test_enrich_writes_authoritative_cvss(session):
    sid = _sid(session, "redhat_csaf")
    res = ingest_mention(session, sid, FetchedMention(
        title="CVE-2026-3000 remote code execution",
        snippet="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H remote code execution PoC",
        url="https://rh/1"))
    ok = asyncio.run(enrich_candidate(session, res.candidate_id))
    assert ok
    row = session.execute(
        select(CVSSScore).where(CVSSScore.candidate_id == res.candidate_id,
                                CVSSScore.provenance == "authoritative")
    ).scalar_one()
    assert row.base_score == 9.8
    assert row.base_severity == "CRITICAL"
    cand = session.get(Candidate, res.candidate_id)
    assert cand.vuln_type == "RCE"
    assert cand.has_public_poc is True
    # con score numérico presente, NO se fija severity_hint
    assert cand.severity_hint is None


def test_enrich_sets_severity_hint_without_score(session):
    sid = _sid(session, "thehackernews")
    res = ingest_mention(session, sid, FetchedMention(
        title="CVE-2026-3001 remote code execution actively exploited",
        snippet="unauthenticated remote code execution, PoC public", url="https://thn/2"))
    asyncio.run(enrich_candidate(session, res.candidate_id))
    cand = session.get(Candidate, res.candidate_id)
    # sin vector CVSS en el texto y sin métricas completas -> hint cualitativo
    scores = session.execute(
        select(CVSSScore).where(CVSSScore.candidate_id == res.candidate_id)
    ).scalars().all()
    assert not scores
    assert cand.severity_hint == "likely-critical"


def test_enrich_no_snippets_returns_false(session):
    c = Candidate(status="candidate")
    session.add(c)
    session.flush()
    assert asyncio.run(enrich_candidate(session, c.id)) is False
