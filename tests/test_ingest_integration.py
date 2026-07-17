"""Tests de integración del pipeline de ingesta (requieren Postgres migrado)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.core.models import Candidate, Identifier
from app.core.models import Mention as MentionRow
from app.core.models import PublishedCVE, Source
from app.ingest.service import FetchedMention, compute_days_ahead, ingest_mention

pytestmark = pytest.mark.usefixtures("sources_seeded")


def _sid(session, name: str) -> int:
    return session.execute(select(Source.id).where(Source.name == name)).scalar_one()


def test_ingest_creates_candidate_and_identifiers(session):
    sid = _sid(session, "certcc_vu")
    res = ingest_mention(session, sid, FetchedMention(
        title="VU#111111 CVE-2026-1000 remote code execution",
        snippet="ZDI-CAN-10000", url="https://kb.cert.org/1"))
    assert res.created is True
    schemes = set(session.execute(
        select(Identifier.scheme).where(Identifier.candidate_id == res.candidate_id)
    ).scalars())
    assert {"CVE", "VU", "ZDI-CAN"} <= schemes


def test_ingest_idempotent_reingest(session):
    sid = _sid(session, "thehackernews")
    m = FetchedMention(title="CVE-2026-1001 exploited", url="https://thn/1")
    r1 = ingest_mention(session, sid, m)
    r2 = ingest_mention(session, sid, m)
    assert r1.created and r2.duplicate
    count = session.execute(
        select(func.count()).select_from(MentionRow)
        .where(MentionRow.candidate_id == r1.candidate_id)
    ).scalar_one()
    assert count == 1


def test_two_sources_same_cve_one_candidate(session):
    a = _sid(session, "certcc_vu")
    b = _sid(session, "thehackernews")
    r1 = ingest_mention(session, a, FetchedMention(title="CVE-2026-1002 x", url="https://a/1"))
    r2 = ingest_mention(session, b, FetchedMention(title="CVE-2026-1002 y", url="https://b/1"))
    assert r1.candidate_id == r2.candidate_id
    cand = session.get(Candidate, r1.candidate_id)
    assert cand.source_count == 2
    assert cand.mention_count == 2
    assert cand.status == "emerging"


def test_mention_without_identifier_skipped(session):
    sid = _sid(session, "thehackernews")
    res = ingest_mention(session, sid, FetchedMention(title="noticia sin cve", url="https://x/1"))
    assert res.created is False and res.candidate_id == ""


def test_days_ahead_computed_against_nvd_observation(session):
    sid = _sid(session, "certcc_vu")
    seen = datetime.now(UTC) - timedelta(days=7)
    res = ingest_mention(session, sid, FetchedMention(
        title="CVE-2026-1003 rce", url="https://a/2", seen_at=seen))
    now = datetime.now(UTC)
    session.merge(PublishedCVE(id="CVE-2026-1003", state="PUBLISHED",
                               nvd_first_observed_at=now,
                               nvd_first_analyzed_observed_at=now))
    session.flush()
    cand = session.get(Candidate, res.candidate_id)
    compute_days_ahead(session, cand)
    assert cand.days_ahead_vs_nvd_present == 7
    assert cand.status == "published"


def test_pre_cve_candidate_reconciles_on_cve_arrival(session):
    sid = _sid(session, "github_commits")
    r1 = ingest_mention(session, sid, FetchedMention(
        title="acme/lib: fix uaf", snippet="GHCOMMIT:acme/lib@deadbeef1234",
        native_id="GHCOMMIT:acme/lib@deadbeef1234", url="https://gh/c/1"))
    assert r1.created and session.get(Candidate, r1.candidate_id).cve_id is None
    r2 = ingest_mention(session, sid, FetchedMention(
        title="advisory CVE-2026-2000", snippet="GHCOMMIT:acme/lib@deadbeef1234",
        cve_id="CVE-2026-2000", native_id="GHCOMMIT:acme/lib@deadbeef1234",
        url="https://gh/adv/1"))
    assert r1.candidate_id == r2.candidate_id
    assert session.get(Candidate, r1.candidate_id).cve_id == "CVE-2026-2000"
