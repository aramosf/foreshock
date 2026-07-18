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
    # Ids DECLARADOS (cve/native/extra): los tres anclan y forman identidad.
    res = ingest_mention(session, sid, FetchedMention(
        title="VU#111111 CVE-2026-1000 remote code execution",
        snippet="ZDI-CAN-10000", url="https://kb.cert.org/1",
        cve_id="CVE-2026-1000", native_id="VU#111111", extra_ids=["ZDI-CAN-10000"]))
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
    # "published" ahora exige nvd_published_at (meta = NVD con datos).
    session.merge(PublishedCVE(id="CVE-2026-1003", state="PUBLISHED",
                               nvd_published_at=now,
                               nvd_first_observed_at=now,
                               nvd_first_analyzed_observed_at=now))
    session.flush()
    cand = session.get(Candidate, res.candidate_id)
    compute_days_ahead(session, cand)
    assert cand.days_ahead_vs_nvd_present == 7
    assert cand.status == "published"


def test_reserved_cve_stays_prepublished(session):
    """Un CVE en cvelist SIN nvd_published_at (reservado / aún no en NVD) NO se
    promueve a 'published': para nosotros sigue siendo pre-publicado."""
    sid = _sid(session, "osv")
    res = ingest_mention(session, sid, FetchedMention(
        title="pkg vuln", cve_id="CVE-2026-1004", url="https://osv/x"))
    session.merge(PublishedCVE(id="CVE-2026-1004", state="PUBLISHED",
                               nvd_published_at=None))  # MITRE sí, NVD no
    session.flush()
    cand = session.get(Candidate, res.candidate_id)
    compute_days_ahead(session, cand)
    assert cand.status != "published"


def test_prose_cves_do_not_overmerge(session):
    """Un commit/noticia que CITA varios CVEs en el texto NO debe fusionarlos:
    solo los ids DECLARADOS (cve_id/native_id/extra_ids) forman identidad."""
    sid = _sid(session, "github_commits")
    snippet = "batch security update: " + " ".join(f"CVE-2026-{2000 + i}" for i in range(8))
    res = ingest_mention(session, sid, FetchedMention(
        title="acme/app: batch update", snippet=snippet,
        cve_id="CVE-2026-2000", native_id="GHCOMMIT:acme/app@abc1234def",
        url="https://gh/c/bulk"))
    from app.core.models import Identifier
    ids = {v for _s, v in session.execute(
        select(Identifier.scheme, Identifier.value)
        .where(Identifier.candidate_id == res.candidate_id))}
    assert ids == {"CVE-2026-2000", "GHCOMMIT:acme/app@abc1234def"}  # NO los otros 7


def test_osv_aliases_do_merge(session):
    """Los aliases del MISMO advisory (OSV extra_ids) SÍ deben fusionar (misma vuln)."""
    sid = _sid(session, "osv")
    res = ingest_mention(session, sid, FetchedMention(
        title="pkg vuln", snippet="advisory", cve_id="CVE-2026-3000",
        native_id="GHSA-jfh8-c2jp-5v3q", extra_ids=["CVE-2026-3001"],
        url="https://osv/1"))
    from app.core.models import Identifier
    ids = {v for _s, v in session.execute(
        select(Identifier.scheme, Identifier.value)
        .where(Identifier.candidate_id == res.candidate_id))}
    assert {"CVE-2026-3000", "GHSA-jfh8-c2jp-5v3q", "CVE-2026-3001"} <= ids


def test_merge_resolves_unique_collisions(session):
    """Fusionar dos candidates con filas cvss/affected colisionantes no debe
    violar UNIQUE, y debe reasignar los affected_products del loser."""
    from app.core.models import AffectedProduct, CVSSScore
    from app.ingest.reconcile import merge_candidates
    w, l = Candidate(status="emerging"), Candidate(status="emerging")
    session.add(w); session.add(l); session.flush()
    for c in (w, l):
        session.add(CVSSScore(candidate_id=c.id, version="3.1", vector="CVSS:3.1/AV:N",
                              provenance="authoritative", source="source-text"))
        session.add(AffectedProduct(candidate_id=c.id, vendor="acme", product="widget",
                                    ecosystem="pypi", kind="product"))
    session.add(AffectedProduct(candidate_id=l.id, product="gadget", ecosystem="npm",
                                kind="product"))
    session.flush()
    merge_candidates(session, w, l)  # no debe lanzar IntegrityError
    session.flush()
    cvss = session.execute(
        select(CVSSScore).where(CVSSScore.candidate_id == w.id)).scalars().all()
    prods = {a.product for a in session.execute(
        select(AffectedProduct).where(AffectedProduct.candidate_id == w.id)).scalars()}
    assert len(cvss) == 1                       # colisión deduplicada
    assert prods == {"widget", "gadget"}        # gadget reasignado del loser
    assert session.get(Candidate, l.id).status == "merged"


def test_ghcommit_only_dropped_but_cve_commit_anchors(session):
    """Política nueva: un commit de seguridad SIN código (solo GHCOMMIT) se
    DESCARTA (nada sin CVE/código reconocido). Un commit que cita un CVE real
    sí entra, anclado a ese CVE."""
    sid = _sid(session, "github_commits")
    # Commit desnudo (sin CVE ni código) -> descartado.
    r1 = ingest_mention(session, sid, FetchedMention(
        title="acme/lib: security fix uaf", snippet="fix use-after-free",
        native_id="GHCOMMIT:acme/lib@deadbeef1234", url="https://gh/c/1"))
    assert r1.created is False and r1.candidate_id == ""
    # Commit que cita un CVE real -> anclado a ese CVE.
    r2 = ingest_mention(session, sid, FetchedMention(
        title="acme/lib: fix CVE-2026-2000", snippet="patch",
        cve_id="CVE-2026-2000", url="https://gh/adv/1"))
    assert r2.created
    assert session.get(Candidate, r2.candidate_id).cve_id == "CVE-2026-2000"


def test_prose_cves_recorded_as_soft_references(session):
    """CVEs citados en la prosa (no el anclado) se guardan como referencia BLANDA:
    contables y con contexto, PERO no como identifiers ni fusionados."""
    from app.core.models import CveSoftReference
    sid = _sid(session, "github_commits")
    snippet = "batch: also mentions CVE-2026-4001 CVE-2026-4002 CVE-2026-4003"
    res = ingest_mention(session, sid, FetchedMention(
        title="acme/app: batch update", snippet=snippet, cve_id="CVE-2026-4000",
        url="https://gh/c/soft"))
    refs = {r.cve_id for r in session.execute(
        select(CveSoftReference).where(
            CveSoftReference.from_candidate_id == res.candidate_id)).scalars()}
    assert refs == {"CVE-2026-4001", "CVE-2026-4002", "CVE-2026-4003"}
    ids = {v for _s, v in session.execute(
        select(Identifier.scheme, Identifier.value)
        .where(Identifier.candidate_id == res.candidate_id))}
    assert ids == {"CVE-2026-4000"}  # los citados NO son identifiers
