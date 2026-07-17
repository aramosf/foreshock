"""Servicio de enriquecimiento (Capa 3): consolida menciones de un candidate,
llama al LLM, calcula CVSS (autoritativo + derivado), fija severity_hint y
persiste productos afectados (con canonicalización determinista por alias).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.models import (
    AffectedProduct,
    Candidate,
    CVSSScore,
    Mention,
    ProductAlias,
)
from app.enrichment.cvss import derive_from_metrics, parse_authoritative, severity_hint
from app.enrichment.llm import enrich
from app.enrichment.normalize import normalize_key

log = get_logger(__name__)


def gather_snippets(session: Session, candidate: Candidate) -> tuple[str | None, list[str]]:
    rows = session.execute(
        select(Mention.title, Mention.snippet).where(Mention.candidate_id == candidate.id)
    ).all()
    snippets: list[str] = []
    for title, snippet in rows:
        piece = " ".join(p for p in (title, snippet) if p)
        if piece:
            snippets.append(piece)
    return candidate.cve_id, snippets


def _upsert_cvss(session: Session, candidate_id: uuid.UUID, *, version: str, vector: str,
                 base_score: float | None, base_severity: str | None, provenance: str,
                 source: str, inferred: list[str] | None, confidence: float | None) -> None:
    stmt = insert(CVSSScore).values(
        candidate_id=candidate_id, version=version, vector=vector,
        base_score=base_score, base_severity=base_severity, provenance=provenance,
        source=source, inferred_metrics=inferred, confidence=confidence,
        recorded_at=datetime.now(UTC),
    ).on_conflict_do_update(
        constraint="uq_cvss_candidate_version_prov_source",
        set_={
            "vector": vector, "base_score": base_score, "base_severity": base_severity,
            "inferred_metrics": inferred, "confidence": confidence,
            "recorded_at": datetime.now(UTC),
        },
    )
    session.execute(stmt)


def _resolve_alias(session: Session, vendor: str | None, product: str) -> tuple[int | None, str]:
    """Canonicalización determinista (Capa 1): alias conocido -> catalog_id."""
    key = normalize_key(f"{vendor or ''} {product}")
    row = session.execute(
        select(ProductAlias.catalog_id).where(ProductAlias.alias_normalized == key)
    ).scalar_one_or_none()
    if row is not None:
        return int(row), "alias"
    return None, "unresolved"


def _upsert_affected(session: Session, candidate_id: uuid.UUID, ap) -> None:
    catalog_id, method = _resolve_alias(session, ap.vendor, ap.product)
    stmt = insert(AffectedProduct).values(
        candidate_id=candidate_id, catalog_id=catalog_id, vendor=ap.vendor,
        product=ap.product, ecosystem=ap.ecosystem, raw=ap.versions_raw,
        normalization_method=method, source="llm", created_at=datetime.now(UTC),
    ).on_conflict_do_update(
        constraint="uq_affected_candidate_product",
        set_={"ecosystem": ap.ecosystem, "raw": ap.versions_raw,
              "catalog_id": catalog_id, "normalization_method": method},
    )
    session.execute(stmt)


def should_reenrich(candidate: Candidate, *, reenrich_hours: int,
                    min_new_mentions: int, mentions_since: int) -> bool:
    if candidate.enrichment_updated_at is None:
        return True
    age_h = (datetime.now(UTC) - candidate.enrichment_updated_at).total_seconds() / 3600
    return age_h >= reenrich_hours or mentions_since >= min_new_mentions


async def enrich_candidate(session: Session, candidate_id: uuid.UUID) -> bool:
    """Enriquece un candidate. Requiere sesión abierta (no hace commit). Devuelve
    True si se escribió enriquecimiento."""
    candidate = session.get(Candidate, candidate_id)
    if candidate is None:
        return False

    cve_id, snippets = gather_snippets(session, candidate)
    if not snippets:
        return False

    blob = "\n".join(snippets)

    # 1) CVSS autoritativo: vectores presentes verbatim en el texto de las fuentes.
    for res in parse_authoritative(blob):
        _upsert_cvss(
            session, candidate.id, version=res.version, vector=res.vector,
            base_score=res.base_score, base_severity=res.base_severity,
            provenance="authoritative", source="source-text",
            inferred=None, confidence=1.0,
        )

    # 2) LLM: metadatos estructurados (NO un número CVSS).
    out, method = await enrich(cve_id, snippets)

    # 3) CVSS derivado desde las métricas base inferidas (si las 8 están).
    derived = derive_from_metrics(out.cvss_metrics)
    if derived is not None:
        _upsert_cvss(
            session, candidate.id, version=derived.version, vector=derived.vector,
            base_score=derived.base_score, base_severity=derived.base_severity,
            provenance="derived", source="llm-derived",
            inferred=derived.inferred_metrics, confidence=out.confidence,
        )

    # 4) Campos de enriquecimiento en el candidate.
    candidate.vuln_type = out.vuln_type
    candidate.attack_vector = out.attack_vector
    candidate.requires_auth = out.requires_auth
    candidate.requires_interaction = out.requires_interaction
    candidate.has_public_poc = out.has_public_poc
    candidate.poc_urls = out.poc_urls or None
    if out.affected_products:
        first = out.affected_products[0]
        candidate.affected_product = (
            f"{first.vendor}/{first.product}" if first.vendor else first.product
        )
        candidate.affected_versions = first.versions_raw
    candidate.enrichment_confidence = out.confidence
    candidate.enrichment_method = method
    candidate.enrichment_updated_at = datetime.now(UTC)

    # 5) severity_hint SOLO si no hay ningún score numérico (autoritativo ni derivado).
    has_score = session.execute(
        select(CVSSScore.id).where(
            CVSSScore.candidate_id == candidate.id, CVSSScore.base_score.is_not(None)
        ).limit(1)
    ).scalar_one_or_none()
    candidate.severity_hint = None if has_score else severity_hint(
        vuln_type=out.vuln_type, attack_vector=out.attack_vector,
        has_public_poc=out.has_public_poc,
    )

    # 6) Productos afectados estructurados.
    for ap in out.affected_products:
        _upsert_affected(session, candidate.id, ap)

    session.flush()
    log.info("enrich.done", candidate=str(candidate.id), method=method,
             products=len(out.affected_products))
    return True
