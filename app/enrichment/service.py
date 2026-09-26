"""Servicio de enriquecimiento (Capa 3): consolida menciones de un candidate,
llama al LLM, calcula CVSS (autoritativo + derivado), fija severity_hint y
persiste productos afectados (con canonicalización determinista por alias).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from json import JSONDecodeError

from pydantic import ValidationError
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
from app.ingest.affected import canonical_ecosystem

log = get_logger(__name__)


# Cota superior de snippets que entran al prompt: un candidate mediático (KEV)
# puede acumular cientos de menciones y el prompt crecería sin límite.
_MAX_SNIPPETS = 40


def gather_snippets(session: Session, candidate: Candidate) -> tuple[str | None, list[str]]:
    # ORDER BY id: sin orden explícito Postgres no garantiza ninguno y el input
    # al LLM (y qué vector autoritativo "gana") sería no reproducible entre runs.
    rows = session.execute(
        select(Mention.title, Mention.snippet)
        .where(Mention.candidate_id == candidate.id)
        .order_by(Mention.id)
    ).all()
    snippets: list[str] = []
    seen: set[str] = set()
    for title, snippet in rows:
        piece = " ".join(p for p in (title, snippet) if p)
        if piece and piece not in seen:
            seen.add(piece)
            snippets.append(piece)
        if len(snippets) >= _MAX_SNIPPETS:
            break
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
    # Ecosistema canónico (pip -> pypi, …): mismo canonicalizador que la ingesta
    # estructurada, para que ("django", "pip") y ("django", "pypi") no generen
    # dos filas distintas bajo el UNIQUE (candidate, vendor, product, ecosystem).
    eco = canonical_ecosystem(ap.ecosystem)
    # DO NOTHING si la fila ya existe: una fila "structured" (OSV/GHSA) es dato
    # de mayor calidad que la extracción LLM y no debe ser pisada (ni su
    # proveniencia falseada) por un re-enrich.
    stmt = insert(AffectedProduct).values(
        candidate_id=candidate_id, catalog_id=catalog_id, vendor=ap.vendor,
        product=ap.product, ecosystem=eco, raw=ap.versions_raw,
        normalization_method=method, source="llm", created_at=datetime.now(UTC),
    ).on_conflict_do_nothing(constraint="uq_affected_candidate_product")
    session.execute(stmt)


def should_reenrich(candidate: Candidate, *, reenrich_hours: int,
                    min_new_mentions: int, mentions_since: int) -> bool:
    if candidate.enrichment_updated_at is None:
        return True
    age_h = (datetime.now(UTC) - candidate.enrichment_updated_at).total_seconds() / 3600
    return age_h >= reenrich_hours or mentions_since >= min_new_mentions


def _persist_authoritative(session: Session, candidate: Candidate, blob: str) -> None:
    """Persiste los vectores CVSS presentes verbatim en el texto de las fuentes.
    De haber varios vectores de la MISMA versión, gana el primero en orden de
    mención (el blob ya viene ordenado por Mention.id): determinista, en vez de
    dejar que el último upsert pise a los anteriores en orden arbitrario."""
    first_by_version: dict[str, object] = {}
    for res in parse_authoritative(blob):
        first_by_version.setdefault(res.version, res)
    for res in first_by_version.values():
        _upsert_cvss(
            session, candidate.id, version=res.version, vector=res.vector,
            base_score=res.base_score, base_severity=res.base_severity,
            provenance="authoritative", source="source-text",
            inferred=None, confidence=1.0,
        )


def _set_if_value(candidate: Candidate, attr: str, value) -> None:
    """Solo escribe si el LLM aportó valor: un null del LLM no debe borrar un
    dato previo bueno (p.ej. has_public_poc=True fijado por un fetcher KEV)."""
    if value is not None:
        setattr(candidate, attr, value)


async def enrich_candidate(session: Session, candidate_id: uuid.UUID) -> bool:
    """Enriquece un candidate. Requiere sesión abierta (no hace commit). Devuelve
    True si se escribió enriquecimiento LLM (los CVSS autoritativos del texto se
    persisten aunque el LLM falle)."""
    candidate = session.get(Candidate, candidate_id)
    if candidate is None:
        return False

    cve_id, snippets = gather_snippets(session, candidate)
    if not snippets:
        return False

    blob = "\n".join(snippets)

    # 1) LLM ANTES de cualquier escritura: no mantener la transacción abierta
    #    durante la llamada de red. Si el LLM falla, persistimos igualmente los
    #    CVSS autoritativos (independientes del LLM) y salimos sin tocar el resto.
    try:
        out, method = await enrich(cve_id, snippets)
    except (ValidationError, JSONDecodeError) as exc:
        # Salida del LLM malformada / no parseable: es una condición PERSISTENTE
        # (los mismos snippets producen la misma salida mala). Persistimos los
        # CVSS autoritativos y SELLAMOS el intento (enrichment_updated_at), para
        # que should_reenrich no reencole este candidate en cada ciclo: si no,
        # al quedar enrichment_updated_at=None se reintentaba sin fin (coste
        # infinito, nunca enriquecido). Con el sello, el reintento se espacia a
        # reenrich_hours (backoff). El método/confianza de fallo solo se fijan si
        # no había un enriquecimiento previo bueno (no degradar datos buenos).
        log.warning("enrich.llm_malformed", candidate=str(candidate_id), error=str(exc))
        _persist_authoritative(session, candidate, blob)
        if candidate.enrichment_method is None:
            candidate.enrichment_method = "llm-failed"
            candidate.enrichment_confidence = 0.0
        candidate.enrichment_updated_at = datetime.now(UTC)
        session.flush()
        return False
    except Exception as exc:  # noqa: BLE001 - fallo transitorio (red/timeout): reintentar
        # A diferencia de la salida malformada, un fallo de red/timeout SÍ debe
        # reintentarse en el siguiente ciclo: no sellamos enrichment_updated_at.
        log.warning("enrich.llm_error", candidate=str(candidate_id), error=str(exc))
        _persist_authoritative(session, candidate, blob)
        session.flush()
        return False

    # 2) CVSS autoritativo: vectores presentes verbatim en el texto de las fuentes.
    _persist_authoritative(session, candidate, blob)

    # 3) CVSS derivado desde las métricas base inferidas (si las 8 están).
    derived = derive_from_metrics(out.cvss_metrics)
    if derived is not None:
        _upsert_cvss(
            session, candidate.id, version=derived.version, vector=derived.vector,
            base_score=derived.base_score, base_severity=derived.base_severity,
            provenance="derived", source="llm-derived",
            inferred=derived.inferred_metrics, confidence=out.confidence,
        )

    # 4) Campos de enriquecimiento en el candidate: un null del LLM nunca borra
    #    un valor previo, y has_public_poc=True es pegajoso (un re-enrich con
    #    menos señal no lo degrada).
    _set_if_value(candidate, "vuln_type", out.vuln_type)
    _set_if_value(candidate, "attack_vector", out.attack_vector)
    _set_if_value(candidate, "requires_auth", out.requires_auth)
    _set_if_value(candidate, "requires_interaction", out.requires_interaction)
    if out.has_public_poc is not None and candidate.has_public_poc is not True:
        candidate.has_public_poc = out.has_public_poc
    if out.poc_urls:
        candidate.poc_urls = list(dict.fromkeys(
            [*(candidate.poc_urls or []), *out.poc_urls]
        ))
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


async def enrich_pending(*, limit: int = 50) -> dict[str, int]:
    """Enriquecimiento por lotes: aplica la política should_reenrich (que hasta
    ahora era código muerto) sobre los candidates vivos más recientes. Gestiona
    sus propias sesiones (una por candidate: un fallo no revierte el lote).

    Devuelve {"enriched": n, "skipped": n, "errors": n}.
    """
    from sqlalchemy import func

    from app.core.config import get_settings
    from app.core.db import session_scope
    from app.core.models import Mention as MentionRow

    settings = get_settings()
    stats = {"enriched": 0, "skipped": 0, "errors": 0}

    # Selección: candidates vivos con menciones, los más activos primero.
    with session_scope() as session:
        rows = session.execute(
            select(Candidate.id, Candidate.enrichment_updated_at)
            .where(
                Candidate.merged_into.is_(None),
                Candidate.status.in_(("candidate", "emerging", "published")),
                Candidate.mention_count >= 1,
            )
            .order_by(Candidate.last_seen_at.desc())
            .limit(limit * 4)
        ).all()
        pending: list[uuid.UUID] = []
        for cid, enriched_at in rows:
            if len(pending) >= limit:
                break
            if enriched_at is None:
                pending.append(cid)
                continue
            since = session.execute(
                select(func.count()).select_from(MentionRow).where(
                    MentionRow.candidate_id == cid, MentionRow.seen_at > enriched_at
                )
            ).scalar_one()
            candidate = session.get(Candidate, cid)
            if candidate is not None and should_reenrich(
                candidate,
                reenrich_hours=settings.enrichment_reenrich_hours,
                min_new_mentions=settings.enrichment_reenrich_min_mentions,
                mentions_since=int(since),
            ):
                pending.append(cid)
            else:
                stats["skipped"] += 1

    for cid in pending:
        try:
            with session_scope() as session:
                ok = await enrich_candidate(session, cid)
            stats["enriched" if ok else "skipped"] += 1
        except Exception as exc:  # noqa: BLE001 - un candidate malo no aborta el lote
            stats["errors"] += 1
            log.warning("enrich.batch_error", candidate=str(cid), error=str(exc))
    log.info("enrich.batch", **stats)
    return stats
