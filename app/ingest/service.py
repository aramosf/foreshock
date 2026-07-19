"""Servicio de ingesta: convierte una mención captada por un fetcher en filas
de mentions/candidates/identifiers de forma idempotente.

Flujo:
  1. Extrae identificadores (fetcher-provisto + regex sobre title/snippet/url).
  2. Resuelve/crea candidate (reconcile) y adjunta identificadores.
  3. Dedup por (source_id, content_hash): si ya existe, no hace nada.
  4. Persiste el HTML crudo en disco (raw_html_path) si se aportó.
  5. Actualiza agregados del candidate y recalcula days_ahead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.models import Candidate, CveSoftReference, Identifier
from app.core.models import Mention as MentionRow
from app.core.models import PublishedCVE
from app.ingest.affected import AffectedInput, persist_affected, persist_cvss_vectors
from app.ingest.hashing import content_hash
from app.ingest.identifiers import (
    RECOGNIZED_SCHEMES,
    extract_identifiers,
    primary_cve,
    primary_native,
)
from app.ingest.reconcile import resolve_candidate

log = get_logger(__name__)


@dataclass
class FetchedMention:
    """Lo que un fetcher entrega al pipeline de ingesta."""

    url: str | None = None
    title: str | None = None
    snippet: str | None = None
    cve_id: str | None = None          # si el fetcher ya lo conoce
    native_id: str | None = None       # p.ej. ZDI-CAN-nnnn
    # Ids DECLARADOS adicionales (p.ej. aliases de un mismo advisory OSV): forman
    # parte de la identidad y SÍ fusionan. NO usar para CVEs sueltos citados en prosa.
    extra_ids: list[str] | None = None
    raw_html: str | None = None        # contenido crudo a persistir
    seen_at: datetime | None = None
    # flags a aplicar al candidate (whitelist en _apply_flags), p.ej. KEV.
    flags: dict[str, object] | None = None
    # datos estructurados (OSV, GHSA…) que se persisten al ingerir:
    affected: list["AffectedInput"] | None = None   # -> affected_products + rangos
    cvss_vectors: list[str] | None = None            # -> cvss_scores autoritativos
    cwe_ids: list[str] | None = None                 # -> candidates.cwe_ids
    reference_urls: list[str] | None = None          # -> candidates.reference_urls
    withdrawn: bool | None = None                    # -> candidates.withdrawn


# Campos del candidate que un fetcher puede fijar vía FetchedMention.flags.
_FLAG_WHITELIST = {"in_kev", "kev_date", "kev_source", "has_public_poc"}


def _apply_flags(candidate: Candidate, flags: dict[str, object] | None) -> None:
    if not flags:
        return
    for key, value in flags.items():
        if key in _FLAG_WHITELIST and value is not None:
            setattr(candidate, key, value)


def _apply_candidate_updates(session: Session, candidate: Candidate,
                             m: "FetchedMention") -> None:
    """Aplica al candidate los flags y datos estructurados de una mención
    (idempotente: los upserts de CVSS/afectados no duplican). Se usa tanto en el
    camino de mención nueva como en el de mención duplicada."""
    _apply_flags(candidate, m.flags)          # p.ej. in_kev
    if m.cvss_vectors:
        persist_cvss_vectors(session, candidate.id, m.cvss_vectors, source="osv")
    if m.affected:
        persist_affected(session, candidate.id, m.affected)
    # Listas: UNIÓN preservando orden, no last-writer-wins — una fuente con menos
    # CWEs/referencias no debe borrar lo aportado por otra.
    if m.cwe_ids:
        candidate.cwe_ids = list(dict.fromkeys([*(candidate.cwe_ids or []), *m.cwe_ids]))
    if m.reference_urls:
        candidate.reference_urls = list(dict.fromkeys(
            [*(candidate.reference_urls or []), *m.reference_urls]
        ))[:50]
    if m.withdrawn is not None:
        candidate.withdrawn = m.withdrawn


@dataclass
class IngestResult:
    candidate_id: str
    mention_id: int | None
    created: bool          # True si se insertó una mención nueva
    duplicate: bool        # True si era duplicada (idempotencia)


def _persist_raw(source_id: int, chash: str, raw_html: str | None) -> str | None:
    if not raw_html:
        return None
    settings = get_settings()
    directory = os.path.join(settings.raw_html_dir, str(source_id))
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{chash}.html")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(raw_html)
    return path


def _days(a: datetime | None, b: datetime | None) -> int | None:
    if a is None or b is None:
        return None
    # round (no timedelta.days, que hace floor y da -1 en deltas negativos pequeños).
    return round((a - b).total_seconds() / 86400)


# Si nuestra primera observación en NVD llega más de este margen DESPUÉS de la
# fecha de publicación que declara NVD, la observación no es señal temprana
# (arranque tardío del radar, nvd-full retroactivo): el KPI "present/analyzed"
# sería una ventaja espuria y se deja a NULL.
_OBSERVATION_LAG_MAX_DAYS = 30


def _observed_days(observed: datetime | None, published: datetime | None,
                   first_seen: datetime) -> int | None:
    if observed is None:
        return None
    if published is not None:
        lag = _days(observed, published)
        if lag is not None and lag > _OBSERVATION_LAG_MAX_DAYS:
            return None
    return _days(observed, first_seen)


def compute_days_ahead(session: Session, candidate: Candidate) -> None:
    """Recalcula los tres deltas de ventaja frente a NVD si hay CVE reconciliado."""
    if not candidate.cve_id or candidate.first_seen_at is None:
        return
    pub = session.get(PublishedCVE, candidate.cve_id)
    if pub is None:
        return
    fs = candidate.first_seen_at
    candidate.days_ahead_vs_nvd_published = _days(pub.nvd_published_at, fs)
    candidate.days_ahead_vs_nvd_present = _observed_days(
        pub.nvd_first_observed_at, pub.nvd_published_at, fs)
    candidate.days_ahead_vs_nvd_analyzed = _observed_days(
        pub.nvd_first_analyzed_observed_at, pub.nvd_published_at, fs)
    # "Published" = la META es NVD CON DATOS (nvd_published_at). Un CVE reservado o
    # solo en MITRE/cvelist sin fecha de NVD sigue siendo PRE-publicado para nosotros.
    if pub.nvd_published_at is not None and candidate.status in ("candidate", "emerging"):
        candidate.status = "published"
        if candidate.promoted_at is None:
            candidate.promoted_at = datetime.now(UTC)


def reconcile_pending_days_ahead(session: Session, limit: int | None = None) -> int:
    """Recalcula days_ahead/promoción para candidates cuyo CVE ya está en el
    baseline pero que no han recibido menciones nuevas desde entonces.

    Sin esto, el KPI solo se computaba al ingerir una mención nueva y quedaba
    NULL para el caso típico (el CVE se publica DESPUÉS de la última mención).
    Pensado para ejecutarse tras cada sync del baseline NVD. Devuelve cuántos
    candidates se actualizaron.
    """
    stmt = (
        select(Candidate)
        .join(PublishedCVE, PublishedCVE.id == Candidate.cve_id)
        .where(
            Candidate.merged_into.is_(None),
            Candidate.status.in_(("candidate", "emerging", "published")),
            (
                Candidate.days_ahead_vs_nvd_present.is_(None)
                | Candidate.status.in_(("candidate", "emerging"))
            ),
        )
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    updated = 0
    for candidate in session.execute(stmt).scalars():
        before = (
            candidate.status,
            candidate.days_ahead_vs_nvd_published,
            candidate.days_ahead_vs_nvd_present,
            candidate.days_ahead_vs_nvd_analyzed,
        )
        compute_days_ahead(session, candidate)
        after = (
            candidate.status,
            candidate.days_ahead_vs_nvd_published,
            candidate.days_ahead_vs_nvd_present,
            candidate.days_ahead_vs_nvd_analyzed,
        )
        if after != before:
            updated += 1
    session.flush()
    return updated


def _record_soft_references(session: Session, mention_id: int, source_id: int,
                            candidate: Candidate, anchored: list, m: "FetchedMention") -> None:
    """Registra como referencia BLANDA los CVEs citados en la prosa que NO son el
    CVE anclado de esta nota. No tocan la identidad ni el union-find: solo cuentan
    y dan contexto ("este CVE se menciona aquí"). Idempotente por (mention_id, cve_id)."""
    anchored_cves = {i.value for i in anchored if i.scheme == "CVE"}
    prose = extract_identifiers(m.title, m.snippet, m.url)
    referenced = {i.value for i in prose if i.scheme == "CVE"} - anchored_cves
    if not referenced:
        return
    context = (m.title or m.snippet or "")[:500] or None
    rows = [{
        "cve_id": cve,
        "mention_id": mention_id,
        "source_id": source_id,
        "from_candidate_id": candidate.id,
        "context": context,
    } for cve in sorted(referenced)]
    stmt = pg_insert(CveSoftReference.__table__).values(rows)
    stmt = stmt.on_conflict_do_nothing(constraint="uq_soft_ref_mention_cve")
    session.execute(stmt)


def _refresh_aggregates(session: Session, candidate: Candidate) -> None:
    mc = session.execute(
        select(func.count()).select_from(MentionRow).where(
            MentionRow.candidate_id == candidate.id
        )
    ).scalar_one()
    sc = session.execute(
        select(func.count(func.distinct(MentionRow.source_id))).where(
            MentionRow.candidate_id == candidate.id
        )
    ).scalar_one()
    first = session.execute(
        select(func.min(MentionRow.seen_at)).where(MentionRow.candidate_id == candidate.id)
    ).scalar_one()
    last = session.execute(
        select(func.max(MentionRow.seen_at)).where(MentionRow.candidate_id == candidate.id)
    ).scalar_one()
    candidate.mention_count = int(mc)
    candidate.source_count = int(sc)
    if first is not None:
        candidate.first_seen_at = first
    if last is not None:
        candidate.last_seen_at = last
    if candidate.status == "candidate" and candidate.mention_count >= 1:
        candidate.status = "emerging"


def ingest_mention(session: Session, source_id: int, m: FetchedMention) -> IngestResult:
    """Ingesta idempotente de una mención. Requiere sesión abierta (no hace commit)."""
    seen_at = m.seen_at or datetime.now(UTC)
    if seen_at.tzinfo is None:            # normaliza a UTC-aware (evita mezcla naive/aware)
        seen_at = seen_at.replace(tzinfo=UTC)

    # IDENTIDAD: solo los ids que la fuente DECLARA (cve_id/native_id/extra_ids).
    # Estos anclan y fusionan (union-find). Los CVEs sueltos citados en la prosa
    # (título/snippet) NO se usan para fusionar: un commit "arregla 21 CVEs" o una
    # noticia que enumera varios NO deben colapsar vulns distintas en un candidate.
    declared = extract_identifiers(m.cve_id, m.native_id, *(m.extra_ids or []))
    if declared:
        ids = declared
    else:
        # Fuente sin id declarado (RSS/scrape): ancla al PRIMER id del texto, no a todos.
        text_ids = extract_identifiers(m.title, m.snippet, m.url)
        ids = text_ids[:1]
    if not ids:
        # Sin identificador no podemos anclar la mención a nada útil.
        log.debug("ingest.skip_no_identifier", source_id=source_id, url=m.url)
        return IngestResult(candidate_id="", mention_id=None, created=False, duplicate=False)

    # POLÍTICA: solo se almacena si ancla a un código de vulnerabilidad RECONOCIDO
    # (CVE/ZDI/VU/GHSA/MSRC/OSV). Un ancla sintética GHCOMMIT (commit de seguridad
    # sin CVE ni código asignado) NO basta: se descarta para no meter ruido sin
    # identidad oficial. Un commit que SÍ cita un CVE/GHSA entra por ese código.
    if not any(i.scheme in RECOGNIZED_SCHEMES for i in ids):
        log.debug("ingest.skip_unrecognized", source_id=source_id, url=m.url,
                  schemes=sorted({i.scheme for i in ids}))
        return IngestResult(candidate_id="", mention_id=None, created=False, duplicate=False)

    # Canónicos extraídos primero (upper/strip vía extract_identifiers); el valor
    # crudo del fetcher solo como fallback (p.ej. un native fuera de esquema como
    # "SSA-123456" de Siemens), saneado para no duplicar por espacios.
    cve = primary_cve(ids) or (m.cve_id.strip().upper() if m.cve_id else None)
    native = primary_native(ids) or (m.native_id.strip() if m.native_id else None)

    chash = content_hash(
        cve=cve, native=native, title=m.title, snippet=m.snippet, url=m.url
    )

    # Dedup: ¿ya existe esta mención para esta fuente?
    existing = session.execute(
        select(MentionRow).where(
            MentionRow.source_id == source_id, MentionRow.content_hash == chash
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Mención duplicada, PERO la identidad y los extras van al CANDIDATE:
        # una reemisión con un alias nuevo en extra_ids (que no cambia el hash)
        # debe adjuntar el identifier y fusionar igualmente, y una que ahora
        # añade in_kev o productos debe aplicarse. resolve_candidate es
        # idempotente (adjunta lo que falte y devuelve el root vivo tras
        # cualquier fusión, aunque la mención apuntara a un tombstone).
        candidate = resolve_candidate(session, ids)
        _apply_candidate_updates(session, candidate, m)
        _refresh_aggregates(session, candidate)
        compute_days_ahead(session, candidate)
        session.flush()
        return IngestResult(
            candidate_id=str(candidate.id),
            mention_id=existing.id,
            created=False,
            duplicate=True,
        )

    candidate = resolve_candidate(session, ids)
    _apply_candidate_updates(session, candidate, m)

    raw_path = _persist_raw(source_id, chash, m.raw_html)

    row = MentionRow(
        candidate_id=candidate.id,
        source_id=source_id,
        extracted_cve=cve,
        extracted_native=native,
        url=m.url,
        title=m.title,
        snippet=m.snippet,
        raw_html_path=raw_path,
        seen_at=seen_at,
        content_hash=chash,
    )
    session.add(row)
    session.flush()

    # Referencias blandas: CVEs citados en prosa que NO son el CVE anclado.
    _record_soft_references(session, row.id, source_id, candidate, ids, m)

    _refresh_aggregates(session, candidate)
    compute_days_ahead(session, candidate)
    session.flush()

    log.info(
        "ingest.mention",
        source_id=source_id,
        candidate=str(candidate.id),
        cve=cve,
        native=native,
    )
    return IngestResult(
        candidate_id=str(candidate.id),
        mention_id=row.id,
        created=True,
        duplicate=False,
    )
