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
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.models import Candidate, Identifier
from app.core.models import Mention as MentionRow
from app.core.models import PublishedCVE
from app.ingest.hashing import content_hash
from app.ingest.identifiers import extract_identifiers, primary_cve, primary_native
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
    raw_html: str | None = None        # contenido crudo a persistir
    seen_at: datetime | None = None


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
    return (a - b).days


def compute_days_ahead(session: Session, candidate: Candidate) -> None:
    """Recalcula los tres deltas de ventaja frente a NVD si hay CVE reconciliado."""
    if not candidate.cve_id or candidate.first_seen_at is None:
        return
    pub = session.get(PublishedCVE, candidate.cve_id)
    if pub is None:
        return
    fs = candidate.first_seen_at
    candidate.days_ahead_vs_nvd_published = _days(pub.nvd_published_at, fs)
    candidate.days_ahead_vs_nvd_present = _days(pub.nvd_first_observed_at, fs)
    candidate.days_ahead_vs_nvd_analyzed = _days(pub.nvd_first_analyzed_observed_at, fs)
    if pub.state == "PUBLISHED" and candidate.status in ("candidate", "emerging"):
        candidate.status = "published"
        if candidate.promoted_at is None:
            candidate.promoted_at = datetime.now(UTC)


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

    ids = extract_identifiers(m.cve_id, m.native_id, m.title, m.snippet, m.url)
    if not ids:
        # Sin identificador no podemos anclar la mención a nada útil.
        log.debug("ingest.skip_no_identifier", source_id=source_id, url=m.url)
        return IngestResult(candidate_id="", mention_id=None, created=False, duplicate=False)

    cve = m.cve_id or primary_cve(ids)
    native = m.native_id or primary_native(ids)

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
        return IngestResult(
            candidate_id=str(existing.candidate_id),
            mention_id=existing.id,
            created=False,
            duplicate=True,
        )

    candidate = resolve_candidate(session, ids)
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
