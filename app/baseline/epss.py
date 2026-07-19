"""Ingesta de scores EPSS (FIRST.org) con histórico por fecha.

EPSS asigna a cada CVE una probabilidad de explotación en los próximos 30 días.
Guardamos histórico: la PK de ``epss_scores`` es ``(cve_id, scored_date)``, de
modo que cada snapshot diario del modelo se conserva y podemos ver la evolución
del score.

`parse_epss_row` es una función pura y testeable.
"""

from __future__ import annotations

import gzip
from datetime import UTC, date, datetime
from typing import Any

from dateutil.parser import isoparse
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import Candidate, EPSSScore
from app.sources.cache import cached_download
from app.sources.http import get, make_client

log = get_logger(__name__)

_BATCH_SIZE = 100  # CVEs por petición cuando se filtra por lista (param cve= de FIRST)
_TOP_LIMIT = 200  # top-N global POR SCORE cuando no se filtra (no "más recientes")
# Volcado masivo de FIRST: TODAS las puntuaciones EPSS actuales (~270k CVEs).
EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_FULL_COMMIT_EVERY = 5000


def parse_epss_row(row: dict[str, Any]) -> dict[str, Any]:
    """Extrae de una fila ``data[]`` de la API EPSS el subconjunto de columnas.

    Función PURA: sin efectos de red ni BD. Devuelve
    ``{cve_id, score, percentile, scored_date}``.
    """
    return {
        "cve_id": row.get("cve"),
        "score": float(row["epss"]),
        "percentile": float(row["percentile"]),
        "scored_date": isoparse(row["date"]).date(),
    }


def upsert_epss(session: Session, record: dict[str, Any], model_version: str | None) -> None:
    """Inserta/actualiza un score EPSS (idempotente, con histórico por fecha).

    Usa ``ON CONFLICT (cve_id, scored_date) DO UPDATE`` refrescando
    score/percentile/model_version/fetched_at. Como la PK incluye la fecha, cada
    día se acumula un nuevo snapshot en lugar de sobrescribir el anterior.
    """
    now = datetime.now(UTC)
    values = {
        "cve_id": record["cve_id"],
        "score": record["score"],
        "percentile": record["percentile"],
        "model_version": model_version,
        "scored_date": record["scored_date"],
        "fetched_at": now,
    }
    stmt = insert(EPSSScore).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["cve_id", "scored_date"],
        set_={
            "score": stmt.excluded.score,
            "percentile": stmt.excluded.percentile,
            "model_version": stmt.excluded.model_version,
            "fetched_at": stmt.excluded.fetched_at,
        },
    )
    session.execute(stmt)


def _chunks(items: list[str], size: int) -> list[list[str]]:
    """Parte una lista en sublistas de tamaño ``size``."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def _ingest_payload(data: dict[str, Any]) -> tuple[str | None, int, int]:
    """Persiste el payload EPSS de una respuesta. Devuelve (versión, ingeridos, saltados)."""
    model_version = data.get("model") or data.get("model_version")
    rows = data.get("data") or []
    ingested = 0
    skipped = 0
    with session_scope() as session:
        for row in rows:
            try:
                record = parse_epss_row(row)
                if not record.get("cve_id"):
                    skipped += 1
                    continue
                upsert_epss(session, record, model_version)
                ingested += 1
            except (KeyError, ValueError, TypeError) as exc:
                skipped += 1
                log.warning("epss.parse_error", row=row.get("cve"), error=str(exc))
    return model_version, ingested, skipped


def tracked_cve_ids() -> list[str]:
    """CVE ids que el radar SIGUE: candidates activos (no fusionados) con CVE.

    Es la población cuyo histórico EPSS interesa acumular a diario; el top-200
    global por score NO la cubre (la mayoría de los CVEs seguidos son recientes
    y con score aún bajo).
    """
    with session_scope() as session:
        rows = session.execute(
            select(Candidate.cve_id)
            .where(Candidate.merged_into.is_(None), Candidate.cve_id.is_not(None))
            .distinct()
        ).scalars().all()
    return sorted(rows)


async def sync_epss(cve_ids: list[str] | None = None) -> dict[str, int]:
    """Ingesta scores EPSS desde FIRST.org (idempotente, con histórico).

    - Si ``cve_ids`` se aporta: consulta filtrando por ``?cve=...`` (lista
      separada por comas) en lotes de 100 CVEs.
    - Si no: trae la primera página del top global POR SCORE
      (``?order=!epss&limit=200``).

    Devuelve métricas de ingesta.
    """
    settings = get_settings()
    stats = {"requests": 0, "ingested": 0, "skipped": 0}
    model_version: str | None = None

    async with make_client() as client:
        if cve_ids:
            batches = _chunks(cve_ids, _BATCH_SIZE)
        else:
            batches = [None]  # una única petición del top global por score

        for batch in batches:
            if batch is None:
                params: dict[str, Any] = {"order": "!epss", "limit": _TOP_LIMIT}
            else:
                params = {"cve": ",".join(batch)}
            resp = await get(client, settings.epss_api_base, params=params)
            data = resp.json()
            stats["requests"] += 1
            version, ingested, skipped = _ingest_payload(data)
            model_version = version or model_version
            stats["ingested"] += ingested
            stats["skipped"] += skipped

    log.info("epss.sync", model_version=model_version, filtered=bool(cve_ids), **stats)
    return stats


async def sync_epss_full() -> dict[str, int]:
    """Full sync: descarga el volcado masivo CSV.gz de FIRST con TODAS las
    puntuaciones EPSS actuales (~270k CVEs) y las ingiere por lotes. Cacheado."""
    stats = {"rows": 0, "ingested": 0, "skipped": 0}
    async with make_client() as client:
        path = await cached_download(client, EPSS_BULK_URL, key="epss_scores-current.csv.gz")

    model_version: str | None = None
    scored_date: date | None = None
    header_seen = False
    batch: list[dict[str, Any]] = []

    def _flush(rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with session_scope() as session:
            for rec in rows:
                upsert_epss(session, rec, model_version)

    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):  # cabecera: #model_version:v..,score_date:..
                for part in line[1:].split(","):
                    if ":" in part:
                        k, v = part.split(":", 1)
                        k = k.strip()
                        if k == "model_version":
                            model_version = v.strip()
                        elif k == "score_date":
                            try:
                                scored_date = isoparse(v.strip()).date()
                            except (ValueError, TypeError):
                                scored_date = None
                continue
            if not header_seen:      # primera línea no-comentario = cabecera cve,epss,percentile
                header_seen = True
                continue
            cols = line.split(",")
            if len(cols) < 3:
                stats["skipped"] += 1
                continue
            stats["rows"] += 1
            try:
                batch.append({
                    "cve_id": cols[0], "score": float(cols[1]),
                    "percentile": float(cols[2]),
                    "scored_date": scored_date or datetime.now(UTC).date(),
                })
                stats["ingested"] += 1
            except (ValueError, IndexError):
                stats["skipped"] += 1
                continue
            if len(batch) >= _FULL_COMMIT_EVERY:
                _flush(batch)
                batch = []
        _flush(batch)

    log.info("epss.full_sync", model_version=model_version, scored_date=str(scored_date), **stats)
    return stats
