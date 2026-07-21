"""Ejecución de fuentes: sincroniza el registro con la tabla `sources`, ejecuta
un fetcher de forma aislada y persiste sus menciones vía el pipeline de ingesta.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import Source as SourceRow
from app.ingest.service import ingest_mention
from app.sources.base import BaseSource, FetchContext, load_all
from app.sources.http import make_client

log = get_logger(__name__)

# Acota la ingesta concurrente: cada _persist_mentions abre una sesión (=1
# conexión). El pool es 5+10=15; con ~22 fuentes disparando a la vez al
# arrancar agotaríamos el pool. 8 deja holgura para la CLI/otras sesiones.
_INGEST_SEMAPHORE = asyncio.Semaphore(8)


def sync_registry_to_db() -> None:
    """Crea/actualiza filas en `sources` para cada fetcher registrado y
    deshabilita las fuentes ZOMBI (filas cuyo fetcher ya no existe en el
    código): sin esto el worker las mantendría "habilitadas" para siempre
    aunque nunca puedan volver a ejecutarse."""
    registry = load_all()
    with session_scope() as session:
        for name, cls in registry.items():
            inst = cls()
            row = session.execute(
                select(SourceRow).where(SourceRow.name == name)
            ).scalar_one_or_none()
            if row is None:
                session.add(SourceRow(**inst.seed_row()))  # type: ignore[arg-type]
            else:
                row.kind = inst.kind
                row.method = inst.method
                row.tier = inst.tier
                # cadence_seconds NO se pisa: puede haberse ajustado en operación.
        # Fuentes zombi: en BD pero ya no en el registro de código.
        for row in session.execute(select(SourceRow)).scalars():
            if row.name not in registry and row.enabled:
                row.enabled = False
                log.warning("sources.zombie_disabled", source=row.name)
    log.info("sources.synced", count=len(registry))


def _get_source_row(session: Session, name: str) -> SourceRow | None:
    return session.execute(
        select(SourceRow).where(SourceRow.name == name)
    ).scalar_one_or_none()


# Códigos SQLSTATE transitorios: deadlock y fallo de serialización. Con la
# ingesta CONCURRENTE (varias fuentes tocan el mismo candidate "caliente" a la
# vez, p.ej. un CVE del KEV que también trae poc_in_github), Postgres puede
# matar una de las transacciones en conflicto; reintentar casi siempre resuelve.
_RETRIABLE_PG = {"40P01", "40001"}


def _ingest_isolated(session: Session, source_id: int, m, *, retries: int = 3):
    """Ingesta UNA mención en su savepoint, reintentando ante deadlock/
    serialización. Devuelve IngestResult (o propaga si no es transitorio)."""
    for attempt in range(retries + 1):
        try:
            with session.begin_nested():
                return ingest_mention(session, source_id, m)
        except OperationalError as exc:
            code = getattr(getattr(exc, "orig", None), "sqlstate", None)
            if attempt < retries and code in _RETRIABLE_PG:
                time.sleep(0.05 * (attempt + 1))
                continue
            raise


async def run_source(name: str) -> dict[str, int]:
    """Ejecuta un fetcher una vez. Devuelve métricas. Nunca propaga excepción del fetch."""
    registry = load_all()
    cls = registry.get(name)
    if cls is None:
        raise KeyError(f"fuente desconocida: {name}")

    inst = cls()
    # Forma consistente en TODOS los caminos de retorno (incluido fetch fallido).
    stats = {"fetched": 0, "created": 0, "duplicate": 0, "errors": 0}

    async with make_client() as client:
        ctx = FetchContext(http=client)
        try:
            mentions = await inst.fetch(ctx)
        except Exception as exc:  # noqa: BLE001 - aislamiento: un fetcher no tumba el worker
            log.error("source.fetch_error", source=name, error=str(exc))
            with session_scope() as session:
                row = _get_source_row(session, name)
                if row is not None:
                    row.last_error = str(exc)[:2000]
                    row.last_error_at = datetime.now(UTC)
            return stats

    # La ingesta usa una sesión SÍNCRONA (psycopg) y puede procesar decenas de
    # miles de menciones (OSV). Ejecutarla en el event loop del AsyncIOScheduler
    # lo CONGELA y bloquea al resto de fuentes (p.ej. github_commits esperaría a
    # que OSV termine). Se despacha a un hilo para que las fuentes corran en
    # paralelo real.
    async with _INGEST_SEMAPHORE:
        await asyncio.to_thread(_persist_mentions, name, inst, mentions, stats)

    log.info("source.run", source=name, **stats)
    return stats


def _persist_mentions(name: str, inst: BaseSource, mentions: list,
                      stats: dict[str, int]) -> None:
    """Parte SÍNCRONA de run_source (BD): aislada en un hilo por to_thread."""
    with session_scope() as session:
        row = _get_source_row(session, name)
        if row is None or row.id is None:
            raise RuntimeError(f"fuente '{name}' no está en la tabla sources; corre el seeding")
        source_id = row.id
        for m in mentions:
            stats["fetched"] += 1
            # Aislamiento por mención vía savepoint (con reintento ante deadlock):
            # una mención mala no revierte el lote ni pierde las válidas.
            try:
                res = _ingest_isolated(session, source_id, m)
                if res.created:
                    stats["created"] += 1
                elif res.duplicate:
                    stats["duplicate"] += 1
            except Exception as exc:  # noqa: BLE001
                stats["errors"] += 1
                log.warning("ingest.mention_error", source=name, error=str(exc))
        row.last_success_at = datetime.now(UTC)
        if stats["errors"]:
            row.last_error = f"{stats['errors']} menciones con error"
            row.last_error_at = datetime.now(UTC)
        else:
            row.last_error = None
        # Hook post-persistencia (p.ej. avanzar watermarks de github_commits):
        # se invoca DENTRO del scope, tras el bucle de ingesta -> si algo falló
        # antes, no corre y el siguiente fetch re-escanea (idempotente). Un
        # fallo del hook NO revierte el lote (solo se pierde el avance del
        # watermark, que es seguro re-escanear).
        try:
            inst.finalize()
        except Exception as exc:  # noqa: BLE001
            log.error("source.finalize_error", source=name, error=str(exc))


def ingest_prefetched(name: str, mentions: list) -> dict[str, int]:
    """Ingiere una lista de menciones YA obtenidas (p.ej. re-extraídas de la caché
    del git-log) para la fuente `name`. Mismo aislamiento por savepoint que
    run_source; no toca la red."""
    stats = {"fetched": len(mentions), "created": 0, "duplicate": 0, "errors": 0}
    with session_scope() as session:
        row = _get_source_row(session, name)
        if row is None or row.id is None:
            raise RuntimeError(f"fuente '{name}' no está en sources; corre el seeding")
        source_id = row.id
        for m in mentions:
            try:
                res = _ingest_isolated(session, source_id, m)
                if res.created:
                    stats["created"] += 1
                elif res.duplicate:
                    stats["duplicate"] += 1
            except Exception as exc:  # noqa: BLE001
                stats["errors"] += 1
                log.warning("ingest.mention_error", source=name, error=str(exc))
        row.last_success_at = datetime.now(UTC)
    log.info("source.reextract", source=name, **stats)
    return stats
