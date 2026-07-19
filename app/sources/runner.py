"""Ejecución de fuentes: sincroniza el registro con la tabla `sources`, ejecuta
un fetcher de forma aislada y persiste sus menciones vía el pipeline de ingesta.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import Source as SourceRow
from app.ingest.service import ingest_mention
from app.sources.base import BaseSource, FetchContext, load_all
from app.sources.http import make_client

log = get_logger(__name__)


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

    with session_scope() as session:
        row = _get_source_row(session, name)
        if row is None or row.id is None:
            raise RuntimeError(f"fuente '{name}' no está en la tabla sources; corre el seeding")
        source_id = row.id
        for m in mentions:
            stats["fetched"] += 1
            # Aislamiento por mención vía savepoint: una mención mala no revierte
            # el lote entero ni pierde las válidas.
            try:
                with session.begin_nested():
                    res = ingest_mention(session, source_id, m)
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

    log.info("source.run", source=name, **stats)
    return stats


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
                with session.begin_nested():
                    res = ingest_mention(session, source_id, m)
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
