"""sources-worker: ejecuta los fetchers habilitados en sus cadencias.

Al arrancar registra los fetchers del código en la tabla `sources` y programa
cada fuente habilitada con su `cadence_seconds`. Cada ejecución es aislada:
un fetcher que falla no tumba el worker (lo garantiza run_source).
"""

from __future__ import annotations

import asyncio

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from app.core.db import get_session
from app.core.logging import configure_logging, get_logger
from app.core.models import Source
from app.sources.runner import run_source, sync_registry_to_db

log = get_logger("sources.worker")


def _enabled_sources() -> list[tuple[str, int]]:
    with get_session() as session:
        rows = session.execute(
            select(Source.name, Source.cadence_seconds).where(Source.enabled.is_(True))
        ).all()
    return [(name, cadence) for name, cadence in rows]


async def _run(name: str) -> None:
    try:
        await run_source(name)
    except Exception as exc:  # noqa: BLE001 - doble red de seguridad
        log.error("sources.run_error", source=name, error=str(exc))


async def main() -> None:
    configure_logging()
    sync_registry_to_db()
    scheduler = AsyncIOScheduler()
    for name, cadence in _enabled_sources():
        scheduler.add_job(_run, "interval", seconds=cadence, args=[name],
                          id=name, max_instances=1, jitter=30)
    scheduler.start()
    log.info("sources.worker_started", count=len(scheduler.get_jobs()))
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
