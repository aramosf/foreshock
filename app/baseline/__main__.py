"""baseline-worker: sincroniza el estado canónico en bucle.

Ejecuta cvelistV5 / NVD / EPSS en sus cadencias (Settings) con APScheduler.
Corre una pasada al arrancar y luego según intervalo. Un fallo en una fuente
se aísla (lo maneja el propio service) y no tumba el worker.
"""

from __future__ import annotations

import asyncio

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.baseline.epss import sync_epss
from app.baseline.cvelist import sync_cvelist
from app.baseline.nvd import sync_nvd_delta
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

log = get_logger("baseline.worker")


async def _cvelist_job() -> None:
    try:
        await asyncio.to_thread(sync_cvelist)
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.cvelist_error", error=str(exc))


async def _nvd_job() -> None:
    try:
        await sync_nvd_delta()
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.nvd_error", error=str(exc))


async def _epss_job() -> None:
    try:
        await sync_epss()
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.epss_error", error=str(exc))


async def main() -> None:
    configure_logging()
    settings = get_settings()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(_cvelist_job, "interval", seconds=settings.cvelist_sync_seconds,
                      id="cvelist", max_instances=1)
    scheduler.add_job(_nvd_job, "interval", seconds=settings.nvd_delta_seconds,
                      id="nvd", max_instances=1)
    scheduler.add_job(_epss_job, "interval", seconds=settings.epss_sync_seconds,
                      id="epss", max_instances=1)
    scheduler.start()
    log.info("baseline.worker_started")

    # Pasada inicial inmediata.
    await _cvelist_job()
    await _nvd_job()
    await _epss_job()

    await asyncio.Event().wait()  # bloquea para siempre


if __name__ == "__main__":
    asyncio.run(main())
