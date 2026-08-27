"""baseline-worker: sincroniza el estado canónico en bucle.

Ejecuta cvelistV5 / NVD / EPSS / enriquecimiento en sus cadencias (Settings)
con APScheduler. La primera pasada se programa VÍA el scheduler
(``next_run_time=now``) para que respete ``max_instances=1`` y no se solape con
el job de intervalo. Un fallo en una fuente se aísla y no tumba el worker.

Notas de diseño:
- ``misfire_grace_time=None``: sin él (default 1 s), un disparo que coincide
  con trabajo largo se DESCARTA en silencio; con None siempre se ejecuta.
- Los jobs con fetch async (NVD/EPSS) escriben en BD con el motor SÍNCRONO;
  para no bloquear el event loop del scheduler se ejecuta la corrutina entera
  en un hilo aparte con su propio loop (``asyncio.to_thread(asyncio.run, ...)``);
  es lo menos invasivo: separar fetch async de la escritura BD obligaría a
  reestructurar los módulos de ingesta.
- SIGTERM/SIGINT paran el scheduler y salen limpiamente.
"""

from __future__ import annotations

import asyncio
import signal
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.baseline.cvelist import sync_cvelist
from app.baseline.enrich import enrich_all
from app.baseline.epss import sync_epss, tracked_cve_ids
from app.baseline.nvd import sync_nvd_delta
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.core.runtime import publish_runtime_metrics

log = get_logger("baseline.worker")

_HEARTBEAT_SECONDS = 30
_ACTIVE_JOBS: set[str] = set()


async def _cvelist_job() -> None:
    _ACTIVE_JOBS.add("cvelist")
    try:
        await asyncio.to_thread(sync_cvelist)
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.cvelist_error", error=str(exc))
    finally:
        _ACTIVE_JOBS.discard("cvelist")


async def _nvd_job() -> None:
    # Corre en hilo con su propio event loop: la escritura BD es síncrona y no
    # debe bloquear el loop del scheduler. La reconciliación del KPI
    # (days_ahead/promoción de candidates) va DENTRO de sync_nvd_delta.
    _ACTIVE_JOBS.add("nvd")
    try:
        await asyncio.to_thread(asyncio.run, sync_nvd_delta())
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.nvd_error", error=str(exc))
    finally:
        _ACTIVE_JOBS.discard("nvd")


async def _epss_job() -> None:
    """Sincroniza EPSS de los CVEs QUE EL RADAR SIGUE (candidates activos con
    CVE) — es lo que acumula el histórico útil — y complementa con el top-200
    global por score."""
    def _run() -> None:
        cve_ids = tracked_cve_ids()  # consulta síncrona a BD (en hilo)
        if cve_ids:
            asyncio.run(sync_epss(cve_ids=cve_ids))
        asyncio.run(sync_epss())  # complemento: top global por score

    _ACTIVE_JOBS.add("epss")
    try:
        await asyncio.to_thread(_run)
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.epss_error", error=str(exc))
    finally:
        _ACTIVE_JOBS.discard("epss")


async def _enrich_job() -> None:
    """Enriquecimiento estructurado incremental (raw_json -> tablas cve_*)."""
    _ACTIVE_JOBS.add("enrich-nvd")
    try:
        await asyncio.to_thread(enrich_all)
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.enrich_error", error=str(exc))
    finally:
        _ACTIVE_JOBS.discard("enrich-nvd")


async def _runtime_job() -> None:
    try:
        await asyncio.to_thread(
            publish_runtime_metrics,
            "baseline-worker",
            active=sorted(_ACTIVE_JOBS),
            scheduled=4,
        )
    except Exception as exc:  # noqa: BLE001 - telemetría no tumba baseline
        log.warning("baseline.runtime_error", error=str(exc))


async def main() -> None:
    configure_logging()
    settings = get_settings()
    # misfire_grace_time=None: nunca descartar un disparo por llegar tarde.
    scheduler = AsyncIOScheduler(job_defaults={"misfire_grace_time": None})
    now = datetime.now(UTC)
    # next_run_time=now: la primera pasada entra POR el scheduler y respeta
    # max_instances=1 (antes se ejecutaba inline y podía solaparse con el job).
    scheduler.add_job(_cvelist_job, "interval", seconds=settings.cvelist_sync_seconds,
                      id="cvelist", max_instances=1, next_run_time=now)
    scheduler.add_job(_nvd_job, "interval", seconds=settings.nvd_delta_seconds,
                      id="nvd", max_instances=1, next_run_time=now)
    scheduler.add_job(_epss_job, "interval", seconds=settings.epss_sync_seconds,
                      id="epss", max_instances=1, next_run_time=now)
    scheduler.add_job(_enrich_job, "interval", seconds=settings.enrich_sync_seconds,
                      id="enrich-nvd", max_instances=1, next_run_time=now)
    scheduler.add_job(
        _runtime_job,
        "interval",
        seconds=_HEARTBEAT_SECONDS,
        id="_runtime",
        max_instances=1,
        next_run_time=now,
    )
    scheduler.start()
    log.info("baseline.worker_started")

    # Salida limpia con SIGTERM/SIGINT (docker stop, Ctrl-C).
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    await stop.wait()
    log.info("baseline.worker_stopping")
    scheduler.shutdown(wait=True)


if __name__ == "__main__":
    asyncio.run(main())
