"""sources-worker: ejecuta los fetchers habilitados en sus cadencias.

Al arrancar registra los fetchers del código en la tabla `sources` y programa
cada fuente habilitada con su `cadence_seconds`. Cada ejecución es aislada:
un fetcher que falla no tumba el worker (lo garantiza run_source).
"""

from __future__ import annotations

import asyncio
import signal
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import get_session
from app.core.logging import configure_logging, get_logger
from app.core.models import Source
from app.core.runtime import publish_runtime_metrics
from app.sources.cache import sweep_stale_temp
from app.sources.runner import (
    run_source,
    runtime_source_state,
    sync_registry_to_db,
)

log = get_logger("sources.worker")
_INTERNAL_JOBS = {"_reconcile", "_runtime"}
_HEARTBEAT_SECONDS = 30


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


def _startup_delay_seconds(
    name: str,
    cadence: int,
    enabled_names: list[str],
    max_spread: int,
) -> int:
    """Slot estable que reparte el arranque sin retrasar más de una cadencia."""
    if max_spread <= 0 or len(enabled_names) <= 1:
        return 0
    ordered = sorted(enabled_names)
    window = min(max_spread, cadence)
    return int(window * ordered.index(name) / len(ordered))


def _reconcile_jobs(
    scheduler: AsyncIOScheduler,
    *,
    stagger_new: bool = False,
) -> None:
    """Sincroniza los jobs del scheduler con la tabla `sources`: añade las
    habilitadas nuevas, elimina las deshabilitadas, y reprograma si cambió la
    cadencia. Permite enable/disable y ajustes de cadencia EN CALIENTE."""
    enabled = dict(_enabled_sources())
    settings = get_settings()
    enabled_names = list(enabled)
    current = {j.id for j in scheduler.get_jobs() if j.id not in _INTERNAL_JOBS}
    for name in current - enabled.keys():          # deshabilitadas -> quitar
        scheduler.remove_job(name)
        log.info("sources.job_removed", source=name)
    for name, cadence in enabled.items():
        job = scheduler.get_job(name)
        if job is None:                            # nueva habilitada -> añadir
            # En el arranque inicial se reparten los jobs en slots estables para
            # evitar que todas las fuentes hagan fetch/git/ingesta a la vez.
            # Una fuente habilitada en caliente sigue arrancando inmediatamente.
            delay = _startup_delay_seconds(
                name,
                cadence,
                enabled_names,
                settings.sources_startup_spread_seconds,
            ) if stagger_new else 0
            scheduler.add_job(_run, "interval", seconds=cadence, args=[name],
                              id=name, max_instances=1, jitter=30,
                              next_run_time=datetime.now(UTC) + timedelta(seconds=delay))
            log.info("sources.job_added", source=name, cadence=cadence,
                     startup_delay=delay)
        elif getattr(job.trigger, "interval", None) and \
                job.trigger.interval.total_seconds() != cadence:  # cadencia cambiada
            # IntervalTrigger explícito para CONSERVAR el jitter (pasar
            # trigger="interval" a secas lo perdería).
            scheduler.reschedule_job(
                name, trigger=IntervalTrigger(seconds=cadence, jitter=30))
            log.info("sources.job_rescheduled", source=name, cadence=cadence)


async def _runtime_job(scheduler: AsyncIOScheduler) -> None:
    active, queued = runtime_source_state()
    scheduled = sum(j.id not in _INTERNAL_JOBS for j in scheduler.get_jobs())
    try:
        await asyncio.to_thread(
            publish_runtime_metrics,
            "sources-worker",
            active=active,
            queued=queued,
            scheduled=scheduled,
        )
    except Exception as exc:  # noqa: BLE001 - telemetría no tumba ingesta
        log.warning("sources.runtime_error", error=str(exc))


async def main() -> None:
    configure_logging()
    # Barrido best-effort de temporales/clones huérfanos que dejó un kill duro
    # anterior (nunca debe impedir el arranque).
    try:
        sweep_stale_temp()
    except Exception as exc:  # noqa: BLE001 - la limpieza nunca tumba el arranque
        log.warning("sources.sweep_error", error=str(exc))
    sync_registry_to_db()
    # misfire_grace_time=None: una ejecución que llega tarde (worker parado,
    # fetch largo) se lanza igualmente en vez de descartarse en silencio.
    scheduler = AsyncIOScheduler(job_defaults={"misfire_grace_time": None})
    _reconcile_jobs(scheduler, stagger_new=True)
    # Re-sincroniza cada 60 s con la BD (enable/disable/cadencia en caliente).
    scheduler.add_job(_reconcile_jobs, "interval", seconds=60, args=[scheduler],
                      id="_reconcile", max_instances=1)
    scheduler.add_job(
        _runtime_job,
        "interval",
        seconds=_HEARTBEAT_SECONDS,
        args=[scheduler],
        id="_runtime",
        max_instances=1,
        next_run_time=datetime.now(UTC),
    )
    scheduler.start()
    log.info("sources.worker_started", count=len(scheduler.get_jobs()))

    # Salida limpia con SIGTERM/SIGINT (docker stop, Ctrl-C): se para el
    # scheduler y se sale sin traceback.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("sources.worker_stopping")
    scheduler.shutdown(wait=False)


if __name__ == "__main__":
    asyncio.run(main())
