"""Orquestación del baseline-worker.

Encadena las tres fuentes de baseline (cvelistV5, delta NVD 2.0 y EPSS) en una
sola pasada idempotente y loguea las métricas agregadas. Las funciones de red
son async; ``run_baseline_once`` ofrece un punto de entrada síncrono para el
scheduler/CLI vía ``asyncio.run``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.baseline.cvelist import sync_cvelist
from app.baseline.epss import sync_epss, tracked_cve_ids
from app.baseline.nvd import reconcile_kpi, sync_nvd_delta

log = get_logger(__name__)


async def run_baseline_async(
    nvd_hours: int = 3,
    force_full_cvelist: bool = False,
) -> dict[str, Any]:
    """Ejecuta el baseline completo (cvelist + NVD + EPSS) una vez.

    ``sync_cvelist`` es síncrona (git + BD) y se ejecuta en un hilo para no
    bloquear el loop; NVD y EPSS son async. Devuelve un dict con las métricas de
    cada fuente. El fallo de una fuente no impide intentar las demás.
    """
    results: dict[str, Any] = {}

    try:
        results["cvelist"] = await asyncio.to_thread(sync_cvelist, force_full_cvelist)
    except Exception as exc:  # noqa: BLE001 - aislamiento entre fuentes
        log.error("baseline.cvelist_error", error=str(exc))
        results["cvelist"] = {"error": str(exc)}

    try:
        results["nvd"] = await sync_nvd_delta(hours=nvd_hours)
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.nvd_error", error=str(exc))
        results["nvd"] = {"error": str(exc)}
        # El delta falló a medias: reconcilia el KPI con lo que sí se ingirió
        # (en éxito lo hace el propio sync_nvd_delta -> stats["reconciled"]).
        results["reconciled"] = await asyncio.to_thread(reconcile_kpi)

    try:
        # EPSS de los CVEs QUE EL RADAR SIGUE (histórico del KPI) + top global.
        cve_ids = await asyncio.to_thread(tracked_cve_ids)
        results["epss"] = await sync_epss(cve_ids=cve_ids) if cve_ids else {}
        results["epss_top"] = await sync_epss()
    except Exception as exc:  # noqa: BLE001
        log.error("baseline.epss_error", error=str(exc))
        results["epss"] = {"error": str(exc)}

    log.info("baseline.run", **{k: v for k, v in results.items()})
    return results


def run_baseline_once(
    nvd_hours: int = 3,
    force_full_cvelist: bool = False,
) -> dict[str, Any]:
    """Punto de entrada síncrono del baseline (para scheduler/CLI)."""
    return asyncio.run(
        run_baseline_async(nvd_hours=nvd_hours, force_full_cvelist=force_full_cvelist)
    )
