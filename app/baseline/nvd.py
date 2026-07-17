"""Delta feed de la NVD 2.0 -> ground truth propio de observación.

Consultamos la API NVD 2.0 filtrando por ventana de última modificación
(``lastModStartDate``/``lastModEndDate``) para traer los CVE tocados en las
últimas ``hours`` horas, paginando de a 2000. El valor diferencial del radar es
registrar CUÁNDO observamos nosotros por primera vez cada CVE en NVD
(``nvd_first_observed_at``) y cuándo lo vimos por primera vez en estado
``Analyzed`` (``nvd_first_analyzed_observed_at``); esos campos se fijan una sola
vez vía ``COALESCE`` y no se pisan en observaciones posteriores.

`parse_nvd_vuln` es una función pura y testeable.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from dateutil.parser import isoparse
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import PublishedCVE
from app.sources.http import get, make_client

log = get_logger(__name__)

_PAGE_SIZE = 2000
_RATE_LIMIT_SLEEP = 6.0  # seg entre páginas sin api key (límite público NVD)


def _parse_dt(value: str | None) -> datetime | None:
    """Convierte una fecha ISO-8601 de NVD a datetime *aware* (o None)."""
    if not value:
        return None
    dt = isoparse(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def parse_nvd_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Extrae de un item ``vulnerabilities[].cve`` los campos ``nvd_*``.

    Función PURA: sin efectos de red ni BD. Acepta tanto el envoltorio
    ``{"cve": {...}}`` como el propio objeto ``cve``.
    """
    cve = vuln.get("cve", vuln) if isinstance(vuln, dict) else {}
    return {
        "id": cve.get("id"),
        "nvd_published_at": _parse_dt(cve.get("published")),
        "nvd_last_modified_at": _parse_dt(cve.get("lastModified")),
        "nvd_vuln_status": cve.get("vulnStatus"),
    }


def upsert_nvd(session: Session, record: dict[str, Any], observed_at: datetime) -> None:
    """Inserta/actualiza los campos ``nvd_*`` de un CVE (idempotente).

    Si el CVE aún no existe en ``published_cves`` se crea con ``state='PUBLISHED'``.
    ``nvd_first_observed_at`` se fija con ``COALESCE(existing, observed_at)`` para
    no pisar la primera observación. ``nvd_first_analyzed_observed_at`` se fija
    igual pero SOLO cuando el estado actual es ``Analyzed``.
    """
    col = PublishedCVE.__table__.c
    status = record.get("nvd_vuln_status")

    values = {
        "id": record["id"],
        "state": "PUBLISHED",
        "nvd_published_at": record.get("nvd_published_at"),
        "nvd_last_modified_at": record.get("nvd_last_modified_at"),
        "nvd_vuln_status": status,
        "nvd_first_observed_at": observed_at,
        # En el INSERT solo se marca el "first analyzed" si ya está Analyzed.
        "nvd_first_analyzed_observed_at": observed_at if status == "Analyzed" else None,
        "ingested_at": observed_at,
    }
    stmt = insert(PublishedCVE).values(**values)

    set_ = {
        "nvd_published_at": func.coalesce(
            stmt.excluded.nvd_published_at, col.nvd_published_at
        ),
        "nvd_last_modified_at": stmt.excluded.nvd_last_modified_at,
        "nvd_vuln_status": stmt.excluded.nvd_vuln_status,
        # Ground truth: no pisar la primera observación si ya existía.
        "nvd_first_observed_at": func.coalesce(col.nvd_first_observed_at, observed_at),
        "ingested_at": observed_at,
    }
    # El "first analyzed" solo se sella cuando observamos el estado Analyzed.
    if status == "Analyzed":
        set_["nvd_first_analyzed_observed_at"] = func.coalesce(
            col.nvd_first_analyzed_observed_at, observed_at
        )

    session.execute(stmt.on_conflict_do_update(index_elements=["id"], set_=set_))


def _iso_z(dt: datetime) -> str:
    """ISO-8601 con milisegundos + 'Z' (formato que documenta la API NVD 2.0).

    `datetime.isoformat()` emite microsegundos de 6 dígitos, que NVD puede
    rechazar; usamos 3 dígitos de fracción y sufijo Z.
    """
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


async def sync_nvd_delta(hours: int = 3) -> dict[str, int]:
    """Ingesta el delta de NVD 2.0 de las últimas ``hours`` horas.

    Pagina con ``resultsPerPage``/``startIndex`` (máx 2000). Envía la cabecera
    ``apiKey`` si está configurada; en su ausencia respeta el rate limit público
    con una pausa de 6 s entre páginas. Devuelve métricas de ingesta.
    """
    settings = get_settings()
    end = datetime.now(UTC)
    start = end - timedelta(hours=hours)
    observed_at = end

    headers: dict[str, str] = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    stats = {"pages": 0, "fetched": 0, "upserted": 0, "skipped": 0}
    start_index = 0
    total_results: int | None = None

    async with make_client() as client:
        while True:
            params = {
                "lastModStartDate": _iso_z(start),
                "lastModEndDate": _iso_z(end),
                "resultsPerPage": _PAGE_SIZE,
                "startIndex": start_index,
            }
            resp = await get(client, settings.nvd_api_base, params=params, headers=headers)
            data = resp.json()
            vulns = data.get("vulnerabilities") or []
            total_results = data.get("totalResults", total_results)
            stats["pages"] += 1

            with session_scope() as session:
                for vuln in vulns:
                    stats["fetched"] += 1
                    # Aislamiento por fila: un registro corrupto (fecha mal formada,
                    # etc.) NO debe abortar la página ni el resto del delta.
                    try:
                        record = parse_nvd_vuln(vuln)
                        if not record.get("id"):
                            stats["skipped"] += 1
                            continue
                        with session.begin_nested():
                            upsert_nvd(session, record, observed_at)
                        stats["upserted"] += 1
                    except Exception as exc:  # noqa: BLE001
                        stats["skipped"] += 1
                        log.warning("nvd.row_error", error=str(exc))

            page_size = data.get("resultsPerPage") or len(vulns)
            start_index += page_size
            if not vulns or (total_results is not None and start_index >= total_results):
                break

            # Respeta el rate limit público (sin api key) entre páginas.
            if not settings.nvd_api_key:
                await asyncio.sleep(_RATE_LIMIT_SLEEP)

    log.info("nvd.delta_sync", hours=hours, total_results=total_results, **stats)
    return stats
