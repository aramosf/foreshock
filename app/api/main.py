"""API de solo lectura + frontend estático de Foreshock.

Sirve:
- /api/*  -> JSON (trend, pending, emerging, lag/histogram, queue/age, velocity,
             candidate, software, stats y estado administrativo)
- /  (=/next) -> dashboard oficial "inminente" (app/api/static/next.html)
- /pending_status -> dashboard operativo de administración

Arranque: uvicorn app.api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import csv
import io
import os
from collections.abc import Iterator

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import admin
from app.api import queries as q
from app.core.db import get_session
from app.core.logging import get_logger
from app.core.operational import OPERATIONAL_MIN_DATE_ISO

app = FastAPI(title="Foreshock API", version="0.1.0")
log = get_logger(__name__)

_STATIC = os.path.join(os.path.dirname(__file__), "static")

# Cabeceras de seguridad básicas para el dashboard estático.
# PENDIENTE (fuera de alcance): autenticación — la API es de solo lectura y se
# asume desplegada en red de confianza; no exponer a Internet sin proxy/auth.
_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # CSP conservadora: solo recursos propios. style 'unsafe-inline' porque los
    # dashboards llevan su <style>; scripts inline y de terceros quedan vetados.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    ),
}


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    for k, v in _SEC_HEADERS.items():
        response.headers.setdefault(k, v)
    response.headers.setdefault(
        "X-Foreshock-Operational-Since", OPERATIONAL_MIN_DATE_ISO
    )
    return response


def db() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


@app.get("/api/trend")
def api_trend(
    granularity: str = Query("month", pattern="^(week|month|year)$"),
    months: int = Query(12, ge=1, le=600),
    days: int | None = Query(None, ge=1, le=3660),
    kind: str | None = Query("all"),
    tech: str | None = None,
    include_historical: bool = Query(False),
    s: Session = Depends(db),
) -> dict:
    out = {"granularity": granularity, "months": months,
           "operational_since": OPERATIONAL_MIN_DATE_ISO,
           "series": q.trend_series(
               s, granularity, months, kind, tech, days, include_historical
           )}
    # `days` presente en la respuesta = capacidad de ventana por días (el
    # frontend sonda esta clave para mostrar los botones "Semana"/"1 sem").
    if days is not None:
        out["days"] = days
    return out


@app.get("/api/pending")
def api_pending(
    kind: str = Query("product"),
    top: int = Query(20, ge=1, le=200),
    tech: str | None = None,
    period: str | None = None,
    granularity: str = Query("month", pattern="^(week|month|year)$"),
    maturity: str = Query("all",
        pattern="^(all|pre_cve|cve_prereserved|cve_reserved)$"),
    s: Session = Depends(db),
) -> dict:
    try:
        return q.pending_top(s, kind, top, tech, period, granularity, maturity)
    except ValueError as exc:
        # period inválido/mismatch de granularidad -> 400 (no all-time silencioso).
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/lag/histogram")
def api_lag_histogram(
    months: int = Query(12, ge=1, le=600),
    exclude_backfill: bool = Query(True),
    metric: str = Query("present", pattern="^(present|published)$"),
    source: str | None = None,
    include_historical: bool = Query(False),
    s: Session = Depends(db),
) -> dict:
    return q.lag_histogram(s, months=months, exclude_backfill=exclude_backfill,
                           metric=metric, source=source,
                           include_historical=include_historical)


@app.get("/api/queue/age")
def api_queue_age(
    exclude_backfill: bool = Query(True),
    s: Session = Depends(db),
) -> dict:
    return q.queue_age(s, exclude_backfill=exclude_backfill)


@app.get("/api/velocity")
def api_velocity(
    days: int = Query(60, ge=1, le=400),
    s: Session = Depends(db),
) -> dict:
    return q.capture_velocity(s, days=days)


@app.get("/api/emerging")
def api_emerging(
    since_days: int | None = Query(None, ge=0, le=3660),
    source: str | None = None,
    tier: int | None = None,
    kind: str | None = None,
    in_kev: bool | None = None,
    tech: str | None = None,
    pending_only: bool = False,
    maturity: str | None = Query(None,
        pattern="^(pre_cve|cve_prereserved|cve_reserved)$"),
    period: str | None = None,
    granularity: str = Query("month", pattern="^(week|month|year)$"),
    page: int = Query(1, ge=1, le=100000),
    page_size: int = Query(50, ge=1, le=500),
    format: str = Query("json", pattern="^(json|csv)$"),
    include_historical: bool = Query(False),
    s: Session = Depends(db),
):
    # CSV: exporta el conjunto filtrado en un lote grande (hasta 5000 filas) para
    # el tablero de triage; JSON mantiene la paginación normal.
    eff_size = 5000 if format == "csv" else page_size
    try:
        data = q.emerging_list(s, since_days=since_days, source=source, tier=tier, kind=kind,
                               in_kev=in_kev, tech=tech, pending_only=pending_only,
                               maturity=maturity, period=period, granularity=granularity,
                               page=page, page_size=eff_size,
                               include_historical=include_historical)
    except ValueError as exc:
        # period inválido/mismatch de granularidad -> 400 (no all-time silencioso).
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if format == "json":
        return data
    # El CSV está topado a `eff_size` filas (una página grande). Si el conjunto
    # filtrado lo excede, se trunca: avisar para que no sea silencioso (el
    # consumidor puede paginar por JSON o afinar filtros).
    if data["total"] > len(data["rows"]):
        log.warning("csv_export_truncated", total=data["total"],
                    returned=len(data["rows"]), cap=eff_size)
    cols = ["cve_id", "maturity", "in_kev", "cvss", "severity_hint", "vuln_type",
            "days_ahead_vs_nvd_present", "source_count", "mention_count",
            "sources", "first_seen_at", "last_seen_at"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in data["rows"]:
        w.writerow([r.get(c) for c in cols])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=foreshock_triage.csv"})


@app.get("/api/pending/critical")
def api_pending_critical(
    top: int = Query(50, ge=1, le=500),
    maturity: str = Query("all",
        pattern="^(all|pre_cve|cve_prereserved|cve_reserved)$"),
    kind: str | None = None,
    tech: str | None = None,
    s: Session = Depends(db),
) -> dict:
    return q.pending_critical(s, top=top, maturity=maturity, kind=kind, tech=tech)


@app.get("/api/pending/breakdown")
def api_pending_breakdown(s: Session = Depends(db)) -> dict:
    return q.pending_breakdown(s)


@app.get("/api/candidate/{key}")
def api_candidate(
    key: str,
    include_historical: bool = Query(False),
    s: Session = Depends(db),
) -> dict:
    detail = q.candidate_detail(s, key, include_historical=include_historical)
    if detail is None:
        raise HTTPException(status_code=404, detail="not found")
    return detail


@app.get("/api/software")
def api_software(
    name: str,
    ecosystem: str = "",
    granularity: str = Query("month", pattern="^(month|year)$"),
    months: int = Query(24, ge=1, le=600),
    include_historical: bool = Query(False),
    s: Session = Depends(db),
) -> dict:
    return q.software_detail(
        s, ecosystem, name, granularity, months, include_historical
    )


@app.get("/api/stats")
def api_stats(
    include_historical: bool = Query(False),
    s: Session = Depends(db),
) -> dict:
    return {
        "operational_since": OPERATIONAL_MIN_DATE_ISO,
        "sources": q.source_stats(s, include_historical=include_historical),
    }


@app.get("/api/admin/status")
def api_admin_status(s: Session = Depends(db)) -> dict:
    return admin.platform_status(s)


@app.get("/healthz")
def healthz() -> dict:
    """Healthcheck real: verifica conectividad con la BD (503 si no responde)."""
    try:
        session = get_session()
        try:
            session.execute(text("SELECT 1"))
        finally:
            session.close()
    except Exception as exc:  # BD caída / red / credenciales
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"ok": True}


@app.get("/")
def index() -> FileResponse:
    """Dashboard OFICIAL: la vista "inminente" (next.html). no-store mientras
    itera, para no servir HTML viejo (el JS se versiona con ?v= en el HTML)."""
    return FileResponse(os.path.join(_STATIC, "next.html"),
                        headers={"Cache-Control": "no-store"})


@app.get("/next")
def next_dashboard() -> FileResponse:
    """Alias del dashboard oficial (compatibilidad con enlaces previos)."""
    return FileResponse(os.path.join(_STATIC, "next.html"),
                        headers={"Cache-Control": "no-store"})


@app.get("/pending_status")
def pending_status() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "pending_status.html"))


app.mount("/static", StaticFiles(directory=_STATIC), name="static")
