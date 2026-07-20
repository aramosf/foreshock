"""API de solo lectura + frontend estático de Foreshock.

Sirve:
- /api/*  -> JSON (trend, pending, emerging, lag/histogram, queue/age,
             candidate, software, stats)
- /       -> la página del dashboard (app/api/static/index.html)

Arranque: uvicorn app.api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import os
from collections.abc import Iterator

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import queries as q
from app.core.db import get_session

app = FastAPI(title="Foreshock API", version="0.1.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")

# Cabeceras de seguridad básicas para el dashboard estático.
# PENDIENTE (fuera de alcance): autenticación — la API es de solo lectura y se
# asume desplegada en red de confianza; no exponer a Internet sin proxy/auth.
_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # CSP conservadora: solo recursos propios. style 'unsafe-inline' porque
    # index.html lleva su <style>; scripts inline y de terceros quedan vetados.
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
    return response


def db() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


@app.get("/api/trend")
def api_trend(
    granularity: str = Query("month", pattern="^(month|year)$"),
    months: int = Query(12, ge=1, le=600),
    kind: str | None = Query("all"),
    tech: str | None = None,
    s: Session = Depends(db),
) -> dict:
    return {"granularity": granularity, "months": months,
            "series": q.trend_series(s, granularity, months, kind, tech)}


@app.get("/api/pending")
def api_pending(
    kind: str = Query("product"),
    top: int = Query(20, ge=1, le=200),
    tech: str | None = None,
    period: str | None = None,
    granularity: str = Query("month", pattern="^(month|year)$"),
    maturity: str = Query("all",
        pattern="^(all|pre_cve|cve_prereserved|cve_reserved)$"),
    s: Session = Depends(db),
) -> dict:
    return q.pending_top(s, kind, top, tech, period, granularity, maturity)


@app.get("/api/lag/histogram")
def api_lag_histogram(
    months: int = Query(12, ge=1, le=600),
    exclude_backfill: bool = Query(True),
    metric: str = Query("present", pattern="^(present|published)$"),
    source: str | None = None,
    s: Session = Depends(db),
) -> dict:
    return q.lag_histogram(s, months=months, exclude_backfill=exclude_backfill,
                           metric=metric, source=source)


@app.get("/api/queue/age")
def api_queue_age(s: Session = Depends(db)) -> dict:
    return q.queue_age(s)


@app.get("/api/emerging")
def api_emerging(
    since_days: int | None = None,
    source: str | None = None,
    tier: int | None = None,
    kind: str | None = None,
    in_kev: bool | None = None,
    tech: str | None = None,
    pending_only: bool = False,
    maturity: str | None = Query(None,
        pattern="^(pre_cve|cve_prereserved|cve_reserved)$"),
    period: str | None = None,
    granularity: str = Query("month", pattern="^(month|year)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    s: Session = Depends(db),
) -> dict:
    return q.emerging_list(s, since_days=since_days, source=source, tier=tier, kind=kind,
                           in_kev=in_kev, tech=tech, pending_only=pending_only,
                           maturity=maturity, period=period, granularity=granularity,
                           page=page, page_size=page_size)


@app.get("/api/candidate/{key}")
def api_candidate(key: str, s: Session = Depends(db)) -> dict:
    detail = q.candidate_detail(s, key)
    if detail is None:
        raise HTTPException(status_code=404, detail="not found")
    return detail


@app.get("/api/software")
def api_software(
    name: str,
    ecosystem: str = "",
    granularity: str = Query("month", pattern="^(month|year)$"),
    months: int = Query(24, ge=1, le=600),
    s: Session = Depends(db),
) -> dict:
    return q.software_detail(s, ecosystem, name, granularity, months)


@app.get("/api/stats")
def api_stats(s: Session = Depends(db)) -> dict:
    return {"sources": q.source_stats(s)}


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
    return FileResponse(os.path.join(_STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=_STATIC), name="static")
