"""API de solo lectura + frontend estático de CVERadar.

Sirve:
- /api/*  -> JSON (trend, pending, emerging, candidate, software, stats)
- /       -> la página del dashboard (app/api/static/index.html)

Arranque: uvicorn app.api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import os
from collections.abc import Iterator

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.api import queries as q
from app.core.db import get_session

app = FastAPI(title="CVERadar API", version="0.1.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")


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
    s: Session = Depends(db),
) -> dict:
    return q.pending_top(s, kind, top, tech, period, granularity)


@app.get("/api/emerging")
def api_emerging(
    since_days: int | None = None,
    source: str | None = None,
    tier: int | None = None,
    kind: str | None = None,
    in_kev: bool | None = None,
    tech: str | None = None,
    pending_only: bool = False,
    period: str | None = None,
    granularity: str = Query("month", pattern="^(month|year)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    s: Session = Depends(db),
) -> dict:
    return q.emerging_list(s, since_days=since_days, source=source, tier=tier, kind=kind,
                           in_kev=in_kev, tech=tech, pending_only=pending_only,
                           period=period, granularity=granularity,
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
    return {"ok": True}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=_STATIC), name="static")
