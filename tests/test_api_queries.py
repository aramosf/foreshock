"""Tests de integración de app/api/queries.py y de la definición de `pending`.

La métrica central (decisión de producto 2026-07-19): pending = candidates sin
fusionar de los que NVD no ha publicado nada — con cve_id sin datos NVD (y no
REJECTED por MITRE) O pre-CVE (sin cve_id aún) — siempre con tecnología asociada
NO-malware (los MAL-* de paquetes maliciosos se cuentan aparte). CLI y API
comparten esta definición.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import queries as q

NOW = dt.datetime.now(dt.UTC)


def _mk_published(session: Session, cve: str, *, nvd_published: bool,
                  state: str = "PUBLISHED") -> None:
    session.execute(text(
        "INSERT INTO published_cves (id, state, nvd_published_at) "
        "VALUES (:id, :state, :nvd)"),
        {"id": cve, "state": state, "nvd": NOW if nvd_published else None})


def _mk_candidate(session: Session, *, cve: str | None = None,
                  product: str | None = None, kind: str = "product",
                  merged_into: uuid.UUID | None = None,
                  first_seen: dt.datetime | None = None) -> uuid.UUID:
    cid = session.execute(text(
        "INSERT INTO candidates (cve_id, merged_into, first_seen_at, last_seen_at) "
        "VALUES (:cve, :merged, :fs, :fs) RETURNING id"),
        {"cve": cve, "merged": merged_into, "fs": first_seen or NOW}).scalar_one()
    if product is not None:
        session.execute(text(
            "INSERT INTO affected_products (candidate_id, product, kind) "
            "VALUES (:cid, :p, :k)"), {"cid": cid, "p": product, "k": kind})
    return cid


@pytest.fixture
def pending_dataset(db: None, session: Session) -> dict[str, uuid.UUID]:
    """Escenario mixto: publicados en NVD, pendientes, pre-CVE, sin producto."""
    _mk_published(session, "CVE-2026-0001", nvd_published=True)
    _mk_published(session, "CVE-2026-0002", nvd_published=False)
    ids = {}
    # NO pending: su CVE ya está publicado en NVD.
    ids["published"] = _mk_candidate(session, cve="CVE-2026-0001", product="acme")
    # pending: en cvelist pero nvd_published_at NULL.
    ids["pend_cvelist"] = _mk_candidate(session, cve="CVE-2026-0002", product="acme")
    # pending: CVE sin fila alguna en published_cves.
    ids["pend_nofila"] = _mk_candidate(session, cve="CVE-2026-0003", product="widget_lib")
    # pending: pre-CVE (sin cve_id aún) con producto no-malware.
    ids["precve"] = _mk_candidate(session, cve=None, product="acme")
    # NO pending: pre-CVE de paquete malicioso (kind=malware, se cuenta aparte).
    ids["malware"] = _mk_candidate(session, cve=None, product="evil-pkg",
                                   kind="malware")
    # NO pending: su CVE fue RECHAZADO por MITRE (resuelto, no pendiente).
    _mk_published(session, "CVE-2026-0005", nvd_published=False, state="REJECTED")
    ids["rechazado"] = _mk_candidate(session, cve="CVE-2026-0005", product="acme")
    # NO pending: con cve_id no publicado pero SIN tecnología asociada.
    ids["sin_producto"] = _mk_candidate(session, cve="CVE-2026-0004", product=None)
    # tombstone fusionado con el mismo cve_id que pend_nofila: excluido.
    ids["tombstone"] = _mk_candidate(
        session, cve="CVE-2026-0003", product="widget_lib",
        merged_into=ids["pend_nofila"])
    session.commit()
    return ids


def test_pending_top_definition(pending_dataset, session: Session) -> None:
    out = q.pending_top(session, kind="product", top=10)
    assert out["total"] == 3
    assert out["by_kind"] == {"product": 3}
    tops = {r["software"]: r["pending"] for r in out["top"]}
    assert tops == {"acme": 2, "widget_lib": 1}


def test_pending_top_agrega_en_sql_por_candidate(pending_dataset, session: Session) -> None:
    # Dos productos para el mismo candidate: el total sigue contando candidates.
    session.execute(text(
        "INSERT INTO affected_products (candidate_id, product, kind) "
        "VALUES (:cid, 'otra_lib', 'product')"), {"cid": pending_dataset["pend_cvelist"]})
    session.commit()
    out = q.pending_top(session, kind="product", top=10)
    assert out["total"] == 3
    assert out["by_kind"] == {"product": 3}


def test_like_wildcards_escapados(db, session: Session) -> None:
    _mk_candidate(session, cve="CVE-2026-0100", product="100%beef")
    _mk_candidate(session, cve="CVE-2026-0101", product="100beef")
    session.commit()
    # "0%b" debe casar solo el producto que contiene el literal "0%b";
    # sin escapar, el % actuaría de comodín y casaría también "100beef".
    out = q.pending_top(session, kind="all", top=10, tech="0%b")
    assert [r["software"] for r in out["top"]] == ["100%beef"]


def test_trend_series_pending(pending_dataset, session: Session) -> None:
    series = q.trend_series(session, "month", 12)
    period = NOW.strftime("%Y-%m")
    row = next(r for r in series if r["period"] == period)
    assert row["pre_published"] == 3


def test_emerging_pending_only(pending_dataset, session: Session) -> None:
    out = q.emerging_list(session, pending_only=True, page_size=50)
    got = {r["cve_id"] for r in out["rows"]}
    assert got == {"CVE-2026-0002", "CVE-2026-0003", None}  # None = pre-CVE
    assert out["total"] == 3


def test_candidate_detail_ignora_tombstones(pending_dataset, session: Session) -> None:
    detail = q.candidate_detail(session, "CVE-2026-0003")
    assert detail is not None
    assert detail["id"] == str(pending_dataset["pend_nofila"])


def test_cli_find_candidate_con_tombstone(pending_dataset, session: Session) -> None:
    # Antes: MultipleResultsFound si un tombstone compartía cve_id.
    from app.cli import _find_candidate

    c = _find_candidate(session, "cve-2026-0003")
    assert c is not None and c.id == pending_dataset["pend_nofila"]


def test_software_detail_filtra_por_meses(db, session: Session) -> None:
    _mk_candidate(session, cve="CVE-2026-0200", product="oldlib",
                  first_seen=NOW - dt.timedelta(days=5 * 365))
    _mk_candidate(session, cve="CVE-2026-0201", product="oldlib")
    session.commit()
    out = q.software_detail(session, "", "oldlib", months=12)
    assert out["total"] == 1  # el antiguo queda fuera de la ventana
    assert out["pending"] == 1


def test_healthz_y_cabeceras_seguridad(db) -> None:
    from fastapi.testclient import TestClient

    from app.api.main import app

    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200 and r.json() == {"ok": True}
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert "script-src 'self'" in r.headers["Content-Security-Policy"]
        assert r.headers["Referrer-Policy"] == "no-referrer"


def test_pending_desglose_por_madurez(pending_dataset, session: Session) -> None:
    """Las DOS métricas de producto: sin_cve (pre-CVE) y cve_reservado
    (CVE asignado pero MITRE/NVD sin contenido)."""
    out = q.pending_top(session, kind="all", top=10)
    assert out["by_maturity"] == {"sin_cve": 1, "cve_reservado": 2}

    solo_precve = q.pending_top(session, kind="all", top=10, maturity="sin_cve")
    assert solo_precve["total"] == 1
    solo_resv = q.pending_top(session, kind="all", top=10, maturity="cve_reservado")
    assert solo_resv["total"] == 2

    with pytest.raises(ValueError):
        q.pending_top(session, maturity="invalida")
