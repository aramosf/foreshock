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


def test_pending_breakdown(pending_dataset, session: Session) -> None:
    out = q.pending_breakdown(session)
    # partición exacta del conjunto pending (3) por madurez.
    assert out["by_maturity"] == {"pre_cve": 1, "cve_prereserved": 1, "cve_reserved": 1}
    # los productos del fixture no llevan ecosystem -> '(sin ecosistema)'.
    ecos = {e["ecosystem"]: e["pending"] for e in out["by_ecosystem"]}
    assert ecos == {"(sin ecosistema)": 3}


def test_pending_critical_solo_con_senal_y_orden(pending_dataset, session: Session) -> None:
    # Sin ninguna señal de gravedad/explotación, no hay "críticos".
    assert q.pending_critical(session)["rows"] == []
    # Marca señales: in_kev (pend con CVE) y has_public_poc (pre-CVE).
    session.execute(text("UPDATE candidates SET in_kev=true WHERE id=:id"),
                    {"id": pending_dataset["pend_nofila"]})
    session.execute(text("UPDATE candidates SET has_public_poc=true WHERE id=:id"),
                    {"id": pending_dataset["precve"]})
    session.commit()
    out = q.pending_critical(session, top=10)
    assert len(out["rows"]) == 2
    # in_kev (+50) pesa más que has_public_poc (+20): el KEV va primero.
    assert out["rows"][0]["cve_id"] == "CVE-2026-0003"
    assert out["rows"][0]["in_kev"] is True and out["rows"][0]["score"] >= 50
    assert out["rows"][1]["has_public_poc"] is True
    assert out["rows"][1]["score"] < out["rows"][0]["score"]
    # el filtro de madurez respeta el conjunto crítico.
    assert q.pending_critical(session, maturity="pre_cve")["rows"][0]["cve_id"] is None


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


def test_pending_pre2016_fuera_del_dashboard_y_de_kev(
    pending_dataset, session: Session,
) -> None:
    """El archivo histórico pre-2016 se conserva, pero no contamina pending ni
    el KPI/tarjeta KEV del dashboard."""
    old = _mk_candidate(
        session,
        cve="CVE-2015-9999",
        product="legacy-inconsistency",
        first_seen=dt.datetime(2015, 12, 31, tzinfo=dt.UTC),
    )
    session.execute(
        text("UPDATE candidates SET in_kev=true, has_public_poc=true WHERE id=:id"),
        {"id": old},
    )
    session.commit()

    pending = q.pending_top(session, kind="all", top=20)
    assert pending["total"] == 3
    assert all(r["software"] != "legacy-inconsistency" for r in pending["top"])

    kev = q.emerging_list(
        session, pending_only=True, in_kev=True, page_size=50,
    )
    assert all(r["cve_id"] != "CVE-2015-9999" for r in kev["rows"])

    critical = q.pending_critical(session, top=50)
    assert all(r["cve_id"] != "CVE-2015-9999" for r in critical["rows"])


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


def test_pending_status_dashboard_y_api(sources_seeded) -> None:
    from fastapi.testclient import TestClient

    from app.api.main import app

    with TestClient(app) as client:
        page = client.get("/pending_status")
        assert page.status_code == 200
        assert "Estado operativo" in page.text
        assert "/static/pending_status.js" in page.text

        response = client.get("/api/admin/status")
        assert response.status_code == 200
        data = response.json()
        assert data["health"] in {"ok", "degraded", "critical"}
        assert data["summary"]["workers_expected"] == 2
        assert data["fetchers"]["summary"]["total"] > 0
        assert {row["role"] for row in data["workers"]} == {
            "api", "baseline-worker", "sources-worker",
        }
        assert data["ingestion"]["pending_min_date"] == "2016-01-01"
        assert data["database"]["migration"]


def test_pending_desglose_por_madurez(pending_dataset, session: Session) -> None:
    """Las TRES métricas de madurez: pre_cve (sin CVE), cve_prereserved (CVE sin
    ficha oficial en el espejo) y cve_reserved (CVE con ficha pero NVD sin datos)."""
    out = q.pending_top(session, kind="all", top=10)
    # precve -> pre_cve; pend_nofila (CVE sin fila) -> cve_prereserved;
    # pend_cvelist (CVE con fila, nvd_published_at NULL) -> cve_reserved.
    assert out["by_maturity"] == {"pre_cve": 1, "cve_prereserved": 1, "cve_reserved": 1}

    assert q.pending_top(session, kind="all", top=10, maturity="pre_cve")["total"] == 1
    assert q.pending_top(
        session, kind="all", top=10, maturity="cve_prereserved")["total"] == 1
    assert q.pending_top(
        session, kind="all", top=10, maturity="cve_reserved")["total"] == 1

    with pytest.raises(ValueError):
        q.pending_top(session, maturity="invalida")


# --------------------------------------------------------------- extensiones dashboard

def _source_id(session: Session, name: str) -> int:
    return session.execute(
        text("SELECT id FROM sources WHERE name=:n"), {"n": name}).scalar_one()


def _add_mention(session: Session, cid: uuid.UUID, source_name: str) -> None:
    session.execute(text(
        "INSERT INTO mentions (candidate_id, source_id, seen_at, content_hash) "
        "VALUES (:c, :s, :t, :h)"),
        {"c": cid, "s": _source_id(session, source_name), "t": NOW, "h": str(uuid.uuid4())})


_DAYS_COL = {"present": "days_ahead_vs_nvd_present",
             "published": "days_ahead_vs_nvd_published"}


def _set_days_ahead(session: Session, cid: uuid.UUID, days: int,
                    *, metric: str = "present") -> None:
    session.execute(text(
        f"UPDATE candidates SET {_DAYS_COL[metric]}=:d WHERE id=:c"),
        {"d": days, "c": cid})


def test_trend_maturity_particiona_pre_published(pending_dataset, session: Session) -> None:
    """Los tres desgloses de madurez suman EXACTAMENTE pre_published por periodo,
    y el periodo actual tiene el reparto esperado (1/1/1)."""
    series = q.trend_series(session, "month", 12)
    for row in series:
        assert (row["pre_cve"] + row["cve_prereserved"] + row["cve_reserved"]
                == row["pre_published"])
    period = NOW.strftime("%Y-%m")
    cur = next(r for r in series if r["period"] == period)
    assert cur["pre_published"] == 3
    assert (cur["pre_cve"], cur["cve_prereserved"], cur["cve_reserved"]) == (1, 1, 1)


def test_lag_histogram_bins_y_exclude_backfill(sources_seeded, session: Session) -> None:
    """Bins, mediana y p90 con datos sembrados; exclude_backfill excluye
    candidates cuya ÚNICA fuente es de backfill, pero conserva los que tienen
    al menos una fuente no-backfill."""
    c1 = _mk_candidate(session, cve="CVE-2026-1001", product="a"); _set_days_ahead(session, c1, 1)
    _add_mention(session, c1, "github_commits")
    c2 = _mk_candidate(session, cve="CVE-2026-1002", product="a"); _set_days_ahead(session, c2, 5)
    _add_mention(session, c2, "github_commits")
    c3 = _mk_candidate(session, cve="CVE-2026-1003", product="a"); _set_days_ahead(session, c3, 50)
    _add_mention(session, c3, "redhat_csaf")
    # osv + github_commits -> tiene fuente no-backfill: se CONSERVA aun excluyendo.
    c6 = _mk_candidate(session, cve="CVE-2026-1006", product="a"); _set_days_ahead(session, c6, 10)
    _add_mention(session, c6, "osv"); _add_mention(session, c6, "github_commits")
    # SOLO osv (backfill) -> se EXCLUYE con exclude_backfill=True.
    c4 = _mk_candidate(session, cve="CVE-2026-1004", product="a"); _set_days_ahead(session, c4, 100)
    _add_mention(session, c4, "osv")
    # days_ahead NULL -> ignorado siempre.
    _mk_candidate(session, cve="CVE-2026-1005", product="a")
    session.commit()

    inc = q.lag_histogram(session, months=12, exclude_backfill=True)
    assert inc["count"] == 4
    bins = {b["label"]: b["count"] for b in inc["bins"]}
    assert bins == {"0-1": 1, "2-7": 1, "8-14": 1, "15-30": 0,
                    "31-60": 1, "61-90": 0, ">90": 0}
    assert inc["median"] == pytest.approx(7.5)
    assert inc["p90"] == pytest.approx(38.0)
    # etiquetas y suma de bins == count.
    assert sum(b["count"] for b in inc["bins"]) == inc["count"]

    full = q.lag_histogram(session, months=12, exclude_backfill=False)
    assert full["count"] == 5   # entra c4 (solo osv)
    fbins = {b["label"]: b["count"] for b in full["bins"]}
    assert fbins[">90"] == 1
    assert full["median"] == pytest.approx(10.0)


def test_emerging_maturity_campo_y_filtro(pending_dataset, session: Session) -> None:
    """Cada fila lleva `maturity` (null si no es pendiente) y `first_seen_at`;
    el filtro maturity= restringe correctamente."""
    out = q.emerging_list(session, page_size=100)
    by_id = {r["id"]: r for r in out["rows"]}
    assert all("first_seen_at" in r for r in out["rows"])
    assert by_id[pending_dataset["precve"]]["maturity"] == "pre_cve"
    assert by_id[pending_dataset["pend_nofila"]]["maturity"] == "cve_prereserved"
    assert by_id[pending_dataset["pend_cvelist"]]["maturity"] == "cve_reserved"
    # No pendientes -> maturity null.
    assert by_id[pending_dataset["published"]]["maturity"] is None
    assert by_id[pending_dataset["malware"]]["maturity"] is None
    assert by_id[pending_dataset["rechazado"]]["maturity"] is None

    only = q.emerging_list(session, maturity="cve_prereserved", page_size=100)
    assert only["total"] == 1
    assert only["rows"][0]["id"] == pending_dataset["pend_nofila"]

    with pytest.raises(ValueError):
        q.emerging_list(session, maturity="invalida")


def test_lag_histogram_published_bins_censored_by_year(sources_seeded, session: Session) -> None:
    """metric=published: bucket '<=0' (NVD publicó antes/a la vez), censored_count
    (cve_id sin nvd_published_at) y by_year; ignora fechas corruptas (< 1990)."""
    # publicados: days_ahead_vs_nvd_published conocido ⟺ el CVE tiene
    # nvd_published_at (como en el pipeline real: compute_days_ahead lo exige).
    for cve in ("CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003", "CVE-2026-2004"):
        _mk_published(session, cve, nvd_published=True)
    p1 = _mk_candidate(session, cve="CVE-2026-2001", product="a")
    _set_days_ahead(session, p1, -2, metric="published")   # NVD antes -> "<=0"
    p2 = _mk_candidate(session, cve="CVE-2026-2002", product="a")
    _set_days_ahead(session, p2, 0, metric="published")    # a la vez -> "<=0"
    p3 = _mk_candidate(session, cve="CVE-2026-2003", product="a")
    _set_days_ahead(session, p3, 5, metric="published")    # "1-7"
    _add_mention(session, p3, "redhat_csaf")               # para el filtro source=
    p4 = _mk_candidate(session, cve="CVE-2026-2004", product="a")
    _set_days_ahead(session, p4, 100, metric="published")  # ">90"
    # censurado: tiene cve_id pero su CVE NO tiene nvd_published_at (sin fila).
    _mk_candidate(session, cve="CVE-2026-2999", product="a")
    # CORRUPTO: first_seen en el año 1 (fecha cero) -> debe IGNORARSE del todo.
    corrupt = _mk_candidate(session, cve="CVE-2026-2500", product="a",
                            first_seen=dt.datetime(1, 1, 1, tzinfo=dt.UTC))
    _set_days_ahead(session, corrupt, 50, metric="published")
    session.commit()

    out = q.lag_histogram(session, months=12, metric="published")
    assert out["metric"] == "published"
    assert out["exclude_backfill"] is False   # forzado: el archivo es el objeto de estudio
    assert out["count"] == 4                   # corrupto excluido
    bins = {b["label"]: b["count"] for b in out["bins"]}
    assert bins == {"<=0": 2, "1-7": 1, "8-14": 0, "15-30": 0,
                    "31-60": 0, "61-90": 0, ">90": 1}
    assert sum(b["count"] for b in out["bins"]) == out["count"]
    assert out["median"] == pytest.approx(2.5)
    assert out["p90"] == pytest.approx(71.5)
    assert out["censored_count"] == 1
    # by_year: una sola cohorte (año actual), sin el corrupto.
    assert len(out["by_year"]) == 1
    yr = out["by_year"][0]
    assert yr["year"] == NOW.year and yr["n"] == 4
    assert yr["mean"] == pytest.approx(25.8)
    assert yr["median"] == pytest.approx(2.5)

    # source= restringe a candidates con esa fuente.
    only = q.lag_histogram(session, months=12, metric="published", source="redhat_csaf")
    assert only["count"] == 1 and only["source"] == "redhat_csaf"
    assert only["censored_count"] == 0

    with pytest.raises(ValueError):
        q.lag_histogram(session, metric="nope")


def test_queue_age_bins_grupos_y_mediana(db, session: Session) -> None:
    """Cola de espera: bins y mediana por grupo (unassigned/assigned); un CVE ya
    publicado en NVD NO cuenta; una fecha corrupta (< 1990) se excluye."""
    def age(days: int) -> dt.datetime:
        return NOW - dt.timedelta(days=days)

    # unassigned (cve_id NULL, con producto no-malware) -> pending.
    _mk_candidate(session, cve=None, product="a", first_seen=age(3))    # 0-7
    _mk_candidate(session, cve=None, product="a", first_seen=age(20))   # 8-30
    _mk_candidate(session, cve=None, product="a", first_seen=age(200))  # 181-365
    # assigned (cve_id sin datos NVD) -> pending.
    _mk_candidate(session, cve="CVE-2026-3001", product="a", first_seen=age(10))   # 8-30
    _mk_candidate(session, cve="CVE-2026-3002", product="a", first_seen=age(400))  # >365
    # NO cuenta: CVE ya PUBLICADO en NVD (no es pending).
    _mk_published(session, "CVE-2026-3999", nvd_published=True)
    _mk_candidate(session, cve="CVE-2026-3999", product="a", first_seen=age(5))
    # NO cuenta: fecha corrupta (año 1) excluida por el suelo 1990.
    _mk_candidate(session, cve=None, product="a",
                  first_seen=dt.datetime(1, 1, 1, tzinfo=dt.UTC))
    session.commit()

    # exclude_backfill=False: estos candidates no tienen menciones, y el filtro
    # de backfill (default) exigiría una fuente no-backfill; aquí se prueba solo
    # la lógica de bins/grupos.
    out = q.queue_age(session, exclude_backfill=False)
    un = {b["label"]: b["count"] for b in out["unassigned"]["bins"]}
    assert out["unassigned"]["total"] == 3          # el corrupto NO cuenta
    assert un == {"0-7": 1, "8-30": 1, "31-90": 0, "91-180": 0,
                  "181-365": 1, ">365": 0}
    assert out["unassigned"]["median_days"] == pytest.approx(20.0)  # de [3,20,200]

    asg = {b["label"]: b["count"] for b in out["assigned"]["bins"]}
    assert out["assigned"]["total"] == 2            # el publicado NO cuenta
    assert asg == {"0-7": 0, "8-30": 1, "31-90": 0, "91-180": 0,
                   "181-365": 0, ">365": 1}
    assert out["assigned"]["median_days"] == pytest.approx(205.0)   # de [10,400]


# ---------------------------------------------------------------- granularidad semanal / days

def test_period_bounds_semana_iso():
    b = q._period_bounds("2026-W29", "week")
    assert b is not None
    start, end = b
    # W29 de 2026 empieza el lunes 2026-07-13.
    assert start == dt.datetime(2026, 7, 13, tzinfo=dt.UTC)
    assert end == start + dt.timedelta(days=7)
    assert q._period_bounds("basura", "week") is None


def test_trend_days_ventana(db, session: Session) -> None:
    # dentro de 5 días y fuera (40 días): con days=7 solo entra el reciente.
    _mk_published(session, "CVE-2026-7001", nvd_published=False)
    _mk_candidate(session, cve="CVE-2026-7001", product="a",
                  first_seen=NOW - dt.timedelta(days=3))
    _mk_published(session, "CVE-2026-7002", nvd_published=False)
    _mk_candidate(session, cve="CVE-2026-7002", product="a",
                  first_seen=NOW - dt.timedelta(days=40))
    session.commit()
    reciente = sum(r["pre_published"] for r in
                   q.trend_series(session, "week", months=12, days=7))
    amplio = sum(r["pre_published"] for r in
                 q.trend_series(session, "week", months=12, days=90))
    assert reciente == 1 and amplio == 2


def test_queue_age_exclude_backfill(sources_seeded, session: Session) -> None:
    # unassigned solo-backfill (osv) NO cuenta con exclude_backfill=True; el que
    # tiene además una fuente no-backfill (github_commits) sí.
    solo_bf = _mk_candidate(session, cve=None, product="a",
                            first_seen=NOW - dt.timedelta(days=400))
    _add_mention(session, solo_bf, "osv")
    mixto = _mk_candidate(session, cve=None, product="a",
                          first_seen=NOW - dt.timedelta(days=400))
    _add_mention(session, mixto, "osv"); _add_mention(session, mixto, "github_commits")
    session.commit()
    con = q.queue_age(session, exclude_backfill=True)
    sin = q.queue_age(session, exclude_backfill=False)
    assert con["unassigned"]["total"] == 1     # solo el mixto
    assert sin["unassigned"]["total"] == 2


def test_source_stats_guarda_fechas_corruptas(sources_seeded, session: Session) -> None:
    # candidate con days_ahead absurdo (>3650) y first_seen año 0001: ignorado.
    good = _mk_candidate(session, cve="CVE-2026-8001", product="a")
    _set_days_ahead(session, good, 10); _add_mention(session, good, "redhat_csaf")
    bad = _mk_candidate(session, cve="CVE-2026-8002", product="a",
                        first_seen=dt.datetime(1, 1, 1, tzinfo=dt.UTC))
    _set_days_ahead(session, bad, 900000); _add_mention(session, bad, "redhat_csaf")
    session.commit()
    stats = {r["source"]: r for r in q.source_stats(session)}
    assert "redhat_csaf" in stats
    assert stats["redhat_csaf"]["avg_days"] == 10.0   # el corrupto no infla
    assert stats["redhat_csaf"]["candidates"] == 1
