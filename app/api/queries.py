"""Consultas de solo lectura para la API (y reutilizadas por la CLI).

Devuelven estructuras JSON-friendly (dicts/listas). El concepto central:
- "published"      = CVEs oficialmente publicados (published_cves, state=PUBLISHED).
- "pre_published"  = pendientes ("pending"): CVEs identificados en otras fuentes
                     que NVD aún no ha publicado, por su primera detección
                     (first_seen_at). Ver PENDING_WHERE_SQL.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.operational import (
    OPERATIONAL_MIN_DATE_ISO,
    old_cve_identifier_sql,
    operational_candidate_sql,
    operational_published_sql,
)

# Allowlist de granularidad -> (unidad date_trunc, formato to_char).
# granularidad -> (unidad date_trunc, formato to_char). 'week' usa semana ISO
# (IYYY = año-ISO, IW = semana-ISO) -> etiquetas tipo "2026-W29".
_GRAN = {"week": ("week", 'IYYY-"W"IW'),
         "month": ("month", "YYYY-MM"),
         "year": ("year", "YYYY")}

# ----------------------------------------------------------------- pending
# Definición CANÓNICA de "pending" — la métrica central del proyecto (decisión
# de producto 2026-07-19, ver docs/AGENT_CHANGELOG.md): vulnerabilidades
# identificadas en otras fuentes de las que NVD aún no ha publicado nada. Entran:
#   a) candidates CON cve_id sin datos en NVD (sin fila en published_cves o
#      nvd_published_at NULL), excluyendo CVEs REJECTED por MITRE, y
#   b) candidates PRE-CVE (cve_id NULL): GHSA/RUSTSEC/GO/PYSEC/VU#… aún sin CVE.
# Siempre con tecnología asociada NO-malware: los advisories de paquetes
# maliciosos (OSV MAL-*, kind='malware') son señal de otra naturaleza y se
# cuentan aparte, no aquí. Excluye tombstones fusionados y rejected.
# El dashboard operativo empieza en 2026: registros anteriores proceden de
# backfills/catálogos históricos heterogéneos y no representan la ventana de
# detección que se pretende explicar. Se conservan en BD, pero no se mezclan con
# pending ni con sus KPIs (incluido KEV). Además, un CVE de un año anterior que
# continúa ausente del espejo oficial es una inconsistencia de fuente, no una
# señal pre-reservada actual.
# La CLI (app/cli.py) reutiliza estas funciones: NO dupliques este fragmento.
_PENDING_MIN_DATE = OPERATIONAL_MIN_DATE_ISO
_NVD_SILENT_SQL = (
    "( c.cve_id IS NULL OR NOT EXISTS (SELECT 1 FROM published_cves p"
    " WHERE p.id = c.cve_id"
    " AND (p.nvd_published_at IS NOT NULL OR p.state = 'REJECTED')) )"
)
_PENDING_SIGNAL_SQL = (
    _NVD_SILENT_SQL
    + " AND EXISTS (SELECT 1 FROM affected_products ap0"
    " WHERE ap0.candidate_id = c.id"
    " AND (ap0.kind IS NULL OR ap0.kind <> 'malware'))"
    " AND NOT EXISTS (SELECT 1 FROM affected_products apm"
    " WHERE apm.candidate_id = c.id AND apm.kind = 'malware')"
)
# withdrawn IS NOT TRUE: advisories retirados o "Duplicate Advisory" de GHSA
# no son pendientes reales.
PENDING_BASE_WHERE_SQL = (
    "c.merged_into IS NULL AND c.status <> 'rejected'"
    " AND c.withdrawn IS NOT TRUE AND " + _PENDING_SIGNAL_SQL
)
PENDING_WHERE_SQL = (
    PENDING_BASE_WHERE_SQL
    + " AND " + operational_candidate_sql("c")
)
SOURCE_INCONSISTENCY_WHERE_SQL = (
    PENDING_BASE_WHERE_SQL + " AND " + old_cve_identifier_sql("c")
)

# Desglose de `pending` por MADUREZ del identificador. cvelistV5 (MITRE) solo
# publica CVEs PUBLISHED/REJECTED — los RESERVED no son públicos — así que un CVE
# citado en un commit/advisory sin ficha oficial es la señal MÁS temprana con
# número CVE. Tres estados (partición exacta del conjunto pending):
#   pre_cve          identificada solo por códigos nativos (ZDI-CAN, GHSA,
#                    RUSTSEC, VU#...) — aún sin CVE asignado.
#   cve_prereserved  YA tiene CVE (p.ej. citado en un commit) pero NO hay ninguna
#                    ficha oficial de él en nuestro espejo MITRE/NVD: un CNA lo
#                    asignó y todavía no hay registro público. La señal estrella.
#   cve_reserved     tiene CVE con ficha en el espejo (MITRE/NVD lo conocen) pero
#                    NVD aún no publica datos (reservado / pendiente de análisis).
_HAS_MIRROR = "EXISTS (SELECT 1 FROM published_cves p WHERE p.id = c.cve_id)"
MATURITY_SQL = {
    "pre_cve": "c.cve_id IS NULL",
    "cve_prereserved": "c.cve_id IS NOT NULL AND NOT " + _HAS_MIRROR,
    "cve_reserved": "c.cve_id IS NOT NULL AND " + _HAS_MIRROR,
}

# Variante booleana para etiquetar filas, p.ej. en software_detail. Reutiliza la
# definición completa para no reintroducir retirados, malware o históricos.
PENDING_EXPR_SQL = "( " + PENDING_WHERE_SQL + " )"

# Fuentes de BACKFILL histórico: en el arranque inicial ingirieron catálogos
# enteros (GHSA, todos los ecosistemas OSV) con `seen_at` = fecha REAL de
# publicación del advisory, a veces años atrás. Para un candidate cuya ÚNICA
# fuente es una de estas, `days_ahead_vs_nvd_present` mide ese backfill, no una
# ventaja operativa real (medias ~2108 d github_advisories, ~493 d osv). El
# histograma de lag y la cola de espera los excluyen por defecto. Se incluye
# gemnasium: la cola de pendientes sin CVE >365 d es casi 100% de estas fuentes
# de archivo y desvirtúa la lectura de "antigüedad real".
BACKFILL_SOURCES = ("github_advisories", "osv", "gemnasium")

# Suelo de fechas válidas: candidates con first_seen_at anterior (p.ej. el año
# 0001 por una fecha 'published' cero en OSV/Debian, ya corregido en el fetcher)
# darían un days_ahead disparatado. Se excluyen en el histograma. Los CVE no
# existían antes de 1999, pero 1990 es un margen conservador.
_LAG_MIN_DATE = "1990-01-01"

# Bins (plantilla {col}). `present`: el primer bin `<= 1` capta 0/1 y cualquier
# delta negativo residual (los grandes negativos ya salen por la guarda de
# observación tardía). `published`: bucket propio `<= 0` = NVD publicó antes o a
# la vez (no hubo atraso), separado del adelanto positivo.
_LAG_BINS = (
    ("0-1", "{col} <= 1"),
    ("2-7", "{col} BETWEEN 2 AND 7"),
    ("8-14", "{col} BETWEEN 8 AND 14"),
    ("15-30", "{col} BETWEEN 15 AND 30"),
    ("31-60", "{col} BETWEEN 31 AND 60"),
    ("61-90", "{col} BETWEEN 61 AND 90"),
    (">90", "{col} > 90"),
)
_LAG_BINS_PUBLISHED = (
    ("<=0", "{col} <= 0"),
    ("1-7", "{col} BETWEEN 1 AND 7"),
    ("8-14", "{col} BETWEEN 8 AND 14"),
    ("15-30", "{col} BETWEEN 15 AND 30"),
    ("31-60", "{col} BETWEEN 31 AND 60"),
    ("61-90", "{col} BETWEEN 61 AND 90"),
    (">90", "{col} > 90"),
)
# metric -> (columna del candidate, bins). `present` = ventaja robusta (nuestra
# observación en NVD); `published` = atraso de NVD frente a fechas oficiales del
# advisory (first_seen) vs published_cves.nvd_published_at.
_LAG_METRICS = {
    "present": ("days_ahead_vs_nvd_present", _LAG_BINS),
    "published": ("days_ahead_vs_nvd_published", _LAG_BINS_PUBLISHED),
}

# "Cola de espera": antigüedad (días desde first_seen_at hasta now()) de las
# pendientes. Bins plantilla {age}. El grupo se decide fuera (cve_id NULL/NOT).
_QUEUE_AGE_EXPR = "floor(extract(epoch FROM (now() - c.first_seen_at)) / 86400)"
_QUEUE_AGE_BINS = (
    ("0-7", "{age} BETWEEN 0 AND 7"),
    ("8-30", "{age} BETWEEN 8 AND 30"),
    ("31-90", "{age} BETWEEN 31 AND 90"),
    ("91-180", "{age} BETWEEN 91 AND 180"),
    ("181-365", "{age} BETWEEN 181 AND 365"),
    (">365", "{age} > 365"),
)
# Partición del conjunto pending por asignación de CVE.
_QUEUE_GROUPS = {
    "unassigned": "c.cve_id IS NULL",       # esperando asignación de CVE
    "assigned": "c.cve_id IS NOT NULL",     # esperando publicación en NVD
}


def _like_pattern(term: str, *, contains: bool = True) -> str:
    """Escapa los comodines LIKE (%, _) y la barra invertida del input del
    usuario; usar siempre junto a ESCAPE '\\' en la query."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%" if contains else escaped


def _period_bounds(period: str, granularity: str) -> tuple[_dt.datetime, _dt.datetime] | None:
    """Convierte 'YYYY-Www'/'YYYY-MM'/'YYYY' en [inicio, fin) para filtrar."""
    try:
        if granularity == "week":
            # 'YYYY-Www' (semana ISO) -> [lunes ISO, lunes+7d).
            ys, ws = period.upper().split("-W")
            start = _dt.datetime.fromisocalendar(int(ys), int(ws), 1).replace(tzinfo=_dt.UTC)
            return start, start + _dt.timedelta(days=7)
        if granularity == "year":
            y = int(period)
            return (_dt.datetime(y, 1, 1, tzinfo=_dt.UTC),
                    _dt.datetime(y + 1, 1, 1, tzinfo=_dt.UTC))
        y, m = (int(x) for x in period.split("-"))
        start = _dt.datetime(y, m, 1, tzinfo=_dt.UTC)
        end = _dt.datetime(y + (m // 12), (m % 12) + 1, 1, tzinfo=_dt.UTC)
        return start, end
    except (ValueError, TypeError):
        return None


def _pending_filter(kind: str | None, tech: str | None) -> tuple[str, dict[str, Any]]:
    """Fragmento SQL (sin 'AND' inicial) + params para restringir candidates
    por kind/tecnología de sus affected_products."""
    clauses = []
    params: dict[str, Any] = {}
    if kind and kind != "all":
        clauses.append("ap.kind = :kind")
        params["kind"] = kind
    if tech:
        clauses.append("ap.product ILIKE :tech ESCAPE '\\'")
        params["tech"] = _like_pattern(tech)
    if clauses:
        frag = ("EXISTS (SELECT 1 FROM affected_products ap "
                "WHERE ap.candidate_id = c.id AND " + " AND ".join(clauses) + ")")
        return frag, params
    return "", params


def trend_series(session: Session, granularity: str = "month", months: int = 12,
                 kind: str | None = None, tech: str | None = None,
                 days: int | None = None,
                 include_historical: bool = False) -> list[dict[str, Any]]:
    """Serie temporal: publicados vs pendientes (pre-publicados) por periodo.

    El cutoff se alinea al inicio del periodo (date_trunc) para que el bucket
    más antiguo sea COMPLETO. Si se pasa `days`, la ventana es de N días (ignora
    `months`) — útil con granularidad semanal para ventanas cortas.
    """
    unit, fmt = _GRAN.get(granularity, _GRAN["month"])
    months = max(1, months)
    # La ventana: por días (si days) o por meses. make_interval con el param que
    # toque; el otro queda inactivo.
    if days is not None:
        window_sql = "make_interval(days => :days)"
        window_params: dict[str, Any] = {"days": days}
    else:
        window_sql = "make_interval(months => :months)"
        window_params = {"months": months}
    cutoff_sql = f"date_trunc('{unit}', now()) - {window_sql}"

    pub_scope = "" if include_historical else " AND " + operational_published_sql(
        "published_cves"
    )
    pending_scope = PENDING_BASE_WHERE_SQL if include_historical else PENDING_WHERE_SQL
    pub = session.execute(text(f"""
        SELECT to_char(date_trunc('{unit}', cvelist_published_at), '{fmt}') AS period,
               count(*) AS n
        FROM published_cves
        WHERE state='PUBLISHED'
          AND cvelist_published_at >= {cutoff_sql}
          {pub_scope}
        GROUP BY 1
    """), window_params).all()

    frag, params = _pending_filter(kind, tech)
    params.update(window_params)
    and_frag = f"AND {frag}" if frag else ""
    # Desglose de pre_published por MADUREZ en la MISMA query (FILTER reutiliza
    # MATURITY_SQL): pre_cve + cve_prereserved + cve_reserved == pre_published
    # por periodo (partición exacta). Alimenta el gráfico de detecciones por
    # madurez y las sparklines de KPIs del dashboard.
    pre = session.execute(text(f"""
        SELECT to_char(date_trunc('{unit}', c.first_seen_at), '{fmt}') AS period,
               count(DISTINCT c.id) AS n,
               count(DISTINCT c.id) FILTER (WHERE {MATURITY_SQL['pre_cve']})
                   AS pre_cve,
               count(DISTINCT c.id) FILTER (WHERE {MATURITY_SQL['cve_prereserved']})
                   AS cve_prereserved,
               count(DISTINCT c.id) FILTER (WHERE {MATURITY_SQL['cve_reserved']})
                   AS cve_reserved
        FROM candidates c
        WHERE {pending_scope}
          {and_frag}
          AND c.first_seen_at >= {cutoff_sql}
        GROUP BY 1
    """), params).all()

    def _blank(period: str) -> dict[str, Any]:
        return {"period": period, "published": 0, "pre_published": 0,
                "pre_cve": 0, "cve_prereserved": 0, "cve_reserved": 0}

    merged: dict[str, dict[str, Any]] = {}
    for period, n in pub:
        merged.setdefault(period, _blank(period))["published"] = int(n)
    for period, n, pc, pr, rs in pre:
        row = merged.setdefault(period, _blank(period))
        row["pre_published"] = int(n)
        row["pre_cve"] = int(pc)
        row["cve_prereserved"] = int(pr)
        row["cve_reserved"] = int(rs)
    return [merged[p] for p in sorted(merged)]


def pending_top(session: Session, kind: str = "product", top: int = 20,
                tech: str | None = None, period: str | None = None,
                granularity: str = "month",
                maturity: str = "all") -> dict[str, Any]:
    """Ranking de software con más vulns pendientes + desglose por kind y por
    madurez (pre_cve | cve_reserved).

    Agrega en SQL (count DISTINCT / GROUP BY) en vez de traer las filas y
    contarlas en Python."""
    extra = ""
    params: dict[str, Any] = {}
    if maturity != "all":
        if maturity not in MATURITY_SQL:
            raise ValueError(f"maturity inválida: {maturity!r}")
        extra += " AND " + MATURITY_SQL[maturity]
    if period:
        bounds = _period_bounds(period, granularity)
        if bounds:
            # += : un period NO debe descartar el filtro de madurez ya acumulado
            extra += " AND c.first_seen_at >= :pstart AND c.first_seen_at < :pend"
            params["pstart"], params["pend"] = bounds

    # RENDIMIENTO: antes se evaluaba PENDING_WHERE_SQL 6 veces (total + by_kind +
    # 3× madurez + top), y cada una fuerza el escaneo caro de affected_products.
    # Ahora son 2 queries, cada una con `pend AS MATERIALIZED` -> el predicado se
    # evalúa UNA sola vez por query. total/by_kind/by_maturity salen de un solo
    # UNION ALL; el top va aparte (necesita ORDER BY ... LIMIT).
    metrics = session.execute(text(f"""
        WITH pend AS MATERIALIZED (
          SELECT c.id, c.cve_id FROM candidates c WHERE {PENDING_WHERE_SQL}{extra}
        )
        SELECT 'total' AS dim, '' AS key, count(*) AS n FROM pend
        UNION ALL
        SELECT 'kind', COALESCE(a.kind, ''), count(DISTINCT p.id)
          FROM pend p JOIN affected_products a ON a.candidate_id = p.id
          GROUP BY a.kind
        UNION ALL
        SELECT 'maturity', 'pre_cve', count(*) FROM pend WHERE cve_id IS NULL
        UNION ALL
        SELECT 'maturity', 'cve_prereserved', count(*) FROM pend p WHERE cve_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM published_cves pp WHERE pp.id = p.cve_id)
        UNION ALL
        SELECT 'maturity', 'cve_reserved', count(*) FROM pend p WHERE cve_id IS NOT NULL
          AND EXISTS (SELECT 1 FROM published_cves pp WHERE pp.id = p.cve_id)
    """), params).all()
    total = 0
    by_kind: dict[str, int] = {}
    by_maturity_all: dict[str, int] = {}
    for dim, key, n in metrics:
        if dim == "total":
            total = int(n)
        elif dim == "kind" and key:
            by_kind[key] = int(n)
        elif dim == "maturity":
            by_maturity_all[key] = int(n)

    filt = ""
    if kind != "all":
        filt = " AND a.kind = :kind"
        params["kind"] = kind
    if tech:
        filt += " AND a.product ILIKE :tech ESCAPE '\\'"
        params["tech"] = _like_pattern(tech)
    params["top"] = top
    rows = session.execute(text(f"""
        WITH pend AS MATERIALIZED (
          SELECT c.id FROM candidates c WHERE {PENDING_WHERE_SQL}{extra}
        )
        SELECT a.product, count(DISTINCT p.id) AS pending
        FROM pend p JOIN affected_products a ON a.candidate_id = p.id
        WHERE TRUE{filt}
        GROUP BY a.product
        ORDER BY pending DESC, a.product
        LIMIT :top
    """), params).all()
    out = {
        "total": total,
        "by_kind": by_kind,
        "kind": kind,
        "maturity": maturity,
        "top": [{"software": s, "pending": int(n)} for s, n in rows],
    }
    if maturity == "all":
        out["by_maturity"] = by_maturity_all
    return out


def _lag_source_filter(source: str | None, params: dict[str, Any]) -> str:
    """Fragmento (con AND inicial) para restringir a candidates con mención de
    `source`; cadena vacía si no se filtra."""
    if not source:
        return ""
    params["source"] = source
    return (" AND EXISTS (SELECT 1 FROM mentions m JOIN sources s ON s.id = m.source_id"
            " WHERE m.candidate_id = c.id AND s.name = :source)")


def _exclude_backfill_sql(params: dict[str, Any]) -> str:
    """Fragmento (sin AND inicial): conserva el candidate solo si tiene ALGUNA
    mención de una fuente NO-backfill (ver BACKFILL_SOURCES). Rellena params."""
    placeholders = ", ".join(f":bf{i}" for i in range(len(BACKFILL_SOURCES)))
    for i, name in enumerate(BACKFILL_SOURCES):
        params[f"bf{i}"] = name
    return ("EXISTS (SELECT 1 FROM mentions m JOIN sources s ON s.id = m.source_id"
            f" WHERE m.candidate_id = c.id AND s.name NOT IN ({placeholders}))")


def lag_histogram(session: Session, months: int = 12, exclude_backfill: bool = True,
                  metric: str = "present", source: str | None = None,
                  include_historical: bool = False) -> dict[str, Any]:
    """Distribución de la ventaja/atraso de Foreshock frente a NVD.

    `metric`:
      - "present" (default, comportamiento actual): días entre nuestra primera
        detección y NUESTRA observación del CVE en NVD
        (days_ahead_vs_nvd_present). Aplica `exclude_backfill`.
      - "published": ATRASO de NVD frente a fechas oficiales — first_seen del
        advisory vs published_cves.nvd_published_at (days_ahead_vs_nvd_published).
        Aquí el archivo histórico ES el objeto de estudio, así que NO se aplica
        exclude_backfill. Añade `censored_count` (candidates con cve_id cuyo CVE
        aún no tiene nvd_published_at: atraso ABIERTO/censurado a la derecha) y
        `by_year` (cohorte por año de first_seen_at: n, media, mediana).

    Común: mediana + p90 (percentile_cont en SQL); `months` filtra por
    first_seen_at; ignora `days_ahead NULL` y fechas < 1990 (fechas cero
    corruptas, ver AGENT_CHANGELOG); `source` opcional restringe a una fuente.
    """
    if metric not in _LAG_METRICS:
        raise ValueError(f"metric inválida: {metric!r}")
    col, bins = _LAG_METRICS[metric]
    ccol = f"c.{col}"
    # El archivo histórico es el objeto de estudio del atraso: no se excluye.
    if metric == "published":
        exclude_backfill = False
    months = max(1, months)
    params: dict[str, Any] = {"months": months}

    where = [
        "c.merged_into IS NULL",
        "c.first_seen_at >= date_trunc('month', now()) - make_interval(months => :months)",
    ]
    if include_historical:
        where.append(f"c.first_seen_at >= '{_LAG_MIN_DATE}'::timestamptz")
    else:
        where.append(operational_candidate_sql("c"))
    if exclude_backfill:
        where.append(_exclude_backfill_sql(params))
    where_sql = " AND ".join(where) + _lag_source_filter(source, params)

    bin_exprs = ",\n           ".join(
        f"count(*) FILTER (WHERE {cond.format(col=ccol)}) AS bin_{i}"
        for i, (_, cond) in enumerate(bins)
    )
    row = session.execute(text(f"""
        SELECT count(*) FILTER (WHERE {ccol} IS NOT NULL) AS n,
               percentile_cont(0.5) WITHIN GROUP (ORDER BY {ccol}) AS median,
               percentile_cont(0.9) WITHIN GROUP (ORDER BY {ccol}) AS p90,
               {bin_exprs}
        FROM candidates c
        WHERE {where_sql}
    """), params).mappings().one()

    out: dict[str, Any] = {
        "metric": metric,
        "months": months,
        "exclude_backfill": exclude_backfill,
        "source": source,
        "count": int(row["n"]),
        "median": float(row["median"]) if row["median"] is not None else None,
        "p90": float(row["p90"]) if row["p90"] is not None else None,
        "bins": [{"label": label, "count": int(row[f"bin_{i}"])}
                 for i, (label, _) in enumerate(bins)],
    }

    if metric == "published":
        # Atraso censurado a la derecha: vimos el advisory (tiene cve_id) pero
        # NVD todavía NO ha publicado ese CVE -> el atraso sigue creciendo.
        out["censored_count"] = int(session.execute(text(f"""
            SELECT count(*) FROM candidates c
            WHERE {where_sql} AND c.cve_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM published_cves p
                              WHERE p.id = c.cve_id AND p.nvd_published_at IS NOT NULL)
        """), params).scalar_one())
        # Cohorte por año de first_seen_at (fechas < 1990 ya excluidas).
        year_rows = session.execute(text(f"""
            SELECT date_part('year', c.first_seen_at)::int AS year,
                   count(*) AS n,
                   round(avg({ccol})::numeric, 1) AS mean,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY {ccol}) AS median
            FROM candidates c
            WHERE {where_sql} AND {ccol} IS NOT NULL
            GROUP BY 1 ORDER BY 1
        """), params).mappings().all()
        out["by_year"] = [
            {"year": int(r["year"]), "n": int(r["n"]),
             "mean": float(r["mean"]) if r["mean"] is not None else None,
             "median": float(r["median"]) if r["median"] is not None else None}
            for r in year_rows
        ]
    return out


def queue_age(session: Session, exclude_backfill: bool = True) -> dict[str, Any]:
    """"Cola de espera": distribución de la ANTIGÜEDAD (días desde first_seen_at
    hasta ahora) de las vulnerabilidades pendientes (conjunto canónico
    PENDING_WHERE_SQL), partida en dos grupos:
      - unassigned: sin cve_id (esperando asignación de CVE)
      - assigned:   con cve_id (esperando publicación en NVD)
    Por grupo: bins fijos de días, total y median_days (percentile_cont en SQL).
    Excluye first_seen_at < 1990 (fechas cero corruptas, ver AGENT_CHANGELOG).
    `exclude_backfill` (misma semántica que /api/lag/histogram): descarta
    candidates cuya ÚNICA fuente es de archivo histórico — la cola sin CVE
    >365 d es casi 100% de esas fuentes y desvirtúa la lectura."""
    age = _QUEUE_AGE_EXPR
    bin_exprs = ",\n               ".join(
        f"count(*) FILTER (WHERE {cond.format(age=age)}) AS bin_{i}"
        for i, (_, cond) in enumerate(_QUEUE_AGE_BINS)
    )
    out: dict[str, Any] = {}
    for name, group_cond in _QUEUE_GROUPS.items():
        params: dict[str, Any] = {}
        where = (f"{PENDING_WHERE_SQL} AND c.first_seen_at >= '{_LAG_MIN_DATE}'::timestamptz"
                 f" AND {group_cond}")
        if exclude_backfill:
            where += " AND " + _exclude_backfill_sql(params)
        row = session.execute(text(f"""
            SELECT count(*) AS n,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY {age}) AS median,
                   {bin_exprs}
            FROM candidates c
            WHERE {where}
        """), params).mappings().one()
        out[name] = {
            "total": int(row["n"]),
            "median_days": float(row["median"]) if row["median"] is not None else None,
            "bins": [{"label": label, "count": int(row[f"bin_{i}"])}
                     for i, (label, _) in enumerate(_QUEUE_AGE_BINS)],
        }
    return out


# CASE (SQL) que etiqueta la MADUREZ de un candidate para filas que pueden NO
# ser pendientes (p.ej. en emerging): null si no es pending; si lo es, la
# partición pre_cve/cve_prereserved/cve_reserved. Reutiliza PENDING_WHERE_SQL y
# MATURITY_SQL — no dupliques esos fragmentos.
_MATURITY_CASE_SQL = (
    "CASE WHEN " + PENDING_WHERE_SQL + " THEN (CASE"
    " WHEN " + MATURITY_SQL["pre_cve"] + " THEN 'pre_cve'"
    " WHEN " + MATURITY_SQL["cve_prereserved"] + " THEN 'cve_prereserved'"
    " ELSE 'cve_reserved' END) ELSE NULL END"
)


def emerging_list(session: Session, *, since_days: int | None = None, source: str | None = None,
                  tier: int | None = None, kind: str | None = None, in_kev: bool | None = None,
                  tech: str | None = None, pending_only: bool = False,
                  maturity: str | None = None,
                  period: str | None = None, granularity: str = "month",
                  page: int = 1, page_size: int = 50,
                  include_historical: bool = False) -> dict[str, Any]:
    """Tabla de candidates con filtros y paginación. Cada fila incluye `maturity`
    (null si no es pendiente) y `first_seen_at`."""
    where = ["c.merged_into IS NULL"]
    params: dict[str, Any] = {}
    if not include_historical:
        where.append(operational_candidate_sql("c"))
    if maturity is not None:
        if maturity not in MATURITY_SQL:
            raise ValueError(f"maturity inválida: {maturity!r}")
        # La madurez solo es significativa DENTRO del conjunto pending (un CVE ya
        # publicado también cumpliría "cve_id NOT NULL AND mirror", pero NO es
        # 'cve_reserved'). Por eso el filtro implica pending, igual que el CASE
        # de `maturity` y que /api/pending.
        where.append(PENDING_WHERE_SQL + " AND " + MATURITY_SQL[maturity])
    if since_days:
        where.append("c.last_seen_at >= :since_cutoff")
        params["since_cutoff"] = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=since_days)
    if period:
        bounds = _period_bounds(period, granularity)
        if bounds:
            where.append("c.first_seen_at >= :pstart AND c.first_seen_at < :pend")
            params["pstart"], params["pend"] = bounds
    if in_kev:
        where.append("c.in_kev IS TRUE")
    if pending_only:
        # Definición canónica completa: además de la fecha, excluye rejected,
        # withdrawn y tombstones exactamente igual que el resto del dashboard.
        where.append(PENDING_WHERE_SQL)
    if source or tier is not None:
        sub = ["SELECT 1 FROM mentions m JOIN sources s ON s.id=m.source_id "
               "WHERE m.candidate_id=c.id"]
        if source:
            sub.append("AND s.name=:source")
            params["source"] = source
        if tier is not None:
            sub.append("AND s.tier=:tier")
            params["tier"] = tier
        where.append("EXISTS (" + " ".join(sub) + ")")
    if kind or tech:
        frag, fparams = _pending_filter(kind, tech)
        if frag:
            where.append(frag)
            params.update(fparams)
    where_sql = " AND ".join(where)

    total = session.execute(text(
        f"SELECT count(*) FROM candidates c WHERE {where_sql}"), params).scalar_one()
    params["limit"] = page_size
    params["offset"] = (max(1, page) - 1) * page_size
    rows = session.execute(text(f"""
        SELECT c.id, c.cve_id, c.status, c.vuln_type, c.in_kev,
               c.days_ahead_vs_nvd_present, c.mention_count, c.source_count,
               c.severity_hint, c.last_seen_at, c.first_seen_at,
               {_MATURITY_CASE_SQL} AS maturity,
               (SELECT base_score FROM cvss_scores v WHERE v.candidate_id=c.id
                  ORDER BY base_score DESC NULLS LAST LIMIT 1) AS cvss,
               (SELECT string_agg(DISTINCT s.name, ',') FROM mentions m
                  JOIN sources s ON s.id=m.source_id WHERE m.candidate_id=c.id) AS sources
        FROM candidates c WHERE {where_sql}
        ORDER BY c.last_seen_at DESC LIMIT :limit OFFSET :offset
    """), params).mappings().all()
    return {"total": int(total), "page": page, "page_size": page_size,
            "rows": [dict(r) for r in rows]}


def candidate_detail(
    session: Session, key: str, *, include_historical: bool = False
) -> dict[str, Any] | None:
    """Deepdive de una nota/candidate: ids, cvss, epss, afectados, refs, timeline."""
    scope = "" if include_historical else " AND " + operational_candidate_sql("c")
    cid = session.execute(
        text("SELECT c.id FROM candidates c WHERE c.cve_id=:k "
             "AND c.merged_into IS NULL" + scope +
             " ORDER BY c.first_seen_at LIMIT 1"),
        {"k": key.upper()}).scalar_one_or_none()
    if cid is None:
        try:
            cid = uuid.UUID(key)
        except ValueError:
            return None
    c = session.execute(text(
        "SELECT c.* FROM candidates c WHERE c.id=:id" + scope),
                        {"id": cid}).mappings().first()
    if c is None:
        return None
    ids = session.execute(text(
        "SELECT scheme, value FROM identifiers WHERE candidate_id=:id ORDER BY scheme, value"),
        {"id": cid}).mappings().all()
    cvss = session.execute(text(
        "SELECT version, base_score, base_severity, provenance, source, vector "
        "FROM cvss_scores WHERE candidate_id=:id ORDER BY provenance, version"),
        {"id": cid}).mappings().all()
    affected = session.execute(text(
        "SELECT vendor, product, ecosystem, purl, kind FROM affected_products "
        "WHERE candidate_id=:id"), {"id": cid}).mappings().all()
    timeline = session.execute(text(
        "SELECT m.seen_at, s.name AS source, m.title, m.url "
        "FROM mentions m JOIN sources s ON s.id=m.source_id "
        "WHERE m.candidate_id=:id ORDER BY m.seen_at"), {"id": cid}).mappings().all()
    epss = None
    if c["cve_id"]:
        epss = session.execute(text(
            "SELECT score, percentile, scored_date FROM epss_scores "
            "WHERE cve_id=:cve ORDER BY scored_date DESC LIMIT 1"),
            {"cve": c["cve_id"]}).mappings().first()
    return {
        "id": str(cid), "cve_id": c["cve_id"], "status": c["status"],
        "vuln_type": c["vuln_type"], "attack_vector": c["attack_vector"],
        "has_public_poc": c["has_public_poc"], "severity_hint": c["severity_hint"],
        "in_kev": c["in_kev"], "kev_date": c["kev_date"], "kev_source": c["kev_source"],
        "days_ahead_present": c["days_ahead_vs_nvd_present"],
        "days_ahead_analyzed": c["days_ahead_vs_nvd_analyzed"],
        "cwe_ids": c["cwe_ids"], "reference_urls": c["reference_urls"],
        "identifiers": [dict(r) for r in ids],
        "cvss": [dict(r) for r in cvss],
        "affected": [dict(r) for r in affected],
        "epss": dict(epss) if epss else None,
        "timeline": [dict(r) for r in timeline],
    }


def software_detail(session: Session, ecosystem: str, name: str,
                    granularity: str = "month", months: int = 24,
                    include_historical: bool = False) -> dict[str, Any]:
    """Deepdive por tecnología: publicados vs pendientes de un paquete + su serie."""
    unit, fmt = _GRAN.get(granularity, _GRAN["month"])
    params = {
        # Match exacto case-insensitive: se escapan los comodines del input.
        "eco": _like_pattern(ecosystem, contains=False) if ecosystem else "",
        "name": _like_pattern(name, contains=False),
        "months": max(1, months),
    }
    operational_scope = (
        "" if include_historical else " AND " + operational_candidate_sql("c")
    )
    cands = session.execute(text(f"""
        SELECT DISTINCT c.id, c.cve_id, c.first_seen_at, c.in_kev,
               {PENDING_EXPR_SQL} AS pending
        FROM candidates c JOIN affected_products a ON a.candidate_id=c.id
        WHERE c.merged_into IS NULL AND a.product ILIKE :name ESCAPE '\\'
          AND ( :eco='' OR a.ecosystem ILIKE :eco ESCAPE '\\' )
          AND c.first_seen_at >= date_trunc('{unit}', now()) - make_interval(months => :months)
          {operational_scope}
        ORDER BY c.first_seen_at DESC NULLS LAST
    """), params).mappings().all()
    series: dict[str, dict[str, int]] = {}
    for r in cands:
        if r["first_seen_at"] is None:
            continue
        period = r["first_seen_at"].strftime("%Y-%m" if granularity == "month" else "%Y")
        s = series.setdefault(period, {"period": period, "pending": 0, "identified": 0})
        s["identified"] += 1
        if r["pending"]:
            s["pending"] += 1
    return {
        "ecosystem": ecosystem, "product": name,
        "total": len(cands),
        "pending": sum(1 for r in cands if r["pending"]),
        "series": [series[p] for p in sorted(series)],
        "candidates": [{"id": str(r["id"]), "cve_id": r["cve_id"],
                        "pending": r["pending"], "in_kev": r["in_kev"],
                        "first_seen": r["first_seen_at"]} for r in cands[:200]],
    }


def source_stats(
    session: Session, *, include_historical: bool = False
) -> list[dict[str, Any]]:
    """Media de días de ventaja por fuente (deduplicada, sin fusionados).

    Guarda defensiva: ignora days_ahead > 3650 o first_seen_at < 1990 — fechas
    corruptas residuales (ver AGENT_CHANGELOG) no deben volver a inflar medias.
    """
    operational_scope = (
        "" if include_historical else " AND " + operational_candidate_sql("c")
    )
    rows = session.execute(text(f"""
        SELECT source, round(avg(days_ahead)::numeric, 1) AS avg_days, count(*) AS candidates
        FROM (
          SELECT DISTINCT s.name AS source, c.id, c.days_ahead_vs_nvd_present AS days_ahead
          FROM sources s JOIN mentions m ON m.source_id=s.id
          JOIN candidates c ON c.id=m.candidate_id
          WHERE c.days_ahead_vs_nvd_present IS NOT NULL AND c.merged_into IS NULL
            AND c.days_ahead_vs_nvd_present <= 3650
            AND c.first_seen_at >= '{_LAG_MIN_DATE}'::timestamptz
            {operational_scope}
        ) t GROUP BY source ORDER BY avg_days DESC
    """)).mappings().all()
    return [dict(r) for r in rows]


# ---------------------------------------------------------- pendientes críticos
# Score de criticidad para el conjunto pending (lo que NVD aún NO ha publicado).
# Determinista y explicable — combina las señales que YA hay en BD:
#   in_kev          +50  (explotado en real: la señal de máxima prioridad)
#   has_public_poc  +20  (hay PoC/exploit circulando)
#   severidad       0-40 (CVSS base autoritativo * 4 si lo hay; si no, mapa del
#                         severity_hint del enrichment)
#   tier fuente      1-15 (min(tier) de sus fuentes: tier 1 avisa más pronto)
# Rango ~0-125. No se inventa gravedad: si no hay CVSS ni severity_hint, esa
# componente es 0 (el CVE pendiente puede no tener aún datos de severidad).
_CRIT_SEVERITY_SQL = (
    "COALESCE(cv.bs * 4.0, CASE lower(p.severity_hint)"
    " WHEN 'critical' THEN 40 WHEN 'high' THEN 28 WHEN 'medium' THEN 14"
    " WHEN 'low' THEN 4 ELSE 0 END)"
)
_CRIT_TIER_SQL = ("CASE tr.mt WHEN 1 THEN 15 WHEN 2 THEN 10 WHEN 3 THEN 6"
                  " WHEN 4 THEN 3 ELSE 1 END")
_CRIT_SCORE_SQL = (
    "(CASE WHEN p.in_kev THEN 50 ELSE 0 END)"
    " + (CASE WHEN p.has_public_poc THEN 20 ELSE 0 END)"
    " + " + _CRIT_SEVERITY_SQL + " + " + _CRIT_TIER_SQL
)


def pending_critical(session: Session, top: int = 50, maturity: str = "all",
                     kind: str | None = None, tech: str | None = None,
                     ) -> dict[str, Any]:
    """Pendientes ordenados por criticidad (en TODAS las categorías de madurez).

    Evalúa el predicado pending UNA vez (CTE MATERIALIZED) y le une, por lotes,
    el CVSS máximo (cvss_scores) y el tier mínimo de sus fuentes; ordena por el
    score. Devuelve el top-N con el DESGLOSE del score (para justificar el orden).
    """
    extra, params = "", {}
    if maturity != "all":
        if maturity not in MATURITY_SQL:
            raise ValueError(f"maturity inválida: {maturity!r}")
        extra += " AND " + MATURITY_SQL[maturity]
    if kind or tech:
        frag, fparams = _pending_filter(kind, tech)
        if frag:
            extra += " AND " + frag
            params.update(fparams)
    params["top"] = top
    rows = session.execute(text(f"""
        WITH sig AS MATERIALIZED (
          -- "Crítico" exige AL MENOS una señal de gravedad/explotación: sin
          -- ninguna, el score sería solo el del tier (<=15) y nunca alcanzaría el
          -- top. Construir primero el conjunto CON señal (índices: in_kev, cvss;
          -- seq scan barato de candidates para poc/severity) hace que el chequeo
          -- pending sobre affected_products sea por-candidato -> la query baja de
          -- ~14 s a ~2 s SIN materializar todo el conjunto pending (238k).
          SELECT id FROM candidates WHERE merged_into IS NULL AND in_kev
          UNION SELECT id FROM candidates WHERE merged_into IS NULL AND has_public_poc
          UNION SELECT id FROM candidates WHERE merged_into IS NULL AND severity_hint IS NOT NULL
          UNION SELECT candidate_id FROM cvss_scores
        ),
        pend AS MATERIALIZED (
          SELECT c.id, c.cve_id, c.in_kev, c.has_public_poc, c.severity_hint,
                 c.vuln_type, c.first_seen_at, c.days_ahead_vs_nvd_present AS days_ahead
          FROM sig JOIN candidates c ON c.id = sig.id
          WHERE {PENDING_WHERE_SQL}{extra}
        )
        SELECT p.id, p.cve_id, p.in_kev, p.has_public_poc, p.severity_hint,
               p.vuln_type, p.first_seen_at, p.days_ahead,
               cv.bs AS cvss, tr.mt AS min_tier, ap.product,
               (CASE WHEN p.cve_id IS NULL THEN 'pre_cve'
                     WHEN NOT EXISTS (SELECT 1 FROM published_cves pp WHERE pp.id=p.cve_id)
                        THEN 'cve_prereserved'
                     ELSE 'cve_reserved' END) AS maturity,
               round(({_CRIT_SCORE_SQL})::numeric, 1) AS score
        FROM pend p
        -- LATERAL correlado (no agregación de tablas enteras): pend es pequeño,
        -- así que un lookup por candidato vía índice es mucho más barato que un
        -- GROUP BY sobre los 1.5M de mentions / todos los cvss_scores.
        LEFT JOIN LATERAL (SELECT max(base_score) AS bs FROM cvss_scores v
                   WHERE v.candidate_id = p.id) cv ON true
        LEFT JOIN LATERAL (SELECT min(s.tier) AS mt FROM mentions m
                   JOIN sources s ON s.id=m.source_id WHERE m.candidate_id=p.id) tr ON true
        LEFT JOIN LATERAL (SELECT product FROM affected_products a
                   WHERE a.candidate_id=p.id AND (a.kind IS NULL OR a.kind<>'malware')
                   ORDER BY a.product LIMIT 1) ap ON true
        ORDER BY score DESC, p.first_seen_at DESC NULLS LAST
        LIMIT :top
    """), params).mappings().all()
    return {
        "maturity": maturity, "top": top,
        "rows": [{
            "id": str(r["id"]), "cve_id": r["cve_id"], "product": r["product"],
            "maturity": r["maturity"], "score": float(r["score"]),
            "in_kev": r["in_kev"], "has_public_poc": r["has_public_poc"],
            "cvss": float(r["cvss"]) if r["cvss"] is not None else None,
            "severity_hint": r["severity_hint"], "vuln_type": r["vuln_type"],
            "min_tier": r["min_tier"], "first_seen_at": r["first_seen_at"],
            "days_ahead": r["days_ahead"],
        } for r in rows],
    }


# ------------------------------------------------ desglose pending (eco/madurez)
def pending_breakdown(session: Session) -> dict[str, Any]:
    """Distribución del conjunto pending por ECOSISTEMA y embudo de MADUREZ, en
    una sola evaluación del predicado (CTE MATERIALIZED + UNION ALL)."""
    rows = session.execute(text(f"""
        WITH pend AS MATERIALIZED (
          SELECT c.id, c.cve_id FROM candidates c WHERE {PENDING_WHERE_SQL}
        )
        SELECT 'eco' AS dim, COALESCE(a.ecosystem, '(sin ecosistema)') AS key,
               count(DISTINCT p.id) AS n
        FROM pend p JOIN affected_products a ON a.candidate_id=p.id
          AND (a.kind IS NULL OR a.kind<>'malware')
        GROUP BY key
        UNION ALL
        SELECT 'maturity', 'pre_cve', count(*) FROM pend WHERE cve_id IS NULL
        UNION ALL
        SELECT 'maturity', 'cve_prereserved', count(*) FROM pend p
          WHERE cve_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM published_cves pp WHERE pp.id=p.cve_id)
        UNION ALL
        SELECT 'maturity', 'cve_reserved', count(*) FROM pend p
          WHERE cve_id IS NOT NULL
            AND EXISTS (SELECT 1 FROM published_cves pp WHERE pp.id=p.cve_id)
    """)).mappings().all()
    eco = sorted(({"ecosystem": r["key"], "pending": int(r["n"])}
                  for r in rows if r["dim"] == "eco"),
                 key=lambda x: x["pending"], reverse=True)
    maturity = {r["key"]: int(r["n"]) for r in rows if r["dim"] == "maturity"}
    return {"by_ecosystem": eco, "by_maturity": maturity}
