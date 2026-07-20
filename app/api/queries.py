"""Consultas de solo lectura para la API (y reutilizadas por la CLI).

Devuelven estructuras JSON-friendly (dicts/listas). El concepto central:
- "published"      = CVEs oficialmente publicados (published_cves, state=PUBLISHED).
- "pre_published"  = pendientes ("pending"): CVEs identificados en otras fuentes
                     que NVD aún no ha publicado, por su primera detección
                     (first_seen_at). Ver PENDING_WHERE_SQL.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

import datetime as _dt

# Allowlist de granularidad -> (unidad date_trunc, formato to_char).
_GRAN = {"month": ("month", "YYYY-MM"), "year": ("year", "YYYY")}

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
# La CLI (app/cli.py) reutiliza estas funciones: NO dupliques este fragmento.
_NVD_SILENT_SQL = (
    "( c.cve_id IS NULL OR NOT EXISTS (SELECT 1 FROM published_cves p"
    " WHERE p.id = c.cve_id"
    " AND (p.nvd_published_at IS NOT NULL OR p.state = 'REJECTED')) )"
)
_PENDING_CORE_SQL = (
    _NVD_SILENT_SQL
    + " AND EXISTS (SELECT 1 FROM affected_products ap0"
    " WHERE ap0.candidate_id = c.id"
    " AND (ap0.kind IS NULL OR ap0.kind <> 'malware'))"
    " AND NOT EXISTS (SELECT 1 FROM affected_products apm"
    " WHERE apm.candidate_id = c.id AND apm.kind = 'malware')"
)
# withdrawn IS NOT TRUE: advisories retirados o "Duplicate Advisory" de GHSA
# no son pendientes reales.
PENDING_WHERE_SQL = (
    "c.merged_into IS NULL AND c.status <> 'rejected'"
    " AND c.withdrawn IS NOT TRUE AND " + _PENDING_CORE_SQL
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

# Variante booleana (sin exigir producto) para etiquetar filas que ya vienen
# unidas a affected_products, p.ej. en software_detail.
PENDING_EXPR_SQL = "( " + _NVD_SILENT_SQL + " )"


def _like_pattern(term: str, *, contains: bool = True) -> str:
    """Escapa los comodines LIKE (%, _) y la barra invertida del input del
    usuario; usar siempre junto a ESCAPE '\\' en la query."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%" if contains else escaped


def _period_bounds(period: str, granularity: str) -> tuple[_dt.datetime, _dt.datetime] | None:
    """Convierte 'YYYY-MM'/'YYYY' en [inicio, fin) para filtrar por periodo."""
    try:
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
                 kind: str | None = None, tech: str | None = None) -> list[dict[str, Any]]:
    """Serie temporal: publicados vs pendientes (pre-publicados) por periodo.

    El cutoff se alinea al inicio del periodo (date_trunc) para que el bucket
    más antiguo sea COMPLETO; con `now() - N*30 días` quedaba cortado a mitad.
    """
    unit, fmt = _GRAN.get(granularity, _GRAN["month"])
    months = max(1, months)

    pub = session.execute(text(f"""
        SELECT to_char(date_trunc('{unit}', cvelist_published_at), '{fmt}') AS period,
               count(*) AS n
        FROM published_cves
        WHERE state='PUBLISHED'
          AND cvelist_published_at >= date_trunc('{unit}', now()) - make_interval(months => :months)
        GROUP BY 1
    """), {"months": months}).all()

    frag, params = _pending_filter(kind, tech)
    params["months"] = months
    and_frag = f"AND {frag}" if frag else ""
    pre = session.execute(text(f"""
        SELECT to_char(date_trunc('{unit}', c.first_seen_at), '{fmt}') AS period,
               count(DISTINCT c.id) AS n
        FROM candidates c
        WHERE {PENDING_WHERE_SQL}
          {and_frag}
          AND c.first_seen_at >= date_trunc('{unit}', now()) - make_interval(months => :months)
        GROUP BY 1
    """), params).all()

    merged: dict[str, dict[str, Any]] = {}
    for period, n in pub:
        merged.setdefault(period, {"period": period, "published": 0, "pre_published": 0})
        merged[period]["published"] = int(n)
    for period, n in pre:
        merged.setdefault(period, {"period": period, "published": 0, "pre_published": 0})
        merged[period]["pre_published"] = int(n)
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
            extra = " AND c.first_seen_at >= :pstart AND c.first_seen_at < :pend"
            params["pstart"], params["pend"] = bounds

    total = session.execute(text(
        f"SELECT count(*) FROM candidates c WHERE {PENDING_WHERE_SQL}{extra}"
    ), params).scalar_one()

    by_kind = session.execute(text(f"""
        SELECT a.kind, count(DISTINCT c.id) AS n
        FROM candidates c JOIN affected_products a ON a.candidate_id = c.id
        WHERE {PENDING_WHERE_SQL}{extra}
        GROUP BY a.kind
    """), params).all()

    by_maturity = {
        label: int(session.execute(text(
            f"SELECT count(*) FROM candidates c WHERE {PENDING_WHERE_SQL}{extra}"
            f" AND {cond}"), params).scalar_one())
        for label, cond in MATURITY_SQL.items()
    } if maturity == "all" else None

    filt = ""
    if kind != "all":
        filt = " AND a.kind = :kind"
        params["kind"] = kind
    if tech:
        filt += " AND a.product ILIKE :tech ESCAPE '\\'"
        params["tech"] = _like_pattern(tech)
    params["top"] = top
    rows = session.execute(text(f"""
        SELECT a.product, count(DISTINCT c.id) AS pending
        FROM candidates c JOIN affected_products a ON a.candidate_id = c.id
        WHERE {PENDING_WHERE_SQL}{extra}{filt}
        GROUP BY a.product
        ORDER BY pending DESC, a.product
        LIMIT :top
    """), params).all()
    out = {
        "total": int(total),
        "by_kind": {k: int(n) for k, n in by_kind if k is not None},
        "kind": kind,
        "maturity": maturity,
        "top": [{"software": s, "pending": int(n)} for s, n in rows],
    }
    if by_maturity is not None:
        out["by_maturity"] = by_maturity
    return out


def emerging_list(session: Session, *, since_days: int | None = None, source: str | None = None,
                  tier: int | None = None, kind: str | None = None, in_kev: bool | None = None,
                  tech: str | None = None, pending_only: bool = False,
                  period: str | None = None, granularity: str = "month",
                  page: int = 1, page_size: int = 50) -> dict[str, Any]:
    """Tabla de candidates con filtros y paginación."""
    where = ["c.merged_into IS NULL"]
    params: dict[str, Any] = {}
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
        # Definición canónica de pending (merged_into ya está filtrado arriba).
        where.append(_PENDING_CORE_SQL)
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
               c.severity_hint, c.last_seen_at,
               (SELECT base_score FROM cvss_scores v WHERE v.candidate_id=c.id
                  ORDER BY base_score DESC NULLS LAST LIMIT 1) AS cvss,
               (SELECT string_agg(DISTINCT s.name, ',') FROM mentions m
                  JOIN sources s ON s.id=m.source_id WHERE m.candidate_id=c.id) AS sources
        FROM candidates c WHERE {where_sql}
        ORDER BY c.last_seen_at DESC LIMIT :limit OFFSET :offset
    """), params).mappings().all()
    return {"total": int(total), "page": page, "page_size": page_size,
            "rows": [dict(r) for r in rows]}


def candidate_detail(session: Session, key: str) -> dict[str, Any] | None:
    """Deepdive de una nota/candidate: ids, cvss, epss, afectados, refs, timeline."""
    cid = session.execute(
        text("SELECT id FROM candidates WHERE cve_id=:k AND merged_into IS NULL "
             "ORDER BY first_seen_at LIMIT 1"),
        {"k": key.upper()}).scalar_one_or_none()
    if cid is None:
        try:
            cid = uuid.UUID(key)
        except ValueError:
            return None
    c = session.execute(text("SELECT * FROM candidates WHERE id=:id"),
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
                    granularity: str = "month", months: int = 24) -> dict[str, Any]:
    """Deepdive por tecnología: publicados vs pendientes de un paquete + su serie."""
    unit, fmt = _GRAN.get(granularity, _GRAN["month"])
    params = {
        # Match exacto case-insensitive: se escapan los comodines del input.
        "eco": _like_pattern(ecosystem, contains=False) if ecosystem else "",
        "name": _like_pattern(name, contains=False),
        "months": max(1, months),
    }
    cands = session.execute(text(f"""
        SELECT DISTINCT c.id, c.cve_id, c.first_seen_at, c.in_kev,
               {PENDING_EXPR_SQL} AS pending
        FROM candidates c JOIN affected_products a ON a.candidate_id=c.id
        WHERE c.merged_into IS NULL AND a.product ILIKE :name ESCAPE '\\'
          AND ( :eco='' OR a.ecosystem ILIKE :eco ESCAPE '\\' )
          AND c.first_seen_at >= date_trunc('{unit}', now()) - make_interval(months => :months)
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


def source_stats(session: Session) -> list[dict[str, Any]]:
    """Media de días de ventaja por fuente (deduplicada, sin fusionados)."""
    rows = session.execute(text("""
        SELECT source, round(avg(days_ahead)::numeric, 1) AS avg_days, count(*) AS candidates
        FROM (
          SELECT DISTINCT s.name AS source, c.id, c.days_ahead_vs_nvd_present AS days_ahead
          FROM sources s JOIN mentions m ON m.source_id=s.id
          JOIN candidates c ON c.id=m.candidate_id
          WHERE c.days_ahead_vs_nvd_present IS NOT NULL AND c.merged_into IS NULL
        ) t GROUP BY source ORDER BY avg_days DESC
    """)).mappings().all()
    return [dict(r) for r in rows]
