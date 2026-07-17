"""Consultas de solo lectura para la API (y reutilizables por la CLI).

Devuelven estructuras JSON-friendly (dicts/listas). El concepto central:
- "published"      = CVEs oficialmente publicados (published_cves, state=PUBLISHED).
- "pre_published"  = candidates SIN CVE oficial (pre-CVE o cve_id no publicado),
                     por su primera detección (first_seen_at).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

import datetime as _dt

# Allowlist de granularidad -> (unidad date_trunc, formato to_char).
_GRAN = {"month": ("month", "YYYY-MM"), "year": ("year", "YYYY")}


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
    """Fragmento SQL + params para restringir candidates pendientes por kind/tecnología."""
    clauses = []
    params: dict[str, Any] = {}
    if kind and kind != "all":
        clauses.append("ap.kind = :kind")
        params["kind"] = kind
    if tech:
        clauses.append("ap.product ILIKE :tech")
        params["tech"] = f"%{tech}%"
    if clauses:
        frag = (" AND EXISTS (SELECT 1 FROM affected_products ap "
                "WHERE ap.candidate_id = c.id AND " + " AND ".join(clauses) + ")")
        return frag, params
    return "", params


def trend_series(session: Session, granularity: str = "month", months: int = 12,
                 kind: str | None = None, tech: str | None = None) -> list[dict[str, Any]]:
    """Serie temporal: publicados vs pre-publicados por periodo (mes/año)."""
    unit, fmt = _GRAN.get(granularity, _GRAN["month"])
    cutoff = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=30 * max(1, months))

    pub = session.execute(text(f"""
        SELECT to_char(date_trunc('{unit}', cvelist_published_at), '{fmt}') AS period,
               count(*) AS n
        FROM published_cves
        WHERE state='PUBLISHED' AND cvelist_published_at >= :cutoff
        GROUP BY 1
    """), {"cutoff": cutoff}).all()

    frag, params = _pending_filter(kind, tech)
    params["cutoff"] = cutoff
    pre = session.execute(text(f"""
        WITH pending AS (
          SELECT c.id, c.first_seen_at
          FROM candidates c
          WHERE c.merged_into IS NULL
            AND ( c.cve_id IS NULL OR NOT EXISTS (
                  SELECT 1 FROM published_cves p
                  WHERE p.id=c.cve_id AND p.state='PUBLISHED') )
            {frag}
            AND c.first_seen_at >= :cutoff
        )
        SELECT to_char(date_trunc('{unit}', first_seen_at), '{fmt}') AS period,
               count(DISTINCT id) AS n
        FROM pending GROUP BY 1
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
                granularity: str = "month") -> dict[str, Any]:
    """Ranking de software con más vulns pendientes + desglose por kind."""
    extra = ""
    params: dict[str, Any] = {}
    if period:
        bounds = _period_bounds(period, granularity)
        if bounds:
            extra = " AND c.first_seen_at >= :pstart AND c.first_seen_at < :pend"
            params["pstart"], params["pend"] = bounds
    rows = session.execute(text(f"""
        SELECT c.id, a.product, a.kind
        FROM candidates c
        LEFT JOIN affected_products a ON a.candidate_id = c.id
        WHERE c.merged_into IS NULL
          AND ( c.cve_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM published_cves p WHERE p.id=c.cve_id AND p.state='PUBLISHED') )
          {extra}
    """), params).all()
    from collections import Counter
    cands: dict = {}
    for cand, product, k in rows:
        cands.setdefault(cand, set())
        if product:
            cands[cand].add((product, k))
    by_kind: Counter = Counter()
    counter: Counter = Counter()
    for prods in cands.values():
        for k in {kk for _, kk in prods}:
            by_kind[k] += 1
        for product, k in prods:
            if (kind == "all" or k == kind) and (not tech or tech.lower() in product.lower()):
                counter[product] += 1
    return {
        "total": len(cands),
        "by_kind": dict(by_kind),
        "kind": kind,
        "top": [{"software": s, "pending": n} for s, n in counter.most_common(top)],
    }


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
        where.append("( c.cve_id IS NULL OR NOT EXISTS (SELECT 1 FROM published_cves p "
                     "WHERE p.id=c.cve_id AND p.state='PUBLISHED') )")
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
            where.append(frag.lstrip(" AND "))
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
        text("SELECT id FROM candidates WHERE cve_id=:k AND merged_into IS NULL LIMIT 1"),
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
    params = {"eco": ecosystem, "name": name, "since": f"{months} months"}
    cands = session.execute(text("""
        SELECT DISTINCT c.id, c.cve_id, c.first_seen_at, c.in_kev,
               ( c.cve_id IS NULL OR NOT EXISTS (SELECT 1 FROM published_cves p
                 WHERE p.id=c.cve_id AND p.state='PUBLISHED') ) AS pending
        FROM candidates c JOIN affected_products a ON a.candidate_id=c.id
        WHERE c.merged_into IS NULL AND a.product ILIKE :name
          AND ( :eco='' OR a.ecosystem ILIKE :eco )
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
