"""CLI de operación y consulta de CVERadar (typer).

Ejemplos:
  cveradar db init
  cveradar sources sync
  cveradar sources list
  cveradar sources run osv
  cveradar baseline sync
  cveradar emerging list --since 24h --tier 1 --min-mentions 2
  cveradar cve show CVE-2026-12345
  cveradar enrich CVE-2026-12345
  cveradar stats
"""

from __future__ import annotations

import asyncio
import csv
import json
import re
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select, text

from app.core.db import get_session, session_scope
from app.core.logging import configure_logging
from app.core.models import (
    Candidate,
    CVSSScore,
    EPSSScore,
    Identifier,
    Mention,
    Source,
)

app = typer.Typer(help="CVERadar — radar temprano de vulnerabilidades", no_args_is_help=True)
sources_app = typer.Typer(help="Gestión de fuentes", no_args_is_help=True)
baseline_app = typer.Typer(help="Sincronización del estado canónico", no_args_is_help=True)
db_app = typer.Typer(help="Base de datos / migraciones", no_args_is_help=True)
app.add_typer(sources_app, name="sources")
app.add_typer(baseline_app, name="baseline")
app.add_typer(db_app, name="db")

console = Console()

# Formatos de salida soportados por los comandos de consulta.
Fmt = str  # "table" | "json" | "csv"


def _emit(fmt: str, columns: list[str], rows: list[tuple],
          meta: dict | None = None, title: str | None = None) -> None:
    """Emite filas como tabla (rich), JSON o CSV. `meta` es un resumen opcional
    (se incluye en JSON; en tabla se imprime al pie; en CSV se omite para no
    contaminar la salida)."""
    if fmt == "json":
        payload: dict = {"data": [dict(zip(columns, r, strict=False)) for r in rows]}
        if meta:
            payload["meta"] = meta
        typer.echo(json.dumps(payload, default=str, ensure_ascii=False, indent=2))
    elif fmt == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(columns)
        for r in rows:
            writer.writerow(["" if v is None else v for v in r])
    else:
        table = Table(*columns, title=title)
        for r in rows:
            table.add_row(*["" if v is None else str(v) for v in r])
        console.print(table)
        if meta:
            console.print("  ".join(f"[dim]{k}={v}[/dim]" for k, v in meta.items()))


def _parse_since(s: str | None) -> datetime | None:
    if not s:
        return None
    m = re.fullmatch(r"(\d+)\s*([hdw])", s.strip().lower())
    if not m:
        raise typer.BadParameter("usa formato como 24h, 7d, 2w")
    n, unit = int(m.group(1)), m.group(2)
    delta = {"h": timedelta(hours=n), "d": timedelta(days=n), "w": timedelta(weeks=n)}[unit]
    return datetime.now(UTC) - delta


# --------------------------------------------------------------------- db
@db_app.command("init")
def db_init() -> None:
    """Aplica las migraciones Alembic (alembic upgrade head)."""
    res = subprocess.run(["alembic", "upgrade", "head"], check=False)
    raise typer.Exit(res.returncode)


# ----------------------------------------------------------------- sources
@sources_app.command("sync")
def sources_sync() -> None:
    """Registra los fetchers del código en la tabla sources."""
    from app.sources.runner import sync_registry_to_db

    sync_registry_to_db()
    console.print("[green]Fuentes sincronizadas.[/green]")


@sources_app.command("list")
def sources_list() -> None:
    """Lista las fuentes registradas y su estado."""
    with get_session() as session:
        rows = session.execute(select(Source).order_by(Source.tier, Source.name)).scalars().all()
    table = Table("name", "tier", "method", "enabled", "cadence", "last_success", "last_error")
    for s in rows:
        table.add_row(
            s.name, str(s.tier), s.method, "✓" if s.enabled else "✗",
            f"{s.cadence_seconds}s",
            s.last_success_at.isoformat() if s.last_success_at else "-",
            (s.last_error or "")[:40],
        )
    console.print(table)


@sources_app.command("enable")
def sources_enable(name: str) -> None:
    """Activa una fuente."""
    _set_enabled(name, True)


@sources_app.command("disable")
def sources_disable(name: str) -> None:
    """Desactiva una fuente."""
    _set_enabled(name, False)


def _set_enabled(name: str, enabled: bool) -> None:
    with session_scope() as session:
        row = session.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
        if row is None:
            console.print(f"[red]fuente desconocida: {name}[/red]")
            raise typer.Exit(1)
        row.enabled = enabled
    console.print(f"[green]{name} {'activada' if enabled else 'desactivada'}.[/green]")


@sources_app.command("run")
def sources_run(name: str) -> None:
    """Ejecuta un fetcher una vez e imprime el resultado."""
    from app.sources.runner import run_source

    stats = asyncio.run(run_source(name))
    console.print(stats)


# ---------------------------------------------------------------- baseline
@baseline_app.command("sync")
def baseline_sync(
    nvd_hours: int = typer.Option(3, help="ventana horas del delta NVD"),
    full_cvelist: bool = typer.Option(False, help="reprocesar todo cvelistV5"),
) -> None:
    """Fuerza una sincronización inmediata de cvelistV5 + NVD + EPSS."""
    from app.baseline.service import run_baseline_once

    console.print(run_baseline_once(nvd_hours=nvd_hours, force_full_cvelist=full_cvelist))


# ---------------------------------------------------------------- emerging
@app.command("emerging")
def emerging(
    action: str = typer.Argument("list"),
    since: str | None = typer.Option(None, help="p.ej. 24h, 7d"),
    source: str | None = typer.Option(None, help="filtra por nombre de fuente"),
    tier: int | None = typer.Option(None, help="filtra por tier de fuente"),
    min_mentions: int = typer.Option(1, help="mínimo de menciones"),
    limit: int = typer.Option(50),
    fmt: str = typer.Option("table", "--format", "-f", help="table | json | csv"),
) -> None:
    """Lista candidates emergentes con filtros."""
    if action != "list":
        raise typer.BadParameter("solo 'list' está soportado")
    since_dt = _parse_since(since)
    with get_session() as session:
        stmt = select(Candidate).where(
            Candidate.merged_into.is_(None),
            Candidate.mention_count >= min_mentions,
        )
        if since_dt is not None:
            stmt = stmt.where(Candidate.last_seen_at >= since_dt)
        if source or tier is not None:
            sub = select(Mention.candidate_id).join(Source, Mention.source_id == Source.id)
            if source:
                sub = sub.where(Source.name == source)
            if tier is not None:
                sub = sub.where(Source.tier == tier)
            stmt = stmt.where(Candidate.id.in_(sub))
        stmt = stmt.order_by(Candidate.last_seen_at.desc()).limit(limit)
        rows = session.execute(stmt).scalars().all()

        data = []
        for c in rows:
            score = session.execute(
                select(CVSSScore.base_score, CVSSScore.version)
                .where(CVSSScore.candidate_id == c.id)
                .order_by(CVSSScore.base_score.desc().nullslast()).limit(1)
            ).first()
            sev = (f"{score[0]} (v{score[1]})" if score and score[0] is not None
                   else (c.severity_hint or None))
            data.append((
                c.cve_id or str(c.id)[:8], c.status, c.vuln_type, sev,
                c.mention_count, c.source_count, c.days_ahead_vs_nvd_present,
                c.last_seen_at.strftime("%Y-%m-%d %H:%M") if c.last_seen_at else None,
            ))
    _emit(fmt, ["cve_id", "status", "vuln", "sev", "mentions", "sources",
                "days_ahead", "last_seen"], data)


# --------------------------------------------------------------------- cve
@app.command("cve")
def cve(action: str = typer.Argument("show"), cve_id: str = typer.Argument(...)) -> None:
    """Muestra el timeline y el enriquecimiento de un CVE (o id de candidate)."""
    if action != "show":
        raise typer.BadParameter("solo 'show' está soportado")
    with get_session() as session:
        candidate = _find_candidate(session, cve_id)
        if candidate is None:
            console.print(f"[red]no encontrado: {cve_id}[/red]")
            raise typer.Exit(1)
        console.print(f"[bold]{candidate.cve_id or candidate.id}[/bold]  status={candidate.status}")
        console.print(
            f"  vuln={candidate.vuln_type} vector={candidate.attack_vector} "
            f"poc={candidate.has_public_poc} hint={candidate.severity_hint}"
        )
        console.print(
            f"  days_ahead present={candidate.days_ahead_vs_nvd_present} "
            f"analyzed={candidate.days_ahead_vs_nvd_analyzed}"
        )
        ids = session.execute(
            select(Identifier.scheme, Identifier.value)
            .where(Identifier.candidate_id == candidate.id)
        ).all()
        console.print("  ids: " + ", ".join(f"{s}:{v}" for s, v in ids))

        cvss = session.execute(
            select(CVSSScore).where(CVSSScore.candidate_id == candidate.id)
        ).scalars().all()
        if cvss:
            t = Table("version", "score", "sev", "provenance", "source")
            for c in cvss:
                t.add_row(c.version, str(c.base_score), c.base_severity or "-",
                          c.provenance, c.source)
            console.print(t)

        if candidate.cve_id:
            epss = session.execute(
                select(EPSSScore).where(EPSSScore.cve_id == candidate.cve_id)
                .order_by(EPSSScore.scored_date.desc()).limit(1)
            ).scalar_one_or_none()
            if epss:
                console.print(f"  EPSS: {epss.score} (pct {epss.percentile}) @ {epss.scored_date}")

        console.print("[bold]Timeline:[/bold]")
        mentions = session.execute(
            select(Mention, Source.name).join(Source, Mention.source_id == Source.id)
            .where(Mention.candidate_id == candidate.id).order_by(Mention.seen_at)
        ).all()
        tl = Table("seen_at", "source", "title", "url")
        for m, sname in mentions:
            tl.add_row(m.seen_at.strftime("%Y-%m-%d %H:%M") if m.seen_at else "-",
                       sname, (m.title or "")[:50], (m.url or "")[:50])
        console.print(tl)


def _find_candidate(session, key: str) -> Candidate | None:
    c = session.execute(
        select(Candidate).where(Candidate.cve_id == key.upper())
    ).scalar_one_or_none()
    if c is not None:
        return c
    try:
        cid = uuid.UUID(key)
    except ValueError:
        return None
    return session.get(Candidate, cid)


# ------------------------------------------------------------------- enrich
@app.command("enrich")
def enrich_cmd(cve_id: str = typer.Argument(...)) -> None:
    """Enriquece un candidate (LLM + CVSS) por CVE o id."""
    from app.enrichment.service import enrich_candidate

    with session_scope() as session:
        candidate = _find_candidate(session, cve_id)
        if candidate is None:
            console.print(f"[red]no encontrado: {cve_id}[/red]")
            raise typer.Exit(1)
        ok = asyncio.run(_enrich_wrap(candidate.id))
    console.print("[green]enriquecido[/green]" if ok else "[yellow]sin datos[/yellow]")


async def _enrich_wrap(cid: uuid.UUID) -> bool:
    from app.enrichment.service import enrich_candidate

    with session_scope() as session:
        return await enrich_candidate(session, cid)


# ------------------------------------------------------------------- stats
@app.command("stats")
def stats(
    fmt: str = typer.Option("table", "--format", "-f", help="table | json | csv"),
) -> None:
    """Media de días de ventaja por fuente y tasa de promoción."""
    with get_session() as session:
        total = session.execute(
            select(func.count()).select_from(Candidate)
            .where(Candidate.merged_into.is_(None))
        ).scalar_one()
        promoted = session.execute(
            select(func.count()).select_from(Candidate)
            .where(Candidate.status == "published", Candidate.merged_into.is_(None))
        ).scalar_one()
        # AVG deduplicada por candidate (el join fuente->mención da N filas/candidate;
        # promediar directamente sesga la media por nº de menciones). Excluye fusionados.
        rows = session.execute(text("""
            SELECT source, avg(days_ahead) AS avg_days, count(*) AS candidates FROM (
              SELECT DISTINCT s.name AS source, c.id, c.days_ahead_vs_nvd_present AS days_ahead
              FROM sources s
              JOIN mentions m ON m.source_id = s.id
              JOIN candidates c ON c.id = m.candidate_id
              WHERE c.days_ahead_vs_nvd_present IS NOT NULL AND c.merged_into IS NULL
            ) t GROUP BY source ORDER BY avg_days DESC
        """)).all()
    data = [(name, round(float(avg), 1) if avg is not None else None, cnt)
            for name, avg, cnt in rows]
    meta = {"candidates": total, "promoted": promoted,
            "promotion_rate_pct": round(promoted / total * 100, 1) if total else 0}
    _emit(fmt, ["source", "avg_days_ahead", "candidates"], data, meta=meta,
          title="Días de ventaja por fuente (vs NVD present)")


# ----------------------------------------------------- pending / trend
# Lee de affected_products (persistido). Una fila por (candidate, producto);
# candidates sin producto salen con product/kind NULL.
_PENDING_AP_SQL = text("""
SELECT c.id, c.first_seen_at, a.product, a.kind
FROM candidates c
LEFT JOIN affected_products a ON a.candidate_id = c.id
WHERE c.merged_into IS NULL
  AND ( c.cve_id IS NULL
     OR NOT EXISTS (SELECT 1 FROM published_cves p
                    WHERE p.id = c.cve_id AND p.state = 'PUBLISHED') )
""")


def _load_pending(session) -> list[tuple]:
    """[(candidate_id, first_seen, product, kind)] para candidates sin CVE oficial."""
    return list(session.execute(_PENDING_AP_SQL))


@app.command("pending")
def pending(
    top: int = typer.Option(20, help="nº de software en el ranking"),
    kind: str = typer.Option("product", help="product | distro | malware | all"),
    fmt: str = typer.Option("table", "--format", "-f", help="table | json | csv"),
) -> None:
    """CVEs identificados asociados a software SIN publicación oficial (NVD/MITRE),
    y ranking del software con más pendientes. Canonicaliza el ecosistema y separa
    productos reales de advisories de distro/malware."""
    from collections import Counter

    with get_session() as session:
        rows = _load_pending(session)

    cands: dict = {}
    for cand, _fs, product, k in rows:
        prods = cands.setdefault(cand, set())
        if product:
            prods.add((product, k))
    total = len(cands)
    with_sw = sum(1 for prods in cands.values() if prods)
    by_kind: Counter = Counter()
    prodcount: Counter = Counter()
    for prods in cands.values():
        for k in {kk for _, kk in prods}:
            by_kind[k] += 1
        for product, k in prods:
            if kind == "all" or k == kind:
                prodcount[product] += 1
    data = list(prodcount.most_common(top))
    meta = {
        "total": total, "con_software": with_sw, "product": by_kind["product"],
        "distro": by_kind["distro"], "malware": by_kind["malware"], "kind": kind,
    }
    _emit(fmt, ["software", "cves_pendientes"], data, meta=meta,
          title=f"Top software (kind={kind})")


@app.command("trend")
def trend(
    kind: str = typer.Option("all", help="product | distro | malware | all"),
    granularity: str = typer.Option("month", help="month | year"),
    months: int = typer.Option(12, help="ventana de meses hacia atrás (p.ej. 6, 12)"),
    fmt: str = typer.Option("table", "--format", "-f", help="table | json | csv"),
) -> None:
    """Serie temporal de vulnerabilidades pendientes por mes/año, por fecha de
    PRIMERA DETECCIÓN del radar (candidate.first_seen_at ≈ fecha de la señal más
    temprana: commit, publicación OSV, dateAdded KEV). Ventana configurable
    (--months). Sirve para ver crecimiento reciente / efecto palo de hockey."""
    from collections import Counter

    date_fmt = "%Y-%m" if granularity == "month" else "%Y"
    cutoff = datetime.now(UTC) - timedelta(days=30 * months) if months > 0 else None
    with get_session() as session:
        rows = _load_pending(session)
    cand_fs: dict = {}
    cand_kinds: dict = {}
    for cand, first_seen, _product, k in rows:
        cand_fs[cand] = first_seen
        if k:
            cand_kinds.setdefault(cand, set()).add(k)
    buckets: Counter = Counter()
    for cand, first_seen in cand_fs.items():
        if first_seen is None:
            continue
        if kind != "all" and kind not in cand_kinds.get(cand, set()):
            continue
        if cutoff is not None and first_seen < cutoff:
            continue
        buckets[first_seen.strftime(date_fmt)] += 1
    if not buckets:
        console.print("[yellow]sin datos temporales[/yellow]")
        return
    periods = sorted(buckets)
    if fmt == "table":
        peak = max(buckets.values())
        data = [(p, buckets[p], "█" * max(1, round(40 * buckets[p] / peak))) for p in periods]
        _emit("table", ["periodo", "pendientes", ""], data,
              meta={"kind": kind, "months": months}, title=f"Tendencia (kind={kind})")
    else:
        _emit(fmt, ["periodo", "pendientes"], [(p, buckets[p]) for p in periods],
              meta={"kind": kind, "months": months})


@app.command("backfill-products")
def backfill_products(
    batch: int = typer.Option(1000, help="commit cada N candidates"),
) -> None:
    """Rellena affected_products para candidates que aún no lo tienen, derivando el
    software de sus menciones (repo GHCOMMIT / paquete 'affected:' / prefijo owner/repo).
    Idempotente. OSV ya lo puebla al ingerir; esto cubre el resto de fuentes."""
    from app.ingest.affected import AffectedInput, classify_kind, persist_affected

    sql = text("""
      SELECT c.id,
        COALESCE(
          (SELECT regexp_replace(i.value,'^GHCOMMIT:(.*)@.*$','\\1')
             FROM identifiers i WHERE i.candidate_id=c.id AND i.scheme='GHCOMMIT' LIMIT 1),
          (SELECT substring(m.snippet from 'affected: (\\S+)')
             FROM mentions m WHERE m.candidate_id=c.id AND m.snippet LIKE '%affected:%' LIMIT 1),
          (SELECT substring(m.title from '^([^:]+/[^:]+):')
             FROM mentions m WHERE m.candidate_id=c.id AND m.title LIKE '%/%:%' LIMIT 1)
        ) AS software,
        EXISTS(SELECT 1 FROM identifiers i WHERE i.candidate_id=c.id
               AND i.scheme='OSV' AND i.value ILIKE 'MAL-%') AS is_malware
      FROM candidates c
      WHERE c.merged_into IS NULL
        AND NOT EXISTS (SELECT 1 FROM affected_products ap WHERE ap.candidate_id=c.id)
    """)

    def to_affected(raw: str | None, is_mal: bool) -> "AffectedInput | None":
        if not raw:
            return None
        s = raw.strip()
        kind = "malware" if is_mal else None
        if "/" in s and ":" not in s.split("/", 1)[0]:
            return AffectedInput(product=s.lower(), ecosystem="github",
                                 kind=kind or "product")
        eco, _, name = s.partition(":")
        prod = name or s
        return AffectedInput(product=prod, ecosystem=(eco if name else None),
                             kind=kind or classify_kind(eco))

    with get_session() as reader:
        targets = list(reader.execute(sql))
    n = 0
    pending_rows = []
    for cid, software, is_mal in targets:
        ai = to_affected(software, is_mal)
        if ai is not None:
            pending_rows.append((cid, ai))
    with session_scope() as session:
        for i, (cid, ai) in enumerate(pending_rows, 1):
            persist_affected(session, cid, [ai])
            n += 1
            if i % batch == 0:
                session.flush()
    console.print(f"[green]backfill: {n} candidates con affected_products[/green]")


if __name__ == "__main__":
    configure_logging()
    app()
