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
import re
import subprocess
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

        table = Table("cve/id", "status", "vuln", "sev", "mentions", "sources",
                      "days_ahead", "last_seen")
        for c in rows:
            score = session.execute(
                select(CVSSScore.base_score, CVSSScore.version)
                .where(CVSSScore.candidate_id == c.id)
                .order_by(CVSSScore.base_score.desc().nullslast()).limit(1)
            ).first()
            sev = (f"{score[0]} (v{score[1]})" if score and score[0] is not None
                   else (c.severity_hint or "-"))
            table.add_row(
                c.cve_id or str(c.id)[:8], c.status or "-", c.vuln_type or "-", sev,
                str(c.mention_count), str(c.source_count),
                str(c.days_ahead_vs_nvd_present) if c.days_ahead_vs_nvd_present is not None else "-",
                c.last_seen_at.strftime("%Y-%m-%d %H:%M") if c.last_seen_at else "-",
            )
    console.print(table)


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
def stats() -> None:
    """Media de días de ventaja por fuente, tasa de promoción y top CNAs."""
    with get_session() as session:
        total = session.execute(select(func.count()).select_from(Candidate)).scalar_one()
        promoted = session.execute(
            select(func.count()).select_from(Candidate).where(Candidate.status == "published")
        ).scalar_one()
        console.print(f"candidates={total} promovidos={promoted} "
                      f"tasa={ (promoted/total*100) if total else 0:.1f}%")

        console.print("[bold]Días de ventaja medios por fuente (vs NVD present):[/bold]")
        rows = session.execute(
            select(Source.name, func.avg(Candidate.days_ahead_vs_nvd_present),
                   func.count(func.distinct(Candidate.id)))
            .join(Mention, Mention.source_id == Source.id)
            .join(Candidate, Candidate.id == Mention.candidate_id)
            .where(Candidate.days_ahead_vs_nvd_present.is_not(None))
            .group_by(Source.name).order_by(func.avg(Candidate.days_ahead_vs_nvd_present).desc())
        ).all()
        t = Table("source", "avg_days_ahead", "candidates")
        for name, avg, cnt in rows:
            t.add_row(name, f"{float(avg):.1f}" if avg is not None else "-", str(cnt))
        console.print(t)


# ----------------------------------------------------- pending / trend
# Filas por candidate SIN CVE público oficial (pre-CVE o CVE no PUBLISHED):
# software derivado + señal de malware (OSV MAL-) + fecha real más temprana.
_PENDING_ROWS_SQL = text("""
WITH pending AS (
  SELECT c.id, c.cve_id
  FROM candidates c
  WHERE c.merged_into IS NULL
    AND ( c.cve_id IS NULL
       OR NOT EXISTS (SELECT 1 FROM published_cves p
                      WHERE p.id = c.cve_id AND p.state = 'PUBLISHED') )
)
SELECT p.id, p.cve_id,
  COALESCE(
    (SELECT regexp_replace(i.value,'^GHCOMMIT:(.*)@.*$','\\1')
       FROM identifiers i WHERE i.candidate_id=p.id AND i.scheme='GHCOMMIT' LIMIT 1),
    (SELECT substring(m.snippet from 'affected: (\\S+)')
       FROM mentions m WHERE m.candidate_id=p.id AND m.snippet LIKE '%affected:%' LIMIT 1),
    (SELECT substring(m.title from '^([^:]+/[^:]+):')
       FROM mentions m WHERE m.candidate_id=p.id AND m.title LIKE '%/%:%' LIMIT 1)
  ) AS software,
  EXISTS(SELECT 1 FROM identifiers i WHERE i.candidate_id=p.id
         AND i.scheme='OSV' AND i.value ILIKE 'MAL-%') AS is_malware,
  (SELECT min(m.seen_at) FROM mentions m WHERE m.candidate_id=p.id) AS first_seen
FROM pending p
""")

# Canonicalización de ecosistema (une pip/PyPI, rust/cargo/crates, etc.).
_ECO_ALIAS = {
    "pip": "pypi", "pypi": "pypi",
    "cargo": "crates.io", "rust": "crates.io", "crates": "crates.io", "crates.io": "crates.io",
    "go": "go", "golang": "go",
    "npm": "npm", "node": "npm",
    "maven": "maven", "nuget": "nuget",
    "gem": "rubygems", "rubygems": "rubygems",
    "composer": "packagist", "packagist": "packagist",
    "hex": "hex", "pub": "pub", "pub.dev": "pub", "hackage": "hackage",
}
_DISTRO = ("ubuntu", "debian", "alpine", "rocky", "almalinux", "suse", "opensuse",
           "red hat", "redhat", "chainguard", "wolfi", "linux", "android", "bitnami",
           "mageia", "photon", "gentoo", "oracle")


def _classify(raw: str | None, is_malware: bool) -> tuple[str | None, str]:
    """Devuelve (software_canónico, kind ∈ product|distro|malware|unknown)."""
    if not raw:
        return None, "unknown"
    if is_malware:
        return raw.strip().lower(), "malware"
    s = raw.strip()
    head = s.split("/", 1)[0]
    if "/" in s and ":" not in head:               # repo GitHub owner/repo
        return s.lower(), "product"
    eco, _, name = s.partition(":")
    ecol = eco.strip().lower()
    if any(ecol.startswith(d) for d in _DISTRO):
        return f"{ecol}:{name.split(':')[-1]}".lower().strip(":"), "distro"
    canon = _ECO_ALIAS.get(ecol, ecol)
    return f"{canon}:{name}".lower().strip(":"), "product"


def _load_pending(session) -> list[tuple[str | None, str, object]]:
    """Devuelve [(software_canónico, kind, first_seen)] por candidate pendiente."""
    out = []
    for _id, _cve, software, is_mal, first_seen in session.execute(_PENDING_ROWS_SQL):
        canon, kind = _classify(software, is_mal)
        out.append((canon, kind, first_seen))
    return out


@app.command("pending")
def pending(
    top: int = typer.Option(20, help="nº de software en el ranking"),
    kind: str = typer.Option("product", help="product | distro | malware | all"),
) -> None:
    """CVEs identificados asociados a software SIN publicación oficial (NVD/MITRE),
    y ranking del software con más pendientes. Canonicaliza el ecosistema y separa
    productos reales de advisories de distro/malware."""
    from collections import Counter

    with get_session() as session:
        rows = _load_pending(session)

    by_kind = Counter(k for _, k, _ in rows)
    console.print(
        f"[bold]CVEs sin publicación oficial: {len(rows)}[/bold]  "
        f"(product={by_kind['product']} · distro={by_kind['distro']} · "
        f"malware={by_kind['malware']} · sin-software={by_kind['unknown']})"
    )
    counter: Counter = Counter()
    for canon, k, _ in rows:
        if canon and (kind == "all" or k == kind):
            counter[canon] += 1
    table = Table("software", "cves_pendientes", title=f"Top software (kind={kind})")
    for name, n in counter.most_common(top):
        table.add_row(name, str(n))
    console.print(table)


@app.command("trend")
def trend(
    kind: str = typer.Option("all", help="product | distro | malware | all"),
    granularity: str = typer.Option("month", help="month | year"),
) -> None:
    """Serie temporal de vulnerabilidades pendientes por mes/año (fecha real más
    temprana de la señal). Sirve para ver crecimiento reciente / efecto palo de hockey."""
    from collections import Counter

    fmt = "%Y-%m" if granularity == "month" else "%Y"
    with get_session() as session:
        rows = _load_pending(session)
    buckets: Counter = Counter()
    for _canon, k, first_seen in rows:
        if first_seen is None:
            continue
        if kind != "all" and k != kind:
            continue
        buckets[first_seen.strftime(fmt)] += 1
    if not buckets:
        console.print("[yellow]sin datos temporales[/yellow]")
        return
    peak = max(buckets.values())
    table = Table("periodo", "pendientes", "", title=f"Tendencia (kind={kind})")
    for period in sorted(buckets):
        n = buckets[period]
        bar = "█" * max(1, round(40 * n / peak))
        table.add_row(period, str(n), bar)
    console.print(table)
    console.print(
        "[dim]Nota: OSV/GitHub se ingieren con ventana de ~5 meses, así que la "
        "caída en meses antiguos es en parte artefacto de la ventana de captación.[/dim]"
    )


if __name__ == "__main__":
    configure_logging()
    app()
