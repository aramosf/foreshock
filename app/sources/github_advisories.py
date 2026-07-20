"""Tier 4 — GitHub Security Advisories (GHSA) vía la API pública de GitHub.

Regla de oro del proyecto: no scrapear GHSA; usar la API. Trae ghsa_id, cve_id
(si asignado), resumen, y `vulnerabilities` con paquete (ecosystem+name) y
rangos de versión -> alimenta affected_products de forma estructurada.

Ventana incremental: en vez de re-descargar `max_pages` (30) páginas cada hora,
se usa el filtro `updated` de la API (rango ISO 8601) con un lookback de
2*cadencia. Elección documentada: la ingesta es idempotente (content_hash), así
que basta con cubrir con margen el hueco desde la última ejecución; 2 cadencias
absorben una corrida perdida y ordenar por `updated` (no `published`) captura
también advisories antiguos que acaban de recibir CVE o rangos afectados. El
backfill histórico se hace con una corrida manual subiendo el lookback.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta


from app.core.config import get_settings
from app.sources.base import (
    BaseSource, FetchContext, parse_advisory_date, register,
)
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://api.github.com/advisories"

# Extrae la URL de la página siguiente del header Link (paginación por cursor).
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')

# Lookback = _LOOKBACK_CADENCES * cadence_seconds (ver docstring del módulo).
_LOOKBACK_CADENCES = 2


@register
class GitHubAdvisoriesSource(BaseSource):
    name = "github_advisories"
    kind = "GitHub Security Advisories (GHSA API)"
    method = "api"
    tier = 4
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        since = datetime.now(UTC) - timedelta(
            seconds=_LOOKBACK_CADENCES * self.cadence_seconds)
        out: list[FetchedMention] = []
        url: str | None = API
        params: dict[str, object] | None = {
            "per_page": 100, "sort": "updated", "direction": "desc",
            # Filtro de fecha de la API (rango ISO 8601): solo lo actualizado
            # desde `since` -> normalmente 1 página en vez de 30.
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        }
        pages = 0
        # Paginación por header Link hasta github_advisories_max_pages (cota de
        # seguridad; con el filtro `updated` rara vez pasa de la primera página).
        while url and pages < settings.github_advisories_max_pages:
            # API JSON oficial -> robots.txt no aplica (ver docstring de get()).
            resp = await get(ctx.http, url, respect_robots=False,
                             params=params, headers=headers)
            batch = resp.json()
            out.extend(self._parse(batch))
            pages += 1
            # Cinturón y tirantes: si el servidor ignorase el filtro, cortamos
            # en cuanto el item más viejo de la página quede fuera de la ventana.
            oldest = self._oldest_updated(batch)
            if oldest is not None and oldest < since:
                break
            m = _NEXT.search(resp.headers.get("Link", ""))
            url = m.group(1) if m else None
            params = None  # la URL 'next' ya lleva el cursor
        return out

    @staticmethod
    def _oldest_updated(data: list[dict]) -> datetime | None:
        oldest: datetime | None = None
        for adv in data:
            dt = _parse_dt(adv.get("updated_at"))
            if dt is not None and (oldest is None or dt < oldest):
                oldest = dt
        return oldest

    @staticmethod
    def _parse(data: list[dict]) -> list[FetchedMention]:
        out: list[FetchedMention] = []
        for adv in data:
            ghsa = adv.get("ghsa_id")
            cve = adv.get("cve_id")
            summary = adv.get("summary") or ""
            # paquetes afectados -> al snippet (el enrichment los estructura después)
            pkgs = []
            for v in adv.get("vulnerabilities") or []:
                pkg = (v or {}).get("package") or {}
                eco, name = pkg.get("ecosystem"), pkg.get("name")
                rng = v.get("vulnerable_version_range")
                if name:
                    pkgs.append(f"{eco}:{name} {rng or ''}".strip())
            snippet = summary
            if pkgs:
                snippet = f"{summary} | affected: {', '.join(pkgs[:10])}"
            # seen_at = fecha REAL de publicación del advisory (fallback: última
            # actualización), no el momento del fetch.
            seen = _parse_dt(adv.get("published_at")) or _parse_dt(adv.get("updated_at"))
            out.append(
                FetchedMention(
                    url=adv.get("html_url"),
                    title=summary[:200] if summary else (cve or ghsa),
                    snippet=snippet[:2000] if snippet else None,
                    cve_id=cve,
                    native_id=ghsa,
                    seen_at=seen,
                )
            )
        return out


def _parse_dt(val: str | None) -> datetime | None:
    """ISO 8601 -> datetime UTC-aware (None si falta, no parsea o es fecha
    cero/imposible < 1990). Delega en el helper compartido."""
    return parse_advisory_date(val)
