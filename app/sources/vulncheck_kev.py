"""Tier 1 — VulnCheck KEV.

Catálogo de CVEs explotados más amplio y temprano que el de CISA (~80% más).
Requiere un token gratuito (FORESHOCK_VULNCHECK_TOKEN); si no hay token, la fuente
queda inactiva (devuelve []).
"""

from __future__ import annotations

import re

from dateutil.parser import isoparse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingest.affected import AffectedInput
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

log = get_logger(__name__)

# owner/repo de un clone_ssh_url git@github.com:owner/repo.git -> URL https.
_SSH = re.compile(r"git@github\.com:([\w.-]+/[\w.-]+?)(?:\.git)?$")


def _kev_date(it: dict):
    """Fecha KEV = la MÁS TEMPRANA entre date_added propio y las de explotación
    reportada (VulnCheck reporta a veces ANTES que CISA -> señal pre-KEV)."""
    dates = []
    for src in ([it.get("date_added")]
                + [r.get("date_added") for r in (it.get("vulncheck_reported_exploitation") or [])]):
        if src:
            try:
                dates.append(isoparse(src).date())
            except (ValueError, TypeError):
                pass
    return min(dates) if dates else None


def _enrichment(it: dict) -> dict:
    """Extrae de un registro vulncheck-kev los datos extra que el fetcher
    ignoraba: producto afectado, CWEs, referencias de exploit/explotación y si
    hay PoC público (vulncheck_xdb)."""
    xdb = it.get("vulncheck_xdb") or []
    refs: list[str] = []
    for x in xdb:
        if x.get("xdb_url"):
            refs.append(x["xdb_url"])
        m = _SSH.match(x.get("clone_ssh_url") or "")
        if m:
            refs.append(f"https://github.com/{m.group(1)}")
    refs += [r.get("url") for r in (it.get("vulncheck_reported_exploitation") or [])
             if isinstance(r, dict) and r.get("url")]
    affected = []
    product = it.get("product")
    if product:
        affected.append(AffectedInput(product=product, vendor=it.get("vendorProject")))
    return {
        "affected": affected or None,
        "cwe_ids": [c for c in (it.get("cwes") or []) if isinstance(c, str)] or None,
        "reference_urls": list(dict.fromkeys(refs))[:50] or None,
        "has_public_poc": bool(xdb),
    }


@register
class VulnCheckKevSource(BaseSource):
    name = "vulncheck_kev"
    kind = "VulnCheck KEV (API)"
    method = "api"
    tier = 1
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        if not settings.vulncheck_token:
            log.info("vulncheck.no_token")  # fuente inactiva sin token
            return []
        headers = {"Authorization": f"Bearer {settings.vulncheck_token}"}
        out: list[FetchedMention] = []
        page = 1
        limit = 100
        while page <= settings.vulncheck_max_pages:
            # API JSON oficial -> robots.txt no aplica (ver docstring de get()).
            resp = await get(
                ctx.http,
                f"{settings.vulncheck_api_base}/index/vulncheck-kev",
                respect_robots=False,
                params={"page": page, "limit": limit},
                headers=headers,
            )
            body = resp.json()
            items = body.get("data", [])
            if not items:
                break
            for it in items:
                cves = it.get("cve") or []
                kev_date = _kev_date(it)
                name = (it.get("vulnerabilityName") or it.get("name")
                        or it.get("product") or (cves[0] if cves else None))
                ransom = it.get("knownRansomwareCampaignUse")
                snippet = " | ".join(p for p in [
                    it.get("vendorProject"), it.get("product"),
                    it.get("shortDescription") or it.get("description"),
                    f"ransomware={ransom}" if ransom and ransom != "Unknown" else None,
                ] if p)[:2000] or None
                enr = _enrichment(it)
                # PoC público -> flag; el resto (afectado, cwe, refs) se aplica
                # al candidate vía _apply_candidate_updates.
                flags = {"in_kev": True, "kev_date": kev_date, "kev_source": "vulncheck"}
                if enr.pop("has_public_poc"):
                    flags["has_public_poc"] = True
                for cve in cves:
                    out.append(FetchedMention(
                        url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                        title=f"VulnCheck KEV: {name}"[:200],
                        snippet=snippet, cve_id=cve, flags=flags, **enr))
            meta = body.get("_meta") or {}
            total_pages = meta.get("total_pages")
            if total_pages is not None:
                if page >= int(total_pages):
                    break
            else:
                # Payload inesperado (sin _meta.total_pages): antes esto cortaba
                # SIEMPRE en la página 1. Se loguea y se sigue paginando mientras
                # la página venga llena (una página corta = última).
                log.warning("vulncheck.missing_total_pages", page=page,
                            meta_keys=sorted(meta.keys()))
                if len(items) < limit:
                    break
            page += 1
        return out
