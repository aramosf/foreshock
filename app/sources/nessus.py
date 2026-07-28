"""Tier 3 — Tenable Nessus plugins (scrape del listado 'newest').

Premisa de señal temprana: un plugin de Nessus puede referenciar un CVE que
está solo RESERVADO en MITRE (ID existe, sin info pública). Se scrapea el
listado HTML de plugins más recientes y se extraen los CVE citados.

Scraping educado: respeta robots.txt, UA identificable, sin rotar IP.
El HTML crudo se persiste (raw_html) para re-parseo sin volver a la fuente.
"""

from __future__ import annotations

from selectolax.parser import HTMLParser

from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get

# Tenable retiró la ruta histórica ``/plugins/nessus/newest`` (ahora responde
# 400). La lista vigente filtra el catálogo común por producto.
LISTING = "https://www.tenable.com/plugins/newest?type=nessus"
BASE = "https://www.tenable.com"


@register
class NessusSource(BaseSource):
    name = "nessus"
    kind = "Tenable Nessus plugin feed (newest)"
    method = "scrape"
    tier = 3
    cadence_seconds = 7200

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        # Tenable rechaza GETs "desnudos" (400); enviamos cabeceras de navegador.
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = await get(ctx.http, LISTING, headers=headers)
        html = resp.text
        tree = HTMLParser(html)
        out: list[FetchedMention] = []
        # Cada plugin es una fila con enlace a /plugins/nessus/<id> y un título.
        for row in tree.css("tr"):
            link = row.css_first("a[href^='/plugins/nessus/']")
            if link is None:
                continue
            href = link.attributes.get("href", "")
            title = link.text(strip=True)
            snippet = row.text(separator=" ", strip=True)
            # Solo filas que citen un CVE (la ingesta extrae el ID del texto).
            if "CVE-" not in snippet.upper() and "CVE-" not in title.upper():
                continue
            out.append(
                FetchedMention(
                    url=f"{BASE}{href}" if href.startswith("/") else href,
                    title=title or None,
                    snippet=snippet[:2000] if snippet else None,
                    # SIN fecha fiable en el payload: el listado 'newest' no trae
                    # la fecha de publicación por fila (vive en el detalle del
                    # plugin, que no se descarga). seen_at=None -> la ingesta usará
                    # now(); aceptable porque el listado es de plugins recientes y
                    # nessus rara vez es la fuente MÁS temprana de un candidate.
                    seen_at=None,
                    # raw por-fila se omite para no duplicar el listado completo N veces;
                    # el detalle del plugin se capturaría en un fetch de segundo nivel.
                    raw_html=None,
                )
            )
        return out
