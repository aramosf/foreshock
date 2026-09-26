"""Helpers de HTTP educado: User-Agent identificable, retries con backoff,
y comprobación de robots.txt (cacheada). Usar desde fetchers scrape/api.
"""

from __future__ import annotations

import time
import urllib.robotparser
from urllib.parse import urlsplit

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


def _is_transient(exc: BaseException) -> bool:
    """Reintenta solo fallos transitorios: errores de transporte y 429/5xx.
    Los 4xx permanentes (400/401/403/404) NO se reintentan (sería inútil y
    empeora el rate limit, p.ej. un 403 secundario de GitHub)."""
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or code >= 500
    return False

# Caché de robots.txt por host con TTL: un robots.txt puede cambiar, así que se
# refresca pasado _ROBOTS_TTL_SECONDS (el proceso es de larga vida).
_ROBOTS_TTL_SECONDS = 86400  # 24 h
_robots_cache: dict[str, tuple[float, urllib.robotparser.RobotFileParser]] = {}


def make_client() -> httpx.AsyncClient:
    settings = get_settings()
    # follow_redirects=True sin allowlist de host = SSRF latente (una fuente podría
    # redirigirnos a un host interno). Riesgo ACEPTADO: las URLs las fija el código
    # (fuentes oficiales), no entrada de usuario. Mitigación ligera: se acota el nº
    # de saltos (max_redirects, por defecto 20 en httpx) para no seguir cadenas de
    # redirección abusivas. Este límite se hereda en client.get/stream (es de
    # cliente, no por-petición).
    return httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        timeout=settings.http_timeout_seconds,
        follow_redirects=True,
        max_redirects=5,
    )


async def allowed_by_robots(client: httpx.AsyncClient, url: str) -> bool:
    settings = get_settings()
    if not settings.respect_robots:
        return True
    parts = urlsplit(url)
    root = f"{parts.scheme}://{parts.netloc}"
    cached = _robots_cache.get(root)
    if cached is None or (time.monotonic() - cached[0]) > _ROBOTS_TTL_SECONDS:
        rp = urllib.robotparser.RobotFileParser()
        try:
            resp = await client.get(f"{root}/robots.txt")
            rp.parse(resp.text.splitlines() if resp.status_code == 200 else [])
        except Exception:  # noqa: BLE001 - sin robots accesible => permitir
            rp.parse([])
        _robots_cache[root] = (time.monotonic(), rp)
    else:
        rp = cached[1]
    return rp.can_fetch(settings.user_agent, url)


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=20),
    retry=retry_if_exception(_is_transient),
)
async def get(client: httpx.AsyncClient, url: str, *,
              respect_robots: bool = True, **kwargs: object) -> httpx.Response:
    """GET con retries exponenciales y archivado del crudo.

    `respect_robots`: robots.txt es un protocolo para CRAWLERS que descubren
    URLs; no aplica a clientes que consumen una API JSON o un feed que el
    propio servicio ofrece para ese fin (api.github.com, CISA KEV, VulnCheck,
    Red Hat Hydra, OSV...). Esas fuentes deben pasar `respect_robots=False`:
    muchos de esos hosts sirven un robots.txt restrictivo pensado para
    buscadores que, de aplicarse, rompería el consumo legítimo de la API.
    Para scraping de HTML (method="scrape") se deja el valor por defecto True.
    """
    if respect_robots and not await allowed_by_robots(client, url):
        raise PermissionError(f"robots.txt prohíbe {url}")
    resp = await client.get(url, **kwargs)  # type: ignore[arg-type]
    resp.raise_for_status()
    # Archiva la respuesta cruda (para recrear sin volver a la fuente).
    from app.sources.cache import archive_response
    archive_response(str(resp.url), resp.content,
                     resp.headers.get("content-type"))
    return resp
