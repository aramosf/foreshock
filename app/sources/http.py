"""Helpers de HTTP educado: User-Agent identificable, retries con backoff,
y comprobación de robots.txt (cacheada). Usar desde fetchers scrape/api.
"""

from __future__ import annotations

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

_robots_cache: dict[str, urllib.robotparser.RobotFileParser] = {}


def make_client() -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        timeout=settings.http_timeout_seconds,
        follow_redirects=True,
    )


async def allowed_by_robots(client: httpx.AsyncClient, url: str) -> bool:
    settings = get_settings()
    if not settings.respect_robots:
        return True
    parts = urlsplit(url)
    root = f"{parts.scheme}://{parts.netloc}"
    rp = _robots_cache.get(root)
    if rp is None:
        rp = urllib.robotparser.RobotFileParser()
        try:
            resp = await client.get(f"{root}/robots.txt")
            rp.parse(resp.text.splitlines() if resp.status_code == 200 else [])
        except Exception:  # noqa: BLE001 - sin robots accesible => permitir
            rp.parse([])
        _robots_cache[root] = rp
    return rp.can_fetch(settings.user_agent, url)


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=20),
    retry=retry_if_exception(_is_transient),
)
async def get(client: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
    """GET con retries exponenciales; respeta robots.txt para scraping."""
    if not await allowed_by_robots(client, url):
        raise PermissionError(f"robots.txt prohíbe {url}")
    resp = await client.get(url, **kwargs)  # type: ignore[arg-type]
    resp.raise_for_status()
    # Archiva la respuesta cruda (para recrear sin volver a la fuente).
    from app.sources.cache import archive_response
    archive_response(str(resp.url), resp.content,
                     resp.headers.get("content-type"))
    return resp
