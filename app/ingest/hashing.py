"""Hash de contenido para idempotencia de menciones.

Regla de diseño: NO se hashea el HTML crudo (timestamps, anuncios, tokens CSRF
cambian el hash y generarían filas nuevas cada fetch). Se hashea el EXTRACTO
semántico: identificadores + título + snippet + URL canónica, todo normalizado.

Consecuencia deseada: un re-listado idéntico -> mismo hash -> no duplica; un
cambio real de contenido -> hash nuevo -> mención nueva (legítima en el timeline).
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SEP = "\x1f"

# Parámetros de tracking que se eliminan de la URL canónica.
_TRACKING_PREFIXES = ("utm_", "mc_", "fbclid", "gclid", "ref", "source")


def normalize_text(s: str | None) -> str:
    """Colapsa espacios y pasa a minúsculas (estable para hashing)."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip().lower()


def canonical_url(url: str | None) -> str:
    """URL canónica: sin fragmento, sin parámetros de tracking, query ordenada."""
    if not url:
        return ""
    parts = urlsplit(url.strip())
    query = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not any(k.lower().startswith(p) for p in _TRACKING_PREFIXES)
    ]
    query.sort()
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, urlencode(query), ""))


def content_hash(
    *,
    cve: str | None,
    native: str | None,
    title: str | None,
    snippet: str | None,
    url: str | None,
) -> str:
    """SHA-256 del extracto normalizado que define la identidad de una mención."""
    payload = _SEP.join(
        [
            (cve or "").upper(),
            (native or "").upper(),
            normalize_text(title),
            normalize_text(snippet),
            canonical_url(url),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
