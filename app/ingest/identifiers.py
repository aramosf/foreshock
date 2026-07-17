"""Extracción de identificadores nativos de vulnerabilidad desde texto.

Detecta CVE, ZDI-CAN, ZDI, VU#, GHSA, MSRC, OSV/ecosistemas, etc. Cada
identificador (scheme, value) ancla un candidate y habilita el enlace
determinista (Etapa A de la correlación).

El primer scheme de la lista es el "nativo" preferido para etiquetar una
mención cuando no hay CVE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Orden = prioridad de "nativo" cuando no hay CVE.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("CVE", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    ("ZDI-CAN", re.compile(r"\bZDI-CAN-\d{3,6}\b", re.IGNORECASE)),
    ("ZDI", re.compile(r"\bZDI-\d{2}-\d{3,5}\b", re.IGNORECASE)),
    ("VU", re.compile(r"\bVU#\d{5,7}\b", re.IGNORECASE)),
    ("GHSA", re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-"
                        r"[23456789cfghjmpqrvwx]{4}\b", re.IGNORECASE)),
    ("MSRC", re.compile(r"\bADV\d{6}\b", re.IGNORECASE)),
    # Identificador sintético para anclar candidates pre-CVE desde commits de
    # seguridad sin CVE asignado: GHCOMMIT:owner/repo@<sha7-40>.
    ("GHCOMMIT", re.compile(r"\bGHCOMMIT:[\w.-]+/[\w.-]+@[0-9a-fA-F]{7,40}\b")),
]


@dataclass(frozen=True)
class ExtractedId:
    scheme: str
    value: str


def _canon(scheme: str, value: str) -> str:
    """Normaliza el valor a su forma canónica.

    GHSA usa prefijo 'GHSA-' en mayúsculas y cuerpo en minúsculas
    (p.ej. 'GHSA-jfh8-c2jp-5v3q'); el resto se pasa a mayúsculas.
    """
    if scheme == "GHSA":
        _, _, body = value.partition("-")
        return f"GHSA-{body.lower()}"
    if scheme == "GHCOMMIT":
        return value  # owner/repo y sha son sensibles a mayúsculas; no normalizar
    return value.upper()


def extract_identifiers(*texts: str | None) -> list[ExtractedId]:
    """Extrae identificadores únicos de uno o varios textos, preservando orden de prioridad.

    >>> ids = extract_identifiers("Fix for CVE-2026-1234 (was ZDI-CAN-26123)")
    >>> [(i.scheme, i.value) for i in ids]
    [('CVE', 'CVE-2026-1234'), ('ZDI-CAN', 'ZDI-CAN-26123')]
    """
    seen: set[tuple[str, str]] = set()
    out: list[ExtractedId] = []
    blob = "\n".join(t for t in texts if t)
    for scheme, pat in _PATTERNS:
        for m in pat.finditer(blob):
            value = _canon(scheme, m.group(0))
            key = (scheme, value)
            if key not in seen:
                seen.add(key)
                out.append(ExtractedId(scheme=scheme, value=value))
    return out


def primary_cve(ids: list[ExtractedId]) -> str | None:
    """Devuelve el primer CVE si existe."""
    for i in ids:
        if i.scheme == "CVE":
            return i.value
    return None


def primary_native(ids: list[ExtractedId]) -> str | None:
    """Devuelve el identificador nativo preferido no-CVE (p.ej. ZDI-CAN)."""
    for i in ids:
        if i.scheme != "CVE":
            return i.value
    return None
