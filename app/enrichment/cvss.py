"""Cálculo y parseo de CVSS v3.x/v4.0 — CVERadar.

Dos caminos (nunca inventar un número):
  1. AUTORITATIVO: se extraen vectores CVSS verbatim del texto de la fuente
     (Red Hat, MSRC, CNA...) y se calcula el score con la librería `cvss`.
  2. DERIVADO: a partir de las métricas base inferidas por el LLM se construye
     un vector y se calcula el score. Solo si están las 8 métricas base; si no,
     se deja el score en blanco y se usa un `severity_hint` cualitativo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cvss import CVSS3, CVSS4

from app.enrichment.schema import CVSSMetricsOut

# Vectores CVSS embebidos en texto.
_VECTOR_RE = re.compile(r"CVSS:(3\.[01]|4\.0)/[A-Z]+:[A-Z]+(?:/[A-Z]+:[A-Z]+)+", re.IGNORECASE)

_AV = {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}
_AC = {"low": "L", "high": "H"}
_PR = {"none": "N", "low": "L", "high": "H"}
_UI = {"none": "N", "required": "R"}
_S = {"unchanged": "U", "changed": "C"}
_CIA = {"none": "N", "low": "L", "high": "H"}


@dataclass
class CVSSResult:
    version: str        # '3.0' | '3.1' | '4.0'
    vector: str
    base_score: float | None
    base_severity: str | None
    provenance: str     # 'authoritative' | 'derived'
    inferred_metrics: list[str] = field(default_factory=list)


def _score_severity(vector: str, version: str) -> tuple[float | None, str | None]:
    """Calcula (base_score, base_severity) desde un vector con la librería cvss."""
    try:
        if version.startswith("4"):
            c = CVSS4(vector)
            return float(c.base_score), c.severity.upper()
        c3 = CVSS3(vector)
        base = float(c3.scores()[0])
        severity = c3.severities()[0].upper()  # la lib devuelve 'Critical'; CHECK exige upper
        return base, severity
    except Exception:  # noqa: BLE001 - vector inválido -> sin score
        return None, None


def parse_authoritative(text: str | None) -> list[CVSSResult]:
    """Extrae y puntúa todos los vectores CVSS presentes en el texto."""
    if not text:
        return []
    out: list[CVSSResult] = []
    seen: set[str] = set()
    for m in _VECTOR_RE.finditer(text):
        vector = m.group(0).upper()
        if vector in seen:
            continue
        seen.add(vector)
        version = m.group(1)
        score, severity = _score_severity(vector, version)
        if score is None:
            continue
        out.append(
            CVSSResult(
                version=version,
                vector=vector,
                base_score=score,
                base_severity=severity,
                provenance="authoritative",
            )
        )
    return out


def derive_from_metrics(metrics: CVSSMetricsOut | None) -> CVSSResult | None:
    """Construye un CVSS v3.1 derivado si están las 8 métricas base; si no, None."""
    if metrics is None:
        return None
    parts = {
        "AV": _AV.get(metrics.attack_vector or ""),
        "AC": _AC.get(metrics.attack_complexity or ""),
        "PR": _PR.get(metrics.privileges_required or ""),
        "UI": _UI.get(metrics.user_interaction or ""),
        "S": _S.get(metrics.scope or ""),
        "C": _CIA.get(metrics.confidentiality or ""),
        "I": _CIA.get(metrics.integrity or ""),
        "A": _CIA.get(metrics.availability or ""),
    }
    if any(v is None for v in parts.values()):
        return None  # métricas insuficientes -> se usará severity_hint
    vector = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in parts.items())
    score, severity = _score_severity(vector, "3.1")
    if score is None:
        return None
    return CVSSResult(
        version="3.1",
        vector=vector,
        base_score=score,
        base_severity=severity,
        provenance="derived",
        inferred_metrics=list(parts.keys()),  # todas provienen de inferencia LLM
    )


# --- severity_hint cualitativo (cuando no hay score numérico) -----------------

_TYPE_WEIGHT = {
    "rce": 4, "remote code execution": 4, "auth bypass": 3, "authbypass": 3,
    "sqli": 3, "deserialization": 4, "ssrf": 2, "xss": 2, "csrf": 2,
    "info leak": 1, "dos": 2, "privilege escalation": 3, "lpe": 3,
}


def severity_hint(
    *, vuln_type: str | None, attack_vector: str | None, has_public_poc: bool | None
) -> str | None:
    """Estimación cualitativa (NO es CVSS) a partir de proxies baratos."""
    if not vuln_type and not attack_vector:
        return None
    score = 0
    if vuln_type:
        score += _TYPE_WEIGHT.get(vuln_type.strip().lower(), 1)
    if attack_vector == "network":
        score += 2
    elif attack_vector == "adjacent":
        score += 1
    if has_public_poc:
        score += 1
    if score >= 6:
        return "likely-critical"
    if score >= 4:
        return "likely-high"
    if score >= 2:
        return "likely-medium"
    return "likely-low"
