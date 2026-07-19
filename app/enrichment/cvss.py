"""Cálculo y parseo de CVSS v3.x/v4.0 — Foreshock.

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

# Claves de métrica válidas por versión mayor. El regex de arriba es codicioso y
# puede "comerse" texto contiguo con forma de métrica (p.ej. ".../A:H/SEE:BELOW"),
# lo que invalidaba el vector entero y descartaba un vector autoritativo válido:
# se trunca en el primer segmento con clave desconocida.
_METRICS_V3 = frozenset({
    "AV", "AC", "PR", "UI", "S", "C", "I", "A", "E", "RL", "RC", "CR", "IR",
    "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
})
_METRICS_V4 = frozenset({
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "E",
    "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA",
    "MSC", "MSI", "MSA", "S", "AU", "R", "V", "RE", "U",
})


def _trim_vector(vector: str, version: str) -> str | None:
    """Corta el vector en el primer segmento cuya clave no es una métrica CVSS
    de esa versión. Devuelve None si no queda ningún segmento válido."""
    valid = _METRICS_V4 if version.startswith("4") else _METRICS_V3
    prefix, *segments = vector.split("/")
    kept: list[str] = []
    for seg in segments:
        key, _, _ = seg.partition(":")
        if key not in valid:
            break
        kept.append(seg)
    if not kept:
        return None
    return "/".join([prefix, *kept])

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
        version = m.group(1)
        trimmed = _trim_vector(m.group(0).upper(), version)
        if trimmed is None:
            continue
        vector = trimmed
        if vector in seen:
            continue
        seen.add(vector)
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
    "sqli": 3, "sql injection": 3, "deserialization": 4, "ssrf": 2, "xss": 2,
    "cross-site scripting": 2, "csrf": 2, "info leak": 1, "dos": 2,
    "denial of service": 2, "privilege escalation": 3, "lpe": 3,
}


def _type_weight(vuln_type: str) -> int:
    """Peso del tipo de vulnerabilidad. vuln_type es texto libre del LLM
    ("SQL Injection", "Remote Code Execution (RCE)"): tras normalizar, si no hay
    match exacto se busca la clave conocida como subcadena."""
    key = vuln_type.strip().lower()
    if key in _TYPE_WEIGHT:
        return _TYPE_WEIGHT[key]
    for known, weight in _TYPE_WEIGHT.items():
        if known in key:
            return weight
    return 1


def severity_hint(
    *, vuln_type: str | None, attack_vector: str | None, has_public_poc: bool | None
) -> str | None:
    """Estimación cualitativa (NO es CVSS) a partir de proxies baratos."""
    if not vuln_type and not attack_vector:
        return None
    score = 0
    if vuln_type:
        score += _type_weight(vuln_type)
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
