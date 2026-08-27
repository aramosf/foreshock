"""Ventana canónica del producto y predicados SQL compartidos.

El dashboard operativo explica señales observadas desde el 1 de enero de 2026.
Los datos anteriores se conservan para auditoría, pero no forman parte de las
consultas operativas por defecto. Del mismo modo, un identificador CVE de un año
anterior que continúa ausente del espejo oficial se clasifica como
inconsistencia de fuente, no como CVE pre-reservado actual.
"""

from __future__ import annotations

from datetime import date

OPERATIONAL_MIN_DATE = date(2026, 1, 1)
OPERATIONAL_MIN_DATE_ISO = OPERATIONAL_MIN_DATE.isoformat()
OPERATIONAL_CVE_YEAR = OPERATIONAL_MIN_DATE.year


def operational_candidate_sql(alias: str = "c") -> str:
    """Predicado SQL para candidates del universo operativo."""
    return (
        f"{alias}.first_seen_at >= '{OPERATIONAL_MIN_DATE_ISO}'::timestamptz"
        f" AND ({alias}.cve_id IS NULL OR "
        f"substring({alias}.cve_id FROM 5 FOR 4) >= '{OPERATIONAL_CVE_YEAR}')"
    )


def operational_published_sql(alias: str = "p") -> str:
    """Predicado SQL para CVEs oficiales del universo operativo."""
    return (
        f"{alias}.cvelist_published_at >= "
        f"'{OPERATIONAL_MIN_DATE_ISO}'::timestamptz"
        f" AND substring({alias}.id FROM 5 FOR 4) >= '{OPERATIONAL_CVE_YEAR}'"
    )


def old_cve_identifier_sql(alias: str = "c") -> str:
    """Identificador CVE anterior al año operativo."""
    return (
        f"{alias}.cve_id IS NOT NULL"
        f" AND substring({alias}.cve_id FROM 5 FOR 4) < '{OPERATIONAL_CVE_YEAR}'"
    )
