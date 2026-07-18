"""Enriquecimiento estructurado de CVEs a partir de ``published_cves.raw_json``
(esquema CVE JSON 5.0 de cvelistV5, con contenedores CNA y ADP de CISA).

Puramente derivado: no descarga nada. Convierte el JSON crudo (que ya está en
BD) en filas normalizadas (cve_cvss / cve_cwe / cve_cpe / cve_reference) y en
columnas denormalizadas de ``published_cves`` para filtros/cruces rápidos.

``parse_record`` es una función PURA y testeable. ``enrich_all`` es el driver
por lotes idempotente (delete-by-cve + insert), reejecutable sin duplicar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import bindparam, delete, insert, select, update

from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import (
    CveCpe,
    CveCvss,
    CveCwe,
    CveReference,
    PublishedCVE,
)

log = get_logger(__name__)

# Clave de métrica CVE 5.0 -> versión CVSS normalizada.
_CVSS_KEYS = {
    "cvssV2_0": "2.0",
    "cvssV2": "2.0",
    "cvssV3_0": "3.0",
    "cvssV3_1": "3.1",
    "cvssV4_0": "4.0",
}
# Prioridad para elegir la métrica "primaria" (mayor versión gana).
_VERSION_RANK = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}


@dataclass
class Enrichment:
    """Resultado puro del parseo de un registro CVE 5.0."""

    cve_id: str
    description_en: str | None = None
    primary_cvss_version: str | None = None
    primary_cvss_score: float | None = None
    primary_cvss_severity: str | None = None
    primary_cvss_vector: str | None = None
    primary_cwe: str | None = None
    has_exploit_ref: bool = False
    has_patch_ref: bool = False
    ssvc_exploitation: str | None = None
    ssvc_automatable: str | None = None
    ssvc_technical_impact: str | None = None
    cvss: list[dict[str, Any]] = field(default_factory=list)
    cwe: list[dict[str, Any]] = field(default_factory=list)
    cpe: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)


def _container_source(container: dict[str, Any]) -> str:
    meta = container.get("providerMetadata") or {}
    return meta.get("shortName") or meta.get("orgId") or "unknown"


def _parse_metrics(container: dict[str, Any], source: str, out: Enrichment) -> None:
    for metric in container.get("metrics") or []:
        if not isinstance(metric, dict):
            continue
        # SSVC (CISA ADP): metric.other.type == "ssvc".
        other = metric.get("other")
        if isinstance(other, dict) and other.get("type") == "ssvc":
            content = other.get("content") or {}
            for opt in content.get("options") or []:
                if not isinstance(opt, dict):
                    continue
                for k, v in opt.items():
                    kl = k.lower()
                    if kl == "exploitation" and out.ssvc_exploitation is None:
                        out.ssvc_exploitation = v
                    elif kl == "automatable" and out.ssvc_automatable is None:
                        out.ssvc_automatable = v
                    elif kl.startswith("technical") and out.ssvc_technical_impact is None:
                        out.ssvc_technical_impact = v
        # CVSS: cualquier clave cvssV*.
        for key, version in _CVSS_KEYS.items():
            block = metric.get(key)
            if not isinstance(block, dict):
                continue
            out.cvss.append({
                "version": block.get("version") or version,
                "source": source,
                "type": metric.get("type"),
                "vector": block.get("vectorString"),
                "base_score": block.get("baseScore"),
                "base_severity": (block.get("baseSeverity") or "").upper() or None,
                "exploitability_score": block.get("exploitabilityScore"),
                "impact_score": block.get("impactScore"),
            })


def _parse_problem_types(container: dict[str, Any], source: str, out: Enrichment) -> None:
    for pt in container.get("problemTypes") or []:
        if not isinstance(pt, dict):
            continue
        for desc in pt.get("descriptions") or []:
            if not isinstance(desc, dict):
                continue
            cwe_id = desc.get("cweId")
            text_desc = desc.get("description")
            if not cwe_id and not text_desc:
                continue
            out.cwe.append({
                "cwe_id": cwe_id or text_desc,
                "description": text_desc if cwe_id else None,
                "source": source,
            })


def _parse_affected(container: dict[str, Any], source: str, out: Enrichment) -> None:
    for aff in container.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        default_status = aff.get("defaultStatus")
        for cpe in aff.get("cpes") or []:
            if not isinstance(cpe, str) or not cpe.startswith("cpe:"):
                continue
            out.cpe.append({
                "cpe23": cpe,
                "vulnerable": default_status != "unaffected",
                "version_start": None,
                "version_start_type": None,
                "version_end": None,
                "version_end_type": None,
                "source": source,
            })


def _parse_references(container: dict[str, Any], source: str, out: Enrichment,
                      seen: set[str]) -> None:
    for ref in container.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        tags = [t for t in (ref.get("tags") or []) if isinstance(t, str)]
        low = {t.lower() for t in tags}
        if "exploit" in low:
            out.has_exploit_ref = True
        if "patch" in low:
            out.has_patch_ref = True
        out.references.append({"url": url, "tags": tags or None, "source": source})


def _pick_primary_cvss(out: Enrichment) -> None:
    """Elige la métrica primaria: CNA-Primary > CNA > ADP; a igualdad, mayor versión."""
    def rank(c: dict[str, Any]) -> tuple[int, int, int]:
        is_cna = 0 if c["source"] in ("CVE", "cisa-adp") else 1  # CNA propietaria gana
        is_primary = 1 if (c.get("type") or "").lower() == "primary" else 0
        return (is_cna, is_primary, _VERSION_RANK.get(c["version"], 0))

    scored = [c for c in out.cvss if c.get("base_score") is not None]
    if not scored:
        return
    best = max(scored, key=rank)
    out.primary_cvss_version = best["version"]
    out.primary_cvss_score = best["base_score"]
    out.primary_cvss_severity = best["base_severity"]
    out.primary_cvss_vector = best["vector"]


def parse_record(cve_id: str, raw: dict[str, Any] | None) -> Enrichment:
    """Parsea un registro CVE JSON 5.0 a un ``Enrichment`` (función pura)."""
    out = Enrichment(cve_id=cve_id)
    if not isinstance(raw, dict):
        return out
    containers = raw.get("containers") or {}
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
    adps = [a for a in (containers.get("adp") or []) if isinstance(a, dict)]

    seen_ref: set[str] = set()
    # CNA primero (fuente propietaria), luego ADP (CISA enriquece).
    if cna:
        src = _container_source(cna)
        _parse_metrics(cna, src, out)
        _parse_problem_types(cna, src, out)
        _parse_affected(cna, src, out)
        _parse_references(cna, src, out, seen_ref)
        for d in cna.get("descriptions") or []:
            if isinstance(d, dict) and d.get("lang", "").lower().startswith("en"):
                out.description_en = d.get("value")
                break
    for adp in adps:
        src = _container_source(adp)
        src = "cisa-adp" if src == "CISA-ADP" else src
        _parse_metrics(adp, src, out)
        _parse_problem_types(adp, src, out)
        _parse_affected(adp, src, out)
        _parse_references(adp, src, out, seen_ref)

    _pick_primary_cvss(out)
    # CWE primario: primer cweId con forma CWE-\d.
    for c in out.cwe:
        cid = c["cwe_id"]
        if isinstance(cid, str) and cid.upper().startswith("CWE-"):
            out.primary_cwe = cid.upper()
            break
    return out


def _persist_batch(session, enrichments: list[Enrichment]) -> None:
    ids = [e.cve_id for e in enrichments]
    # Idempotencia: borra el detalle previo de estos CVEs antes de reinsertar.
    for table in (CveCvss, CveCwe, CveCpe, CveReference):
        session.execute(delete(table.__table__).where(table.__table__.c.cve_id.in_(ids)))

    def rows(items_key, cols):
        acc = []
        for e in enrichments:
            for item in getattr(e, items_key):
                row = {"cve_id": e.cve_id}
                row.update({c: item.get(c) for c in cols})
                acc.append(row)
        return acc

    cvss_rows = rows("cvss", ["version", "source", "type", "vector", "base_score",
                              "base_severity", "exploitability_score", "impact_score"])
    cwe_rows = rows("cwe", ["cwe_id", "description", "source"])
    cpe_rows = rows("cpe", ["cpe23", "vulnerable", "version_start", "version_start_type",
                            "version_end", "version_end_type", "source"])
    ref_rows = rows("references", ["url", "tags", "source"])
    if cvss_rows:
        session.execute(insert(CveCvss.__table__), cvss_rows)
    if cwe_rows:
        session.execute(insert(CveCwe.__table__), cwe_rows)
    if cpe_rows:
        session.execute(insert(CveCpe.__table__), cpe_rows)
    if ref_rows:
        session.execute(insert(CveReference.__table__), ref_rows)

    # Update denormalizado en published_cves (executemany).
    now = datetime.now(UTC)
    upd = (
        update(PublishedCVE.__table__)
        .where(PublishedCVE.__table__.c.id == bindparam("b_id"))
        .values(
            description_en=bindparam("v_description_en"),
            primary_cvss_version=bindparam("v_primary_cvss_version"),
            primary_cvss_score=bindparam("v_primary_cvss_score"),
            primary_cvss_severity=bindparam("v_primary_cvss_severity"),
            primary_cvss_vector=bindparam("v_primary_cvss_vector"),
            primary_cwe=bindparam("v_primary_cwe"),
            has_exploit_ref=bindparam("v_has_exploit_ref"),
            has_patch_ref=bindparam("v_has_patch_ref"),
            ssvc_exploitation=bindparam("v_ssvc_exploitation"),
            ssvc_automatable=bindparam("v_ssvc_automatable"),
            ssvc_technical_impact=bindparam("v_ssvc_technical_impact"),
            enriched_at=bindparam("v_enriched_at"),
        )
    )
    params = [{
        "b_id": e.cve_id,
        "v_description_en": e.description_en,
        "v_primary_cvss_version": e.primary_cvss_version,
        "v_primary_cvss_score": e.primary_cvss_score,
        "v_primary_cvss_severity": e.primary_cvss_severity,
        "v_primary_cvss_vector": e.primary_cvss_vector,
        "v_primary_cwe": e.primary_cwe,
        "v_has_exploit_ref": e.has_exploit_ref,
        "v_has_patch_ref": e.has_patch_ref,
        "v_ssvc_exploitation": e.ssvc_exploitation,
        "v_ssvc_automatable": e.ssvc_automatable,
        "v_ssvc_technical_impact": e.ssvc_technical_impact,
        "v_enriched_at": now,
    } for e in enrichments]
    session.execute(upd, params)


def enrich_all(batch_size: int = 2000) -> dict[str, int]:
    """Recorre TODA published_cves por lotes (keyset por id), parsea raw_json y
    persiste el enriquecimiento. Idempotente: reejecutable sin duplicar."""
    stats = {"processed": 0, "cvss": 0, "cwe": 0, "cpe": 0, "refs": 0}
    last_id = ""
    while True:
        with session_scope() as session:
            rows = session.execute(
                select(PublishedCVE.__table__.c.id, PublishedCVE.__table__.c.raw_json)
                .where(PublishedCVE.__table__.c.id > last_id)
                .order_by(PublishedCVE.__table__.c.id)
                .limit(batch_size)
            ).all()
            if not rows:
                break
            enrichments = [parse_record(cid, raw) for cid, raw in rows]
            _persist_batch(session, enrichments)
            for e in enrichments:
                stats["cvss"] += len(e.cvss)
                stats["cwe"] += len(e.cwe)
                stats["cpe"] += len(e.cpe)
                stats["refs"] += len(e.references)
            stats["processed"] += len(rows)
            last_id = rows[-1][0]
        if stats["processed"] % (batch_size * 10) == 0:
            log.info("enrich.progress", **stats)
    log.info("enrich.done", **stats)
    return stats
