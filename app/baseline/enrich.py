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

from sqlalchemy import and_, bindparam, delete, insert, or_, select, update

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


def _parse_metrics(container: dict[str, Any], source: str, out: Enrichment,
                   from_cna: bool = False) -> None:
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
                # from_cna: la métrica viene del contenedor CNA (propietario) y
                # no de un ADP. Se decide por el TIPO de contenedor, no por el
                # shortName (que en ADP no siempre es "CISA-ADP"). Se usa solo
                # para elegir la primaria; no se persiste.
                "from_cna": from_cna,
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
    """Elige la métrica primaria: MAYOR versión CVSS primero; a igualdad de
    versión, contenedor CNA (propietario) sobre ADP y, a igualdad, tipo primary.

    El orden antiguo (fuente > versión) hacía que un CVSS v2.0 del CNA ganara a
    un v4.0 de CISA-ADP: v4.0 es estrictamente más informativo y no debe perder
    frente a v2.0. Por eso la versión pasa a dominar el ranking. La detección de
    ADP es por TIPO de contenedor (``from_cna``), tolerante a shortNames de ADP
    distintos de "CISA-ADP".
    """
    def rank(c: dict[str, Any]) -> tuple[int, int, int]:
        version = _VERSION_RANK.get(c["version"], 0)
        from_cna = 1 if c.get("from_cna") else 0     # CNA propietaria > ADP
        is_primary = 1 if (c.get("type") or "").lower() == "primary" else 0
        return (version, from_cna, is_primary)

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
        _parse_metrics(cna, src, out, from_cna=True)
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


def enrich_all(batch_size: int = 2000, full: bool = False) -> dict[str, int]:
    """Recorre published_cves por lotes (keyset por id), parsea raw_json y
    persiste el enriquecimiento. Idempotente: reejecutable sin duplicar.

    Por defecto es INCREMENTAL: solo procesa los CVEs nunca enriquecidos
    (``enriched_at IS NULL``) o cuyo registro cvelist cambió después del último
    enriquecimiento (``cvelist_updated_at > enriched_at``). Con ``full=True``
    reprocesa todo el histórico (útil tras cambiar el parser).

    Las filas SIN ``raw_json`` se saltan sin sellar ``enriched_at``: son CVEs
    creados por el módulo NVD cuyo registro cvelist aún no ha llegado, y no hay
    nada que derivar. Sellarlas las dejaba fuera del incremental para siempre,
    porque ``cvelist_updated_at`` es el ``dateUpdated`` del registro (una fecha
    PASADA) y nunca llega a superar el sello. Se contabilizan en ``skipped``.
    """
    stats = {"processed": 0, "skipped": 0, "cvss": 0, "cwe": 0, "cpe": 0, "refs": 0}
    col = PublishedCVE.__table__.c
    last_id = ""
    batches = 0
    while True:
        with session_scope() as session:
            stmt = (
                select(col.id, col.raw_json)
                .where(col.id > last_id)
                .order_by(col.id)
                .limit(batch_size)
            )
            if not full:
                # Incremental: pendientes de enriquecer o re-tocados por cvelist.
                stmt = stmt.where(or_(
                    col.enriched_at.is_(None),
                    col.cvelist_updated_at > col.enriched_at,
                    # Auto-reparación ACOTADA: sellado pese a tener JSON pero sin
                    # haber extraído NADA (firma de un parser antiguo defectuoso:
                    # ni descripción, ni CVSS, ni CWE). NO reseleccionamos filas
                    # ya enriquecidas que solo carecen de descripción inglesa
                    # (CNA no anglófono) pero sí tienen CVSS/CWE: esas están
                    # hechas y reprocesarlas en cada pasada era amplificación de
                    # escritura permanente. Barato: no destoasta raw_json. Una
                    # reparación tras un fix real del parser se hace con full=True.
                    and_(
                        col.raw_json.isnot(None),
                        col.state == "PUBLISHED",
                        col.description_en.is_(None),
                        col.enriched_at.isnot(None),
                        col.primary_cvss_score.is_(None),
                        col.primary_cwe.is_(None),
                    ),
                ))
            rows = session.execute(stmt).all()
            if not rows:
                break
            last_id = rows[-1][0]
            batches += 1
            # Sin raw_json no hay nada que derivar: ni se parsea ni se sella.
            parseable = [(cid, raw) for cid, raw in rows if isinstance(raw, dict)]
            stats["skipped"] += len(rows) - len(parseable)
            if not parseable:
                continue
            enrichments = [parse_record(cid, raw) for cid, raw in parseable]
            _persist_batch(session, enrichments)
            for e in enrichments:
                stats["cvss"] += len(e.cvss)
                stats["cwe"] += len(e.cwe)
                stats["cpe"] += len(e.cpe)
                stats["refs"] += len(e.references)
            stats["processed"] += len(parseable)
        # Cada 10 lotes (no por múltiplo de `processed`: con filas saltadas el
        # contador ya no cae en múltiplos exactos del tamaño de lote).
        if batches % 10 == 0:
            log.info("enrich.progress", **stats)
    log.info("enrich.done", full=full, **stats)
    return stats
