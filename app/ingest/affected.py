"""Canonicalización de software y persistencia de datos estructurados.

Fuente única de verdad para:
- canonicalizar ecosistema (une pip/PyPI, rust/cargo/crates, …),
- clasificar el software (product | distro | malware),
- persistir affected_products (+ rangos de versión) y cvss_scores autoritativos
  a partir de datos estructurados que traen las fuentes (OSV, GHSA, …).

Lo usan tanto la ingesta (al vuelo) como la CLI y el backfill.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.models import AffectedProduct, AffectedVersionRange, CVSSScore
from app.enrichment.cvss import _score_severity

# Alias de ecosistema -> forma canónica.
ECO_ALIAS = {
    "pip": "pypi", "pypi": "pypi",
    "cargo": "crates.io", "rust": "crates.io", "crates": "crates.io", "crates.io": "crates.io",
    "go": "go", "golang": "go",
    "npm": "npm", "node": "npm",
    "maven": "maven", "nuget": "nuget",
    "gem": "rubygems", "rubygems": "rubygems",
    "composer": "packagist", "packagist": "packagist",
    "hex": "hex", "pub": "pub", "pub.dev": "pub", "hackage": "hackage",
}
DISTRO = ("ubuntu", "debian", "alpine", "rocky", "almalinux", "suse", "opensuse",
          "red hat", "redhat", "chainguard", "wolfi", "linux", "android", "bitnami",
          "mageia", "photon", "gentoo", "oracle")


def canonical_ecosystem(eco: str | None) -> str | None:
    if not eco:
        return None
    e = eco.strip().lower()
    return ECO_ALIAS.get(e, e)


def classify_kind(ecosystem: str | None, is_malware: bool = False) -> str:
    if is_malware:
        return "malware"
    e = (ecosystem or "").strip().lower()
    if any(e.startswith(d) for d in DISTRO):
        return "distro"
    return "product"


@dataclass
class VersionRangeInput:
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    version_type: str | None = None
    raw: str | None = None


@dataclass
class AffectedInput:
    product: str
    vendor: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    kind: str | None = None
    exact_versions: list[str] | None = None
    ranges: list[VersionRangeInput] = field(default_factory=list)


def persist_affected(session: Session, candidate_id: uuid.UUID,
                     items: list[AffectedInput]) -> None:
    """Upsert de affected_products (+ rangos) para un candidate."""
    for ap in items:
        eco = canonical_ecosystem(ap.ecosystem)
        kind = ap.kind or classify_kind(ap.ecosystem)
        stmt = insert(AffectedProduct).values(
            candidate_id=candidate_id, vendor=ap.vendor, product=ap.product,
            ecosystem=eco, purl=ap.purl, kind=kind, exact_versions=ap.exact_versions,
            source="structured", created_at=datetime.now(UTC),
        ).on_conflict_do_update(
            constraint="uq_affected_candidate_product",
            set_={"ecosystem": eco, "purl": ap.purl, "kind": kind,
                  "exact_versions": ap.exact_versions},
        ).returning(AffectedProduct.id)
        ap_id = session.execute(stmt).scalar_one()
        # rangos: reemplaza los existentes de esta fila
        session.execute(
            delete(AffectedVersionRange).where(
                AffectedVersionRange.affected_product_id == ap_id)
        )
        for r in ap.ranges:
            session.add(AffectedVersionRange(
                affected_product_id=ap_id, introduced=r.introduced, fixed=r.fixed,
                last_affected=r.last_affected, version_type=r.version_type, raw=r.raw,
            ))


def persist_cvss_vectors(session: Session, candidate_id: uuid.UUID,
                         vectors: list[str], source: str) -> None:
    """Escribe cvss_scores AUTORITATIVOS a partir de vectores estructurados."""
    for vec in vectors:
        v = vec.strip().upper()   # normaliza: 'cvss:3.1/...' también válido
        if v.startswith("CVSS:4"):
            version = "4.0"
        elif v.startswith("CVSS:3.1"):
            version = "3.1"
        elif v.startswith("CVSS:3.0"):
            version = "3.0"
        else:
            continue
        score, severity = _score_severity(v, version)
        if score is None:
            continue
        session.execute(
            insert(CVSSScore).values(
                candidate_id=candidate_id, version=version, vector=v,
                base_score=score, base_severity=severity, provenance="authoritative",
                source=source, recorded_at=datetime.now(UTC),
            ).on_conflict_do_update(
                constraint="uq_cvss_candidate_version_prov_source",
                set_={"vector": v, "base_score": score, "base_severity": severity,
                      "recorded_at": datetime.now(UTC)},
            )
        )
