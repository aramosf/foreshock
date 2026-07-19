"""Reconciliación de candidates a partir de identificadores nativos.

Etapa A de la correlación (enlace determinista): un (scheme, value) pertenece
a un solo candidate. Si una mención trae identificadores que ya apuntaban a
candidates distintos, se fusionan (union-find con tombstone reversible).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.models import AffectedProduct, Candidate, CveSoftReference, CVSSScore, Identifier
from app.core.models import Mention as MentionRow
from app.ingest.identifiers import ExtractedId, primary_cve


def find_root(session: Session, candidate_id: uuid.UUID) -> Candidate:
    """Sigue la cadena merged_into hasta el candidate raíz (ganador vivo)."""
    seen: set[uuid.UUID] = set()
    current = session.get(Candidate, candidate_id)
    assert current is not None
    while current.merged_into is not None and current.merged_into not in seen:
        seen.add(current.id)
        nxt = session.get(Candidate, current.merged_into)
        if nxt is None:
            break
        current = nxt
    return current


def _candidate_for_identifier(session: Session, eid: ExtractedId) -> Candidate | None:
    row = session.execute(
        select(Identifier).where(
            Identifier.scheme == eid.scheme, Identifier.value == eid.value
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    return find_root(session, row.candidate_id)


def _pick_winner(candidates: list[Candidate]) -> Candidate:
    """Gana el que tiene CVE; a igualdad, el visto primero (first_seen_at más antiguo)."""
    def key(c: Candidate) -> tuple[int, float]:
        has_cve = 0 if c.cve_id else 1
        ts = c.first_seen_at.timestamp() if c.first_seen_at else float("inf")
        return (has_cve, ts)

    return sorted(candidates, key=key)[0]


def merge_candidates(session: Session, winner: Candidate, loser: Candidate) -> None:
    """Fusiona loser -> winner: reasigna TODOS los hijos, marca tombstone. Reversible.

    Identifier y Mention tienen UNIQUE globales (sin candidate_id) -> reasignar es
    seguro. CVSSScore y AffectedProduct tienen UNIQUE que INCLUYE candidate_id, así
    que dos candidates pueden tener filas colisionantes: antes de reasignar, se
    borran del loser las que ya existen en el winner (evita IntegrityError).
    """
    if winner.id == loser.id:
        return

    # Tablas con UNIQUE global: reasignación directa.
    for model in (Identifier, MentionRow):
        session.execute(
            update(model)
            .where(model.candidate_id == loser.id)  # type: ignore[attr-defined]
            .values(candidate_id=winner.id)
        )

    # Tablas con UNIQUE que incluye candidate_id: elimina colisiones del loser, reasigna resto.
    for model, keycols in (
        (CVSSScore, (CVSSScore.version, CVSSScore.provenance, CVSSScore.source)),
        (AffectedProduct, (AffectedProduct.vendor, AffectedProduct.product,
                           AffectedProduct.ecosystem)),
    ):
        for loser_row in session.execute(
            select(model).where(model.candidate_id == loser.id)  # type: ignore[attr-defined]
        ).scalars():
            conflict = session.execute(
                select(model.id).where(  # type: ignore[attr-defined]
                    model.candidate_id == winner.id,  # type: ignore[attr-defined]
                    *[kc == getattr(loser_row, kc.key) for kc in keycols],
                )
            ).first()
            if conflict is not None:
                session.delete(loser_row)  # ya existe en el winner -> descarta duplicado
            else:
                loser_row.candidate_id = winner.id
    session.flush()

    # Referencias blandas: el contexto de drill-down debe apuntar al ganador vivo,
    # no al tombstone.
    session.execute(
        update(CveSoftReference)
        .where(CveSoftReference.from_candidate_id == loser.id)
        .values(from_candidate_id=winner.id)
    )

    # candidate_links no se reasignan: su UNIQUE canónico (a<b) haría colisiones y son
    # sugerencias reversibles; quedan referidas al tombstone (limpieza futura).
    session.execute(
        update(Candidate).where(Candidate.id == loser.id).values(
            merged_into=winner.id, status="merged"
        )
    )
    if winner.cve_id is None and loser.cve_id is not None:
        winner.cve_id = loser.cve_id
    _absorb_scalar_state(winner, loser)
    session.flush()


# Campos del candidate que se absorben del loser en una fusión. Política:
# el ganador conserva lo suyo; lo que tenga a None se rellena desde el loser
# (el dato se ganó con una mención real y no debe quedar enterrado en el
# tombstone). Booleanos "pegajosos" (in_kev, has_public_poc): True gana.
# Listas: unión preservando orden.
_ABSORB_FILL = (
    "kev_date", "kev_source", "withdrawn", "severity_hint", "vuln_type",
    "attack_vector", "requires_auth", "requires_interaction",
    "affected_product", "affected_versions", "enrichment_confidence",
    "enrichment_method", "enrichment_updated_at",
)
_ABSORB_STICKY_TRUE = ("in_kev", "has_public_poc")
_ABSORB_UNION = ("cwe_ids", "reference_urls", "poc_urls")


def _absorb_scalar_state(winner: Candidate, loser: Candidate) -> None:
    for attr in _ABSORB_FILL:
        if getattr(winner, attr) is None and getattr(loser, attr) is not None:
            setattr(winner, attr, getattr(loser, attr))
    for attr in _ABSORB_STICKY_TRUE:
        if getattr(loser, attr) is True:
            setattr(winner, attr, True)
    for attr in _ABSORB_UNION:
        mine, theirs = getattr(winner, attr) or [], getattr(loser, attr) or []
        if theirs:
            merged = list(dict.fromkeys([*mine, *theirs]))
            setattr(winner, attr, merged)


def resolve_candidate(session: Session, ids: list[ExtractedId]) -> Candidate:
    """Devuelve el candidate que corresponde a estos identificadores.

    - ninguno conocido -> crea candidate nuevo
    - uno -> lo usa
    - varios -> los fusiona en un ganador
    Después adjunta los identificadores que falten.
    """
    roots: dict[uuid.UUID, Candidate] = {}
    for eid in ids:
        c = _candidate_for_identifier(session, eid)
        if c is not None:
            roots[c.id] = c

    if not roots:
        candidate = Candidate(status="candidate")
        session.add(candidate)
        session.flush()
    elif len(roots) == 1:
        candidate = next(iter(roots.values()))
    else:
        candidate = _pick_winner(list(roots.values()))
        for other in roots.values():
            if other.id != candidate.id:
                merge_candidates(session, candidate, other)

    # Adjunta identificadores nuevos y fija cve_id si aparece. ON CONFLICT DO
    # NOTHING sobre el UNIQUE global (scheme, value): si otro proceso insertó el
    # mismo identifier entre nuestro SELECT y este INSERT, no reventamos el
    # savepoint de la mención entera (perderíamos la primera observación).
    existing = {
        (i.scheme, i.value)
        for i in session.execute(
            select(Identifier).where(Identifier.candidate_id == candidate.id)
        ).scalars()
    }
    new_rows = [
        {"candidate_id": candidate.id, "scheme": eid.scheme, "value": eid.value}
        for eid in ids
        if (eid.scheme, eid.value) not in existing
    ]
    if new_rows:
        session.execute(
            pg_insert(Identifier.__table__)
            .values(new_rows)
            .on_conflict_do_nothing(constraint="uq_identifiers_scheme_value")
        )
    cve = primary_cve(ids)
    if cve and candidate.cve_id is None:
        candidate.cve_id = cve
    session.flush()
    return candidate
