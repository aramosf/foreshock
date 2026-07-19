"""Acceso al watermark persistente de los deltas baseline (tabla `sync_state`).

Una fila por fuente (`id` = 'nvd_delta', 'cvelist', ...). El `cursor` es el
último punto CONFIRMADO de la fuente (fecha ISO, SHA de git...) y SOLO debe
escribirse tras completar la pasada con éxito: así un run fallido reintenta
desde el mismo punto y no se pierden datos.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.db import session_scope
from app.core.models import SyncState


def get_cursor(session: Session, source_id: str) -> str | None:
    """Devuelve el cursor confirmado de la fuente, o None si nunca se guardó."""
    row = session.get(SyncState, source_id)
    return row.cursor if row is not None else None


def set_cursor(
    session: Session, source_id: str, cursor: str, extra: dict[str, Any] | None = None
) -> None:
    """Upsert del cursor confirmado (idempotente)."""
    now = datetime.now(UTC)
    stmt = insert(SyncState).values(
        id=source_id, cursor=cursor, extra=extra, updated_at=now
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["id"],
        set_={"cursor": stmt.excluded.cursor, "extra": stmt.excluded.extra,
              "updated_at": stmt.excluded.updated_at},
    )
    session.execute(stmt)


def read_cursor(source_id: str) -> str | None:
    """Variante autocontenida (abre su propia transacción)."""
    with session_scope() as session:
        return get_cursor(session, source_id)


def write_cursor(source_id: str, cursor: str, extra: dict[str, Any] | None = None) -> None:
    """Variante autocontenida (abre su propia transacción)."""
    with session_scope() as session:
        set_cursor(session, source_id, cursor, extra)
