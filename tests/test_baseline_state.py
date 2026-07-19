"""Tests del área baseline: troceo de ventanas NVD, sanitización NUL,
watermarks de sync_state y enriquecimiento incremental."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.baseline.cvelist import _strip_nul
from app.baseline.nvd import _window_chunks


# ---------------------------------------------------------------------
# Puros (sin BD)
# ---------------------------------------------------------------------
def test_window_chunks_single_when_small():
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = start + timedelta(hours=3)
    assert _window_chunks(start, end) == [(start, end)]


def test_window_chunks_splits_over_120_days():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = start + timedelta(days=300)
    chunks = _window_chunks(start, end)
    assert len(chunks) == 3
    # Contiguos, sin huecos ni solapes, y cubren exactamente [start, end].
    assert chunks[0][0] == start
    assert chunks[-1][1] == end
    for (_, a_end), (b_start, _) in zip(chunks, chunks[1:]):
        assert a_end == b_start
    # Ningún tramo supera el límite de la API (120 días).
    assert all(e - s <= timedelta(days=120) for s, e in chunks)


def test_window_chunks_empty_when_start_after_end():
    now = datetime(2026, 7, 1, tzinfo=UTC)
    assert _window_chunks(now, now) == []
    assert _window_chunks(now, now - timedelta(hours=1)) == []


def test_strip_nul_removes_nul_recursively():
    raw = {
        "desc\u0000ription": "hola\u0000mundo",
        "nested": {"v": ["a\u0000", 1, None, {"k": "\u0000"}]},
        "n": 3,
    }
    clean = _strip_nul(raw)
    assert clean == {"description": "holamundo",
                     "nested": {"v": ["a", 1, None, {"k": ""}]}, "n": 3}


def test_strip_nul_keeps_clean_data_intact():
    raw = {"a": ["x", 1.5, True], "b": None}
    assert _strip_nul(raw) == raw


# ---------------------------------------------------------------------
# Integración (BD real; el esquema debe estar en head)
# ---------------------------------------------------------------------
def test_sync_state_roundtrip(db):
    from app.baseline.state import read_cursor, write_cursor
    from app.core.db import session_scope
    from app.core.models import SyncState

    # sync_state no está en el TRUNCATE del fixture: limpieza propia.
    with session_scope() as s:
        s.query(SyncState).filter(SyncState.id == "test_src").delete()

    assert read_cursor("test_src") is None
    write_cursor("test_src", "2026-07-18T00:00:00+00:00")
    assert read_cursor("test_src") == "2026-07-18T00:00:00+00:00"
    # Upsert: la segunda escritura actualiza, no duplica.
    write_cursor("test_src", "abc123", extra={"note": "sha"})
    assert read_cursor("test_src") == "abc123"

    with session_scope() as s:
        s.query(SyncState).filter(SyncState.id == "test_src").delete()


def test_enrich_all_incremental_only_touches_pending(db):
    from sqlalchemy import select

    from app.baseline.enrich import enrich_all
    from app.core.db import session_scope
    from app.core.models import PublishedCVE

    now = datetime.now(UTC)
    raw = {"containers": {"cna": {
        "providerMetadata": {"shortName": "acme"},
        "descriptions": [{"lang": "en", "value": "desc"}],
    }}}
    with session_scope() as s:
        # Ya enriquecido y sin cambios posteriores -> NO debe reprocesarse.
        s.add(PublishedCVE(id="CVE-2026-1000", state="PUBLISHED", raw_json=raw,
                           cvelist_updated_at=now - timedelta(days=2),
                           enriched_at=now - timedelta(days=1)))
        # Nunca enriquecido -> debe procesarse.
        s.add(PublishedCVE(id="CVE-2026-1001", state="PUBLISHED", raw_json=raw))
        # Re-tocado por cvelist tras el último enriquecimiento -> debe procesarse.
        s.add(PublishedCVE(id="CVE-2026-1002", state="PUBLISHED", raw_json=raw,
                           cvelist_updated_at=now,
                           enriched_at=now - timedelta(days=1)))

    stats = enrich_all()
    assert stats["processed"] == 2

    with session_scope() as s:
        rows = dict(s.execute(
            select(PublishedCVE.id, PublishedCVE.enriched_at)
        ).all())
    assert rows["CVE-2026-1000"] < now  # intacto
    assert rows["CVE-2026-1001"] is not None and rows["CVE-2026-1001"] > now
    assert rows["CVE-2026-1002"] > now

    # full=True reprocesa también el ya enriquecido.
    stats_full = enrich_all(full=True)
    assert stats_full["processed"] == 3
