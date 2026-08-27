"""Tests puros del parseo OSV (rangos afectados y cap por recencia)."""

from __future__ import annotations

import json
import zipfile
from types import SimpleNamespace

import pytest

from app.sources import osv
from app.sources.osv import _affected


def test_affected_multiple_introduced_fixed_pairs():
    """Un range con varios pares introduced/fixed produce UN VersionRangeInput
    por par (antes se colapsaban en uno solo y se perdían los intermedios)."""
    rec = {"affected": [{
        "package": {"ecosystem": "PyPI", "name": "acme"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.2"},
            {"introduced": "2.0"}, {"fixed": "2.5"},
        ]}],
    }]}
    items, _ = _affected(rec, is_malware=False)
    assert len(items) == 1
    ranges = items[0].ranges
    assert len(ranges) == 2
    assert (ranges[0].introduced, ranges[0].fixed) == ("0", "1.2")
    assert (ranges[1].introduced, ranges[1].fixed) == ("2.0", "2.5")


def test_affected_last_affected_closes_range():
    rec = {"affected": [{
        "package": {"ecosystem": "Go", "name": "acme/mod"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0"}, {"last_affected": "1.9"},
        ]}],
    }]}
    items, _ = _affected(rec, is_malware=False)
    (rng,) = items[0].ranges
    assert rng.introduced == "1.0" and rng.last_affected == "1.9" and rng.fixed is None


def test_affected_single_pair_unchanged():
    rec = {"affected": [{
        "package": {"ecosystem": "PyPI", "name": "acme"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "3.1.4"},
        ]}],
    }]}
    items, _ = _affected(rec, is_malware=False)
    (rng,) = items[0].ranges
    assert rng.introduced == "0" and rng.fixed == "3.1.4"


@pytest.mark.asyncio
async def test_osv_emite_lotes_y_confirma_watermark(tmp_path, monkeypatch):
    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(5):
            rec = {
                "id": f"GHSA-aaaa-bbbb-{i:04d}",
                "published": f"2026-07-{20 + i:02d}T00:00:00Z",
                "modified": f"2026-07-{20 + i:02d}T12:00:00Z",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": f"pkg-{i}"}
                }],
            }
            zf.writestr(f"{i}.json", json.dumps(rec))

    async def cached(*args, **kwargs):
        return str(archive)

    written = {}
    monkeypatch.setattr(osv, "cached_download", cached)
    monkeypatch.setattr(osv, "read_cursor", lambda _key: None)
    monkeypatch.setattr(
        osv, "write_cursor", lambda key, value: written.update({key: value})
    )
    monkeypatch.setattr(osv, "_BATCH_SIZE", 2)

    source = osv.OsvSource()
    batches = [
        batch async for batch in source._scan_eco_batches(
            SimpleNamespace(http=object()), "PyPI", None, 0
        )
    ]
    assert [len(batch) for batch in batches] == [2, 2, 1]
    source.finalize()
    assert written["source:osv:PyPI"].startswith("2026-07-24T12:00:00")


@pytest.mark.asyncio
async def test_osv_watermark_descarta_catalogo_antiguo(tmp_path, monkeypatch):
    archive = tmp_path / "delta.zip"
    records = [
        {
            "id": "GHSA-old0-old0-old0",
            "published": "2026-07-01T00:00:00Z",
            "modified": "2026-07-27T00:00:00Z",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "old"}}],
        },
        {
            "id": "GHSA-new0-new0-new0",
            "published": "2026-07-01T00:00:00Z",
            "modified": "2026-07-28T12:01:00Z",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "new"}}],
        },
    ]
    with zipfile.ZipFile(archive, "w") as zf:
        for i, rec in enumerate(records):
            zf.writestr(f"{i}.json", json.dumps(rec))

    async def cached(*args, **kwargs):
        return str(archive)

    monkeypatch.setattr(osv, "cached_download", cached)
    monkeypatch.setattr(
        osv, "read_cursor", lambda _key: "2026-07-28T12:00:00+00:00"
    )
    source = osv.OsvSource()
    rows = [
        mention
        async for batch in source._scan_eco_batches(
            SimpleNamespace(http=object()), "PyPI", None, 0
        )
        for mention in batch
    ]
    assert [row.native_id for row in rows] == ["GHSA-new0-new0-new0"]
