"""Watermark incremental de Red Hat Security Data."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.sources import redhat_csaf


@pytest.mark.asyncio
async def test_redhat_usa_cursor_con_solape_y_lo_confirma(monkeypatch) -> None:
    params_seen = []
    cursors = {}

    class Response:
        @staticmethod
        def json():
            return []

    async def fake_get(client, url, **kwargs):
        params_seen.append(kwargs["params"])
        return Response()

    monkeypatch.setattr(
        redhat_csaf, "get_settings",
        lambda: SimpleNamespace(redhat_lookback_days=3),
    )
    monkeypatch.setattr(
        redhat_csaf, "read_cursor",
        lambda _key: "2026-07-20T15:00:00+00:00",
    )
    monkeypatch.setattr(redhat_csaf, "get", fake_get)
    monkeypatch.setattr(
        redhat_csaf, "write_cursor",
        lambda key, value: cursors.update({key: value}),
    )

    source = redhat_csaf.RedHatCSAFSource()
    assert await source.fetch(SimpleNamespace(http=object())) == []
    assert params_seen == [{"after": "2026-07-19", "per_page": 1000, "page": 1}]
    assert cursors == {}

    source.finalize()
    assert "source:redhat_csaf" in cursors
