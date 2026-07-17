"""Tests de normalización de nombres y del proveedor LLM mock (unit, sin BD)."""

import pytest

from app.enrichment.llm import MockProvider, _extract_json
from app.enrichment.normalize import Method, normalize_key
from app.enrichment.schema import EnrichmentOut


def test_normalize_key_basic():
    assert normalize_key("  Fortinet   FortiOS ") == "fortinet fortios"


def test_normalize_key_separators():
    assert normalize_key("Forti-OS") == "forti os"


def test_normalize_key_accents():
    assert normalize_key("Añó") == "ano"


def test_method_enum_values():
    assert Method.LLM.value == "llm"
    assert Method.UNRESOLVED.value == "unresolved"


def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_markdown_fenced():
    assert _extract_json('```json\n{"a": 2}\n```') == {"a": 2}


def test_extract_json_embedded():
    assert _extract_json('bla {"a": 3} fin') == {"a": 3}


@pytest.mark.asyncio
async def test_mock_provider_detects_rce_and_poc():
    raw = await MockProvider().complete("sys", "remote code execution, PoC public, unauthenticated")
    out = EnrichmentOut.model_validate(_extract_json(raw))
    assert out.vuln_type == "RCE"
    assert out.has_public_poc is True
    assert out.attack_vector == "network"
    assert out.requires_auth is False


@pytest.mark.asyncio
async def test_mock_provider_extracts_urls():
    raw = await MockProvider().complete("sys", "see https://poc.example/exploit and text")
    out = EnrichmentOut.model_validate(_extract_json(raw))
    assert "https://poc.example/exploit" in out.poc_urls


@pytest.mark.asyncio
async def test_mock_provider_low_confidence():
    raw = await MockProvider().complete("sys", "xss issue")
    out = EnrichmentOut.model_validate(_extract_json(raw))
    assert out.vuln_type == "XSS"
    assert out.confidence < 0.5
