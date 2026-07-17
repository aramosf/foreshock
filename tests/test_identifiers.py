"""Tests de extracción de identificadores (unit, sin BD)."""

from app.ingest.identifiers import extract_identifiers, primary_cve, primary_native


def test_extract_cve():
    ids = extract_identifiers("Fix for CVE-2026-1234")
    assert [(i.scheme, i.value) for i in ids] == [("CVE", "CVE-2026-1234")]


def test_extract_multiple_priority_order():
    ids = extract_identifiers("CVE-2026-1234 relates to ZDI-CAN-26123 and VU#987654")
    schemes = [i.scheme for i in ids]
    assert schemes == ["CVE", "ZDI-CAN", "VU"]


def test_cve_case_insensitive_and_canonical():
    ids = extract_identifiers("cve-2026-0001")
    assert ids[0].value == "CVE-2026-0001"


def test_dedup_same_id():
    ids = extract_identifiers("CVE-2026-0001 CVE-2026-0001", "CVE-2026-0001")
    assert len(ids) == 1


def test_ghsa_canonical_form():
    ids = extract_identifiers("GHSA-JFH8-C2JP-5V3Q advisory")
    assert ids[0].scheme == "GHSA"
    assert ids[0].value == "GHSA-jfh8-c2jp-5v3q"


def test_ghcommit_preserved_case():
    ids = extract_identifiers("GHCOMMIT:Acme/Lib@ABC1234def")
    assert ids[0].scheme == "GHCOMMIT"
    assert ids[0].value == "GHCOMMIT:Acme/Lib@ABC1234def"


def test_primary_cve_and_native():
    ids = extract_identifiers("CVE-2026-1234 ZDI-CAN-26123")
    assert primary_cve(ids) == "CVE-2026-1234"
    assert primary_native(ids) == "ZDI-CAN-26123"


def test_no_identifiers():
    assert extract_identifiers("nada relevante aquí") == []


def test_native_none_when_only_cve():
    ids = extract_identifiers("CVE-2026-1234")
    assert primary_native(ids) is None
