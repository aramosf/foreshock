"""Tests puros del parser de enriquecimiento (CVE JSON 5.0 -> Enrichment)."""

from __future__ import annotations

from app.baseline.enrich import parse_record


def _record(cna=None, adp=None):
    containers = {}
    if cna is not None:
        containers["cna"] = cna
    if adp is not None:
        containers["adp"] = adp
    return {"dataType": "CVE_RECORD", "containers": containers}


def test_parse_cna_cvss_cwe_refs_desc():
    raw = _record(cna={
        "providerMetadata": {"shortName": "talos"},
        "metrics": [{"cvssV3_0": {
            "version": "3.0", "baseScore": 7.5, "baseSeverity": "HIGH",
            "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}],
        "problemTypes": [{"descriptions": [
            {"lang": "en", "type": "CWE", "cweId": "CWE-79", "description": "XSS"}]}],
        "references": [
            {"url": "https://x/exploit", "tags": ["exploit"]},
            {"url": "https://x/patch", "tags": ["patch"]},
        ],
        "descriptions": [{"lang": "en", "value": "A denial-of-service issue."}],
        "affected": [{"vendor": "acme", "product": "web",
                      "cpes": ["cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"]}],
    })
    e = parse_record("CVE-2026-0001", raw)
    assert e.primary_cvss_version == "3.0"
    assert e.primary_cvss_score == 7.5
    assert e.primary_cvss_severity == "HIGH"
    assert e.primary_cwe == "CWE-79"
    assert e.description_en == "A denial-of-service issue."
    assert e.has_exploit_ref is True
    assert e.has_patch_ref is True
    assert len(e.references) == 2
    assert len(e.cpe) == 1
    assert e.cpe[0]["cpe23"].startswith("cpe:2.3:a:acme:web")


def test_parse_adp_ssvc():
    raw = _record(cna={"providerMetadata": {"shortName": "acme"}}, adp=[{
        "title": "CISA ADP Vulnrichment",
        "providerMetadata": {"shortName": "CISA-ADP"},
        "metrics": [{"other": {"type": "ssvc", "content": {"options": [
            {"Exploitation": "active"},
            {"Automatable": "yes"},
            {"Technical Impact": "total"},
        ]}}}],
    }])
    e = parse_record("CVE-2026-0002", raw)
    assert e.ssvc_exploitation == "active"
    assert e.ssvc_automatable == "yes"
    assert e.ssvc_technical_impact == "total"


def test_primary_prefers_higher_version_and_cna():
    raw = _record(
        cna={
            "providerMetadata": {"shortName": "acme"},
            "metrics": [
                {"cvssV3_1": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM",
                              "vectorString": "v31"}},
                {"cvssV4_0": {"version": "4.0", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                              "vectorString": "v40"}},
            ],
        },
        adp=[{"providerMetadata": {"shortName": "CISA-ADP"},
              "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 8.0,
                                        "baseSeverity": "HIGH", "vectorString": "adp31"}}]}],
    )
    e = parse_record("CVE-2026-0003", raw)
    # v4.0 de la CNA gana sobre v3.1 y sobre el ADP.
    assert e.primary_cvss_version == "4.0"
    assert e.primary_cvss_score == 9.8
    assert len(e.cvss) == 3  # 2 CNA + 1 ADP, todas conservadas en detalle


def test_empty_and_none_are_safe():
    assert parse_record("CVE-X", None).cvss == []
    assert parse_record("CVE-X", {}).primary_cvss_score is None
    assert parse_record("CVE-X", {"containers": {}}).primary_cwe is None
