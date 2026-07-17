"""Tests de cálculo/parseo CVSS y severity_hint (unit, sin BD)."""

from app.enrichment.cvss import derive_from_metrics, parse_authoritative, severity_hint
from app.enrichment.schema import CVSSMetricsOut


def test_parse_authoritative_v31():
    res = parse_authoritative("scored CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H here")
    assert len(res) == 1
    assert res[0].version == "3.1"
    assert res[0].base_score == 9.8
    assert res[0].base_severity == "CRITICAL"
    assert res[0].provenance == "authoritative"


def test_parse_authoritative_v40():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    res = parse_authoritative(f"text {v} text")
    assert res and res[0].version == "4.0"
    assert res[0].base_severity in {"CRITICAL", "HIGH"}


def test_parse_authoritative_none():
    assert parse_authoritative("sin vector") == []


def test_parse_authoritative_dedup():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert len(parse_authoritative(f"{v} y otra vez {v}")) == 1


def test_derive_full_metrics():
    m = CVSSMetricsOut(attack_vector="network", attack_complexity="low",
                       privileges_required="none", user_interaction="none",
                       scope="unchanged", confidentiality="high",
                       integrity="high", availability="high")
    res = derive_from_metrics(m)
    assert res is not None
    assert res.provenance == "derived"
    assert res.base_score == 9.8
    assert set(res.inferred_metrics) == {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


def test_derive_incomplete_returns_none():
    m = CVSSMetricsOut(attack_vector="network")  # faltan métricas
    assert derive_from_metrics(m) is None


def test_derive_none_input():
    assert derive_from_metrics(None) is None


def test_severity_hint_critical():
    assert severity_hint(vuln_type="RCE", attack_vector="network",
                         has_public_poc=True) == "likely-critical"


def test_severity_hint_scales_down():
    assert severity_hint(vuln_type="XSS", attack_vector="local",
                         has_public_poc=False) in {"likely-medium", "likely-low"}


def test_severity_hint_none_without_signal():
    assert severity_hint(vuln_type=None, attack_vector=None, has_public_poc=None) is None
