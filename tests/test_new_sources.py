"""Tests unitarios de los parsers de las nuevas fuentes (sin red ni BD)."""

from app.sources.gemnasium import GemnasiumSource, _ranges


def test_gemnasium_ranges_parsea_multi_rango():
    r = _ranges(">=5.0.0,<5.0.10||>=5.1.0,<5.1.4||>=4.2.0,<4.2.17")
    assert [(x.introduced, x.fixed) for x in r] == [
        ("5.0.0", "5.0.10"), ("5.1.0", "5.1.4"), ("4.2.0", "4.2.17")]
    assert _ranges(None) == [] and _ranges("") == []


def test_gemnasium_to_mention(tmp_path):
    yml = tmp_path / "adv.yml"
    yml.write_text(
        'identifier: "CVE-2024-53908"\n'
        'identifiers:\n- "CVE-2024-53908"\n- "GHSA-m9g8-fxxm-xg86"\n'
        'package_slug: "pypi/Django"\n'
        'title: "Django SQLi"\ndescription: "desc"\n'
        'pubdate: "2024-12-06"\n'
        'affected_range: ">=5.0.0,<5.0.10"\nfixed_versions:\n- "5.0.10"\n'
        'urls:\n- "https://example.test/a"\n', encoding="utf-8")
    from datetime import UTC, datetime
    m = GemnasiumSource._to_mention(str(yml), "pypi", datetime(2000, 1, 1, tzinfo=UTC))
    assert m is not None
    assert m.cve_id == "CVE-2024-53908"
    assert m.extra_ids == ["GHSA-m9g8-fxxm-xg86"]
    assert m.affected[0].product == "Django" and m.affected[0].ecosystem == "pypi"
    assert m.affected[0].ranges[0].fixed == "5.0.10"
    assert m.seen_at.year == 2024

    # fuera de la ventana -> None
    future = datetime(2030, 1, 1, tzinfo=UTC)
    assert GemnasiumSource._to_mention(str(yml), "pypi", future) is None


def test_kernel_cve_regex_y_producto():
    from app.sources.kernel_cve import _CVE
    assert _CVE.search("CVE-2026-64187: xfs: fix recovery").group(0) == "CVE-2026-64187"
    assert _CVE.search("sin cve aquí") is None


def test_trickest_product_y_pocs(tmp_path):
    from app.sources.poc_repos import TrickestCveSource
    md = tmp_path / "CVE-2024-4577.md"
    md.write_text(
        "### [CVE-2024-4577](https://cve.mitre.org/...)\n"
        "![](https://img.shields.io/static/v1?label=Product&message=PHP&color=blue)\n"
        "- https://github.com/foo/CVE-2024-4577\n"
        "- https://github.com/bar/poc\n", encoding="utf-8")
    m = TrickestCveSource()._parse_file(str(md), "CVE-2024-4577")
    assert m.cve_id == "CVE-2024-4577"
    assert "PHP" in (m.title or "")
    assert m.flags["has_public_poc"] is True
    assert "https://github.com/foo/CVE-2024-4577" in m.reference_urls
