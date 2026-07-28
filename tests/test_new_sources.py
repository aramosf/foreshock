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


def test_nessus_usa_el_listado_vigente():
    from app.sources.nessus import LISTING

    assert LISTING == "https://www.tenable.com/plugins/newest?type=nessus"


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


def test_wordfence_cves_extrae_de_cve_y_titulo():
    from app.sources.wordfence import _cves
    assert _cves({"cve": "CVE-2026-1111"}) == ["CVE-2026-1111"]
    assert _cves({"cve": ["CVE-2026-1001", "CVE-2026-1002"]}) == ["CVE-2026-1001", "CVE-2026-1002"]
    assert _cves({"cve": None, "title": "SQLi (CVE-2026-3333)"}) == ["CVE-2026-3333"]
    assert _cves({"cve": None, "title": "sin cve"}) == []


def test_vulncheck_kev_date_convencion_fechas():
    """_kev_date: fecha real más temprana; sin fechas -> None; < 1990 -> descartada."""
    from app.sources.vulncheck_kev import _kev_date

    # fecha antigua real -> datetime UTC-aware de ese año
    dt = _kev_date({"date_added": "2013-01-15T00:00:00Z"})
    assert dt is not None and dt.year == 2013 and dt.tzinfo is not None

    # gana la MÁS temprana entre date_added y las de explotación reportada
    dt2 = _kev_date({"date_added": "2024-05-01",
                     "vulncheck_reported_exploitation": [{"date_added": "2022-02-20"}]})
    assert dt2 is not None and (dt2.year, dt2.month) == (2022, 2)

    # sin ninguna fecha -> None (la ingesta usará now())
    assert _kev_date({}) is None
    assert _kev_date({"date_added": None}) is None

    # fecha corrupta / zero-value (< 1990) -> descartada -> None
    assert _kev_date({"date_added": "0001-01-01T00:00:00Z"}) is None


def test_vulncheck_fetch_estampa_seen_at_real_no_now():
    """La FetchedMention lleva seen_at = fecha KEV real (no now()) y kev_date (Date)."""
    import asyncio

    import app.sources.vulncheck_kev as mod
    from app.sources.base import FetchContext

    page = {"data": [{"cve": ["CVE-2013-0808"],
                      "date_added": "2013-05-10T00:00:00Z",
                      "vendorProject": "Adobe", "product": "Flash"}],
            "_meta": {"total_pages": 1}}

    class _Resp:
        def json(self):
            return page

    class _Settings:
        vulncheck_token = "x"
        vulncheck_max_pages = 5
        vulncheck_api_base = "https://api.test"

    async def run():
        orig_get, orig_settings = mod.get, mod.get_settings

        async def fake_get(*a, **k):
            return _Resp()

        mod.get = fake_get
        mod.get_settings = lambda: _Settings()
        try:
            return await mod.VulnCheckKevSource().fetch(FetchContext(http=None))  # type: ignore[arg-type]
        finally:
            mod.get, mod.get_settings = orig_get, orig_settings

    ms = asyncio.run(run())
    assert len(ms) == 1
    m = ms[0]
    assert m.cve_id == "CVE-2013-0808"
    # seen_at = fecha KEV real (2013), NUNCA el momento de ingesta.
    assert m.seen_at is not None and m.seen_at.year == 2013
    # kev_date es un date (columna candidates.kev_date), igual que cisa_kev.
    assert m.flags["kev_date"].year == 2013
    assert m.flags["in_kev"] is True and m.flags["kev_source"] == "vulncheck"


def test_cisco_parse_json_multi_cve():
    import asyncio

    from app.sources.base import FetchContext
    from app.sources.cisco_psirt import CiscoPsirtSource

    class _Resp:
        def json(self):
            return [{"identifier": "cisco-sa-x", "title": "Cisco Foo",
                     "cve": "CVE-2026-1001", "summary": "y CVE-2026-1002 tambien",
                     "severity": "High", "firstPublished": "2026-06-01T00:00:00.000+0000",
                     "url": "https://cisco.test/x"}]

    class _Ctx:
        async def _get(self, *a, **k):
            return _Resp()

    async def run():
        src = CiscoPsirtSource()
        import app.sources.cisco_psirt as mod
        orig = mod.get
        mod.get = lambda *a, **k: _Ctx()._get()
        try:
            return await src.fetch(FetchContext(http=None))  # type: ignore[arg-type]
        finally:
            mod.get = orig

    ms = asyncio.run(run())
    cves = sorted(m.cve_id for m in ms)
    assert cves == ["CVE-2026-1001", "CVE-2026-1002"]
    assert ms[0].seen_at.year == 2026
