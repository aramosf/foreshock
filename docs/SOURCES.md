# Sources

The **sources layer** (`app/sources/`) is CVERadar's collection tier. Every fetcher
is a self-contained module that pulls signal from one upstream and hands the
pipeline a list of `FetchedMention` objects. Fetchers **never touch the
database** — persistence, deduplication, correlation and enrichment are the job
of the ingestion pipeline (`app/ingest/`, see `INGESTION.md`). A fetcher that
raises is isolated by the runner: the exception is logged, recorded on the
`sources` row, and the rest of the schedule keeps running.

This document describes the `BaseSource` contract, the four collection methods,
the eleven registered fetchers, the polite-HTTP layer, the Playwright browser
pool, and how to add a new fetcher.

---

## 1. The `BaseSource` contract

Defined in `app/sources/base.py`. Each fetcher lives in
`app/sources/<name>.py` and declares a `BaseSource` subclass decorated with
`@register`.

### 1.1 Class attributes

| Attribute | Type | Meaning |
|-----------|------|---------|
| `name` | `str` | Unique identifier; equals `sources.name`. Required — `@register` raises if empty. |
| `kind` | `str` | Human-readable description of the origin. |
| `method` | `str` | One of `api` / `rss` / `scrape` / `browser`. Default `"api"`. |
| `tier` | `int` | `1..5` — signal-earliness priority (1 = earliest/highest). Default `5`. |
| `cadence_seconds` | `int` | Default poll interval. Default `3600`. |

### 1.2 The abstract method

```python
@abc.abstractmethod
async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
    ...
```

`fetch` is the only method a subclass **must** implement. It returns new
mentions; **idempotency is guaranteed downstream by ingestion**, so a fetcher
may freely re-return items it has returned before (a repeated listing hashes to
the same `content_hash` and is deduplicated — see `INGESTION.md`).

### 1.3 `FetchContext` — injected shared resources

```python
@dataclass
class FetchContext:
    http: "httpx.AsyncClient"                 # polite shared client (from make_client)
    settings: Settings = field(default_factory=get_settings)
    browser: "BrowserPool | None" = None      # only for method == "browser"
```

The runner builds one `FetchContext` per run and injects the shared HTTP
client. `browser` is `None` unless a browser pool has been provisioned.

### 1.4 `seed_row()`

Returns the row written to the `sources` table by
`runner.sync_registry_to_db()`:

```python
{"name", "kind", "method", "tier", "cadence_seconds"}
```

### 1.5 Registration and discovery

- `@register` validates `name` is set, rejects duplicates, and stores the class
  in the global `REGISTRY: dict[str, type[BaseSource]]`.
- `load_all()` imports every module under `app.sources` (skipping the framework
  modules `base`, `browser`, `runner`, `robots`) so their `@register`
  decorators populate `REGISTRY`, then returns it.

### 1.6 The `FetchedMention` output object

Defined in `app/ingest/service.py`; fully described in `INGESTION.md`. Fields:

| Field | Type | Purpose |
|-------|------|---------|
| `url` | `str \| None` | Source URL (also mined for identifiers, canonicalized for hashing). |
| `title` | `str \| None` | Short title. |
| `snippet` | `str \| None` | Body/summary text (fetchers cap at 2000 chars). |
| `cve_id` | `str \| None` | CVE if the fetcher already knows it. |
| `native_id` | `str \| None` | Non-CVE native id (GHSA, OSV id, `GHCOMMIT:...`, ZDI-CAN, …). |
| `raw_html` | `str \| None` | Raw content persisted to disk when provided. |
| `seen_at` | `datetime \| None` | **Real** publication time; falls back to fetch time. |
| `flags` | `dict \| None` | Whitelisted candidate flags: `in_kev`, `kev_date`, `kev_source`, `has_public_poc`. |
| `affected` | `list[AffectedInput] \| None` | Structured affected products + version ranges. |
| `cvss_vectors` | `list[str] \| None` | Authoritative CVSS vector strings. |
| `cwe_ids` | `list[str] \| None` | CWE ids → `candidates.cwe_ids`. |
| `reference_urls` | `list[str] \| None` | Reference URLs → `candidates.reference_urls` (capped at 50). |
| `withdrawn` | `bool \| None` | → `candidates.withdrawn`. |

---

## 2. The four collection methods

The `method` attribute is declarative metadata (stored on `sources.method`); it
tells operators how a fetcher collects and hints at the tooling used. There is
no dispatch on it — each `fetch()` implements its own collection.

| `method` | Tooling | Typical use |
|----------|---------|-------------|
| `api` | `httpx` against a JSON/XML API | CISA KEV, VulnCheck, Red Hat, GHSA, OSV, GitHub commits |
| `rss` | `feedparser` over an RSS/Atom feed | CERT/CC, The Hacker News |
| `scrape` | `httpx` + `selectolax` on static HTML | Nessus |
| `browser` | `BrowserPool` (Playwright, optional dependency) | JS-rendered pages (no fetcher currently uses it) |

---

## 3. The eleven fetchers

| # | `name` | Tier | Method | Endpoint / URL | Signal | Auth | Pagination |
|---|--------|------|--------|----------------|--------|------|------------|
| 1 | `cisa_kev` | 1 | api | `cisa.gov/.../known_exploited_vulnerabilities.json` | CVEs exploited in the wild (authoritative KEV) | none | none (single JSON) |
| 2 | `vulncheck_kev` | 1 | api | `{vulncheck_api_base}/index/vulncheck-kev` | Broader/earlier KEV (~80% larger than CISA) | Bearer token (`CVERADAR_VULNCHECK_TOKEN`) — inactive without it | `page`/`limit=100`, stops at `_meta.total_pages`, cap `vulncheck_max_pages` (50) |
| 3 | `certcc_vu` | 1 | rss | `kb.cert.org/vuls/atomfeed/` | VU# notes, often precede the CVE | none | none (single feed) |
| 4 | `redhat_csaf` | 2 | api | `access.redhat.com/hydra/rest/securitydata/cve.json` | Recent CVEs + **authoritative** CVSS v3 vector | none | `after`+`per_page=1000`+`page`, stops on short page, cap `max_pages=20` |
| 5 | `nessus` | 3 | scrape | `tenable.com/plugins/nessus/newest` | Plugin may cite a still-**reserved** CVE | none (browser-like headers) | none (single listing) |
| 6 | `nuclei_templates` | 3 | api | `github.com/projectdiscovery/nuclei-templates` commits | New template ≈ imminent mass exploitation | GitHub PAT recommended | commit `Link` header, cap `github_commits_max_pages` |
| 7 | `metasploit` | 3 | api | `github.com/rapid7/metasploit-framework` commits | New exploit module = reliable exploit exists | GitHub PAT recommended | commit `Link` header, cap `github_commits_max_pages` |
| 8 | `github_advisories` | 4 | api | `api.github.com/advisories` | GHSA + CVE + affected packages | GitHub PAT optional (raises rate limit) | `Link` header cursor, cap `github_advisories_max_pages` (30) |
| 9 | `github_commits` | 4 | api | `api.github.com` top-N repos commits | CVE citations + pre-CVE security fixes | GitHub PAT (5000 req/h) | per-repo commit `Link` header + repo rotation cursor |
| 10 | `osv` | 4 | api | `osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip` | Ecosystem advisories, rich structured data | none | per-ecosystem `all.zip`, cap `osv_max_per_ecosystem` (3000) |
| 11 | `thehackernews` | 5 | rss | `feeds.feedburner.com/TheHackersNews` | News, sometimes early on active campaigns | none | none (single feed) |

Notes that apply broadly:

- **KEV fetchers (`cisa_kev`, `vulncheck_kev`)** set `flags={"in_kev": True,
  "kev_date": <date>, "kev_source": "cisa"|"vulncheck"}`. `in_kev` is the
  highest-priority signal and the ground-truth label for "did it enter KEV".
- **`redhat_csaf`** places the CVSS vector into the snippet
  (`... | CVSS: <vector>`); the enrichment layer extracts it as authoritative
  (it does not use the structured `cvss_vectors` field). The Red Hat `severity`
  is prefixed as `[severity] description`.
- **`vulncheck_kev`** fans one KEV record with multiple `cve` values into one
  mention per CVE.
- **`github_advisories`** attaches `native_id=ghsa_id`, `cve_id=cve` (if
  assigned), and folds affected packages (`ecosystem:name range`) into the
  snippet (`... | affected: ...`).
- **`certcc_vu` / `thehackernews`** parse the feed with `feedparser`, using the
  entry's real `published_parsed`/`updated_parsed` as `seen_at`. `thehackernews`
  keeps only entries whose title+summary contain `CVE-`.

### 3.1 `github_commits` in detail

`app/sources/github_commits.py` watches the **top-N GitHub repositories by
stars** and scans their commits for two kinds of early vulnerability signal:

1. **Commits citing a CVE** (regex `CVE-\d{4}-\d{4,7}`, case-insensitive) —
   often reserved, not yet public in NVD/MITRE → mention carries that `cve_id`.
2. **Security-fix commits with no CVE** (regex `_SECFIX`: `security fix`,
   `vulnerabilit`, `remote code execution`, `rce`, `xss`, `sql injection`,
   `sqli`, `auth bypass`, `ssrf`, `deserializ`, `path traversal`, `arbitrary
   code/file`, `buffer overflow`, `use-after-free`, `privilege escalation`,
   `out-of-bounds`) → anchored as a **pre-CVE candidate** via the synthetic id
   `GHCOMMIT:owner/repo@<sha12>` (`native_id`), which reconciliation can later
   merge with the CVE when it appears. Only emitted when `synthesize` is on.

**Top-N repo list — star windowing + weekly cache** (`_build_repo_list`): the
GitHub Search API caps results at 1000 per query, so the list is built with
**descending star windows**. Starting from `stars:>=50` (floor is 50 stars), it
paginates 10 pages × 100 = 1000 per window, records the minimum star count seen
(`page_min`), then opens the next window `stars:{floor}..{page_min}` below it,
until `github_top_n` (default 10000) repos are collected. The result is cached to
`{data_dir}/github_top_repos.json` with a `built_at` timestamp; it is rebuilt
weekly, or eagerly if the cached list is shorter than the requested
`github_top_n` (lets you raise the setting without deleting the cache).

**Incremental crawl — cursor + per-repo watermark**: each run processes a
**rotating batch** of `github_repos_per_run` (default 150) repos to respect the
rate limit. The batch start is a cursor persisted at
`{data_dir}/github_commits_cursor.txt`; it advances by `github_repos_per_run mod
len(repos)` each run and **wraps** around the list (the tail wraps to the head
so no repo is skipped). A per-repo **watermark** map
(`{data_dir}/github_repo_state.json`, `full_name -> ISO of newest committer date
scanned`, written atomically via a `.tmp` file + `os.replace`) makes each scan
incremental: `since = max(N-month cutoff, watermark[repo])`.

**Commit pagination via the `Link` header** (`_scan_repo`): GitHub returns the
newest commits first, 100 per page. Without paginating, a repo with more than
100 commits in the window would silently lose the rest forever (the watermark
would jump straight to the newest). `_scan_repo` therefore follows
`resp.links["next"]["url"]` up to `github_commits_max_pages` (default 10) pages,
tracking the newest committer date seen to return as the new watermark. A repo
that errors is caught (`github.repo_error`) and does not sink the batch.

`scan_single_repo(...)` is the helper used by `nuclei_templates` and
`metasploit`: it scans **one** repo over an N-month window
(`github_commits_months`, default 5) with `synthesize=False`, so those fetchers
only emit commits that already cite a CVE (no synthetic GHCOMMIT noise). The
global `github_synthesize_candidates` (default `True`) controls synthesis for the
top-N `github_commits` fetcher.

### 3.2 `osv` in detail

`app/sources/osv.py` follows the project rule **"OSV before scraping GHSA"**.
It downloads each ecosystem's `all.zip` dump, filters by real publication date,
and extracts everything usable per advisory.

**Ecosystems**: configured via `osv_ecosystems` (default 5:
`PyPI,Go,crates.io,RubyGems,Packagist`). The ingestion canonicalizer
(`app/ingest/affected.py`, `ECO_ALIAS`) recognizes 13 canonical ecosystems —
`pypi`, `crates.io`, `go`, `npm`, `maven`, `nuget`, `rubygems`, `packagist`,
`hex`, `pub`, `hackage` (plus aliases such as `pip`, `cargo`, `rust`, `node`,
`gem`, `composer`, `golang`). Any ecosystem name OSV emits is accepted and
normalized.

**Streaming `all.zip` to disk** (`_scan_eco`): the large dumps (npm/Debian) are
hundreds of MB; buffering them in RAM (`resp.content` + `BytesIO`) risks OOM.
Instead the response is **streamed to a `NamedTemporaryFile`** with a 300 s
timeout, then `zipfile.ZipFile` reads entries lazily from disk. The temp file is
always unlinked in a `finally`. Per-ecosystem output is capped at
`osv_max_per_ecosystem` (default 3000). An ecosystem that errors is isolated
(`osv.eco_error`) and does not sink the whole source.

**Publication-window filter** (`_to_mention`): uses `published` (real date),
falling back to `modified`; records published before the `osv_months` (default
5) cutoff are dropped.

**Rich extraction** per record:

- **Multiple aliases**: `_cve_alias` picks the first `CVE-*` alias as `cve_id`;
  the OSV id becomes `native_id`; remaining aliases (GHSA, etc.) go into the
  snippet as `aliases: ...` (the regex extractor then anchors them as
  identifiers too).
- **`severity` → CVSS** (`_cvss_vectors`): collects top-level `severity[].score`
  and per-`affected[].severity[].score` strings that start with `CVSS:` (v3/v4),
  deduplicated preserving order → `cvss_vectors` → **authoritative** CVSS scores.
- **`affected[]` + purl + ranges** (`_affected`): for each affected package it
  builds an `AffectedInput(product, ecosystem, purl, kind, exact_versions,
  ranges)`. Ranges are folded from OSV `events` (`introduced` / `fixed` /
  `last_affected`, with `version_type`) into `VersionRangeInput`. It also emits
  `eco:name <fixed` labels for the snippet.
- **CWE** (`_cwe_ids`): `database_specific.cwe_ids` (or `cwes`) → `cwe_ids`.
- **references** (`_references`): `references[].url` → `reference_urls`.
- **`withdrawn`**: presence of the `withdrawn` field → `withdrawn=True`.
- **`MAL-` → malware**: an OSV id starting with `MAL-` sets `is_malware=True`,
  so `classify_kind` tags the affected products as `malware` rather than
  `product`/`distro`.

---

## 4. Polite HTTP (`app/sources/http.py`)

All API/scrape fetchers go through this layer.

- **Identifiable User-Agent**: `make_client()` sets `settings.user_agent`
  (default `CVERadar/0.1 (+https://github.com/cveradar; early-CVE research)`),
  `follow_redirects=True`, and `settings.http_timeout_seconds` (30 s).
- **robots.txt** (`allowed_by_robots`): when `settings.respect_robots` is true
  (default), the per-host `robots.txt` is fetched once and cached in
  `_robots_cache`; a `PermissionError` is raised for disallowed URLs. If
  `robots.txt` is unreachable the host is treated as allow-all.
- **Retries only on transient failures** (`_is_transient`): the `@retry`
  wrapper (tenacity, `stop_after_attempt(3)`, exponential backoff `1..20 s`,
  `reraise=True`) retries **only**:
  - transport errors (`httpx.TransportError`), and
  - HTTP `429` or `>= 500`.

  **Permanent `4xx` (400/401/403/404) are NOT retried** — retrying is useless
  and worsens rate limiting (e.g. a secondary GitHub `403`). `get()` runs the
  robots check, then `client.get(...)`, then `raise_for_status()`.

Note: fetchers that must not throw on a plain `4xx` (e.g. `github_commits`
`_scan_repo`, `_build_repo_list`) call `client.get(...)` **directly** and branch
on `resp.status_code`, bypassing `get()`'s `raise_for_status`.

---

## 5. `BrowserPool` (`app/sources/browser.py`)

A concurrency-safe pool of Playwright persistent contexts for `browser`-method
fetchers. Playwright is an **optional** dependency (extra `browser`): importing
the module is fine, but `start()` imports `playwright.async_api` lazily, so the
package still imports without Playwright installed.

Design:

- **One persistent context per source** (own `user-data-dir` under
  `{data_dir}/browser/<source>`) → durable cookies/session and isolation between
  sources.
- **Per-source lock** (`_locks[source]`): Playwright contexts are **not**
  concurrency-safe, so never two concurrent fetches over the same context.
- **Global semaphore** (`_global`, size `browser_max_concurrent`, default 3):
  caps simultaneous pages to bound memory.
- **Recycling** (`_recycle`): a context is closed and dropped after
  `browser_recycle_after` uses (default 50) — contexts leak memory — or
  immediately on a crash (respawned on the next attempt).

`page(source)` is an async context manager: it takes the per-source lock **and**
the global semaphore, acquires/creates the context, yields a fresh `Page`, then
on exit closes the page, increments the use counter, and recycles if the
threshold is reached. `close()` recycles all contexts and stops Playwright.

---

## 6. Execution & scheduling

### 6.1 Runner (`app/sources/runner.py`)

- `sync_registry_to_db()`: upserts a `sources` row for every registered fetcher.
  On update it refreshes `kind`, `method`, `tier` but **never overwrites
  `cadence_seconds`** (may have been tuned in operation).
- `run_source(name)`: runs one fetcher once and **never propagates a fetch
  exception**. A failing `fetch()` is caught, logged (`source.fetch_error`), and
  recorded on the row (`last_error`, `last_error_at`); it returns zeroed stats.
  On success, each mention is ingested inside a **per-mention
  `session.begin_nested()` savepoint** so one bad mention neither rolls back the
  batch nor loses the valid ones; it tracks `fetched`/`created`/`duplicate`/
  `errors` and stamps `last_success_at`.

### 6.2 Worker (`app/sources/__main__.py`)

The `sources-worker` runs enabled fetchers on their cadences with
`AsyncIOScheduler`:

- On startup it calls `sync_registry_to_db()` and schedules every enabled source
  (`interval`, `seconds=cadence`, `max_instances=1`, `jitter=30`).
- **Hot reconcile** (`_reconcile_jobs`, re-run every 60 s via the `_reconcile`
  job): it re-reads the `sources` table and reconciles scheduler jobs with it —
  **adds** newly enabled sources, **removes** disabled ones, and **reschedules**
  when `cadence_seconds` changed. This makes enable/disable and cadence tuning
  take effect **hot**, without restarting the worker.

---

## 7. How to add a fetcher

Create `app/sources/<name>.py`, declare a `@register` subclass, and return
`FetchedMention`s. `load_all()` discovers it automatically; the worker seeds it
into `sources` on next startup (enabled by default).

```python
from __future__ import annotations

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention
from app.ingest.affected import AffectedInput, VersionRangeInput

@register
class MyVendorSource(BaseSource):
    name = "my_vendor"
    kind = "My Vendor security advisories (API)"
    method = "api"          # api | rss | scrape | browser
    tier = 2
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        resp = await get(ctx.http, "https://vendor.example/advisories.json")
        out: list[FetchedMention] = []
        for adv in resp.json():
            out.append(
                FetchedMention(
                    url=adv["url"],
                    title=adv["title"][:200],
                    snippet=adv["summary"][:2000],
                    cve_id=adv.get("cve"),          # if known
                    native_id=adv.get("advisory_id"),
                    seen_at=None,                    # real publish time if you have it
                    # --- structured extras (all optional) ---
                    flags={"in_kev": False, "has_public_poc": True},
                    cvss_vectors=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
                    cwe_ids=["CWE-79"],
                    reference_urls=[adv["url"]],
                    withdrawn=False,
                    affected=[
                        AffectedInput(
                            product="acme-lib",
                            ecosystem="PyPI",
                            purl="pkg:pypi/acme-lib",
                            exact_versions=["1.0.0"],
                            ranges=[VersionRangeInput(introduced="0", fixed="1.0.1")],
                        )
                    ],
                )
            )
        return out
```

Guidance:

- Only `name` and `fetch` are strictly required; set `tier`/`method`/`cadence`
  to describe the source.
- Do the minimum in the fetcher: return raw-ish mentions. Identifier
  extraction, hashing, correlation, CVSS scoring and canonicalization all happen
  in ingestion/enrichment.
- Prefer `get()` for polite retries/robots. Only call `ctx.http.get()` directly
  when you must branch on non-transient status codes yourself.
- The structured fields (`flags`, `cvss_vectors`, `cwe_ids`, `reference_urls`,
  `withdrawn`, `affected`) are applied to the **candidate** on both the new-
  mention and duplicate-mention paths (see `INGESTION.md`), so re-emitting a
  record that newly carries `in_kev` or products still takes effect.
- Populate `seen_at` with the **real** publication time whenever the upstream
  provides it — the days-ahead metric depends on it.
