# Sources

The **sources layer** (`app/sources/`) is Foreshock's collection tier. Every fetcher
is a self-contained module that pulls signal from one upstream and hands the
pipeline a list of `FetchedMention` objects. Fetchers **never touch the
database** — persistence, deduplication, correlation and enrichment are the job
of the ingestion pipeline (`app/ingest/`, see `INGESTION.md`). A fetcher that
raises is isolated by the runner: the exception is logged, recorded on the
`sources` row, and the rest of the schedule keeps running.

This document describes the `BaseSource` contract, the five collection methods,
the **22 registered fetchers** (grouped by tier), the RSS/Atom feed framework,
the polite-HTTP layer, the Playwright browser pool, the GitHub repo watchlist /
registry, and how to add a new fetcher.

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
| `method` | `str` | One of `api` / `rss` / `scrape` / `browser` / `git`. Default `"api"`. |
| `tier` | `int` | `1..9` (CHECK, since `0009`) — signal-earliness priority (1 = earliest/highest); values in use are `1..5`. Default `5`. |
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
| `native_id` | `str \| None` | Non-CVE native id (GHSA, OSV id, ZDI-CAN, …). |
| `extra_ids` | `list[str] \| None` | Extra **declared** ids that are part of the identity and **do merge** (e.g. the other aliases of one OSV/ZDI advisory). Must **not** be used for bare CVEs merely cited in prose. |
| `raw_html` | `str \| None` | Raw content persisted to disk when provided. |
| `seen_at` | `datetime \| None` | **Real** publication time; falls back to fetch time. |
| `flags` | `dict \| None` | Whitelisted candidate flags: `in_kev`, `kev_date`, `kev_source`, `has_public_poc`. |
| `affected` | `list[AffectedInput] \| None` | Structured affected products + version ranges. |
| `cvss_vectors` | `list[str] \| None` | Authoritative CVSS vector strings. |
| `cwe_ids` | `list[str] \| None` | CWE ids → `candidates.cwe_ids`. |
| `reference_urls` | `list[str] \| None` | Reference URLs → `candidates.reference_urls` (capped at 50). |
| `withdrawn` | `bool \| None` | → `candidates.withdrawn`. |

---

## 2. The five collection methods

The `method` attribute is declarative metadata (stored on `sources.method`,
`CHECK method IN ('api','rss','scrape','browser','git')` since `0008`); it tells
operators how a fetcher collects and hints at the tooling used. There is no
dispatch on it — each `fetch()` implements its own collection.

| `method` | Tooling | Typical use |
|----------|---------|-------------|
| `api` | `httpx` against a JSON/XML API | CISA KEV, VulnCheck, Red Hat, GHSA, OSV |
| `rss` | `feedparser` over an RSS/Atom feed | 11 RSS fetchers (ZDI, CERT-EU, Siemens, Palo Alto, Spring, Fortinet, Veeam, Full Disclosure, oss-security, The Hacker News, …) |
| `scrape` | `httpx` + `selectolax` on static HTML | Nessus |
| `browser` | `BrowserPool` (Playwright, optional dependency) | JS-rendered pages (no fetcher currently uses it) |
| `git` | `git clone --filter=blob:none` + `git log` (no REST API) | `github_commits` (top-N repo commit scan) |

> `nuclei_templates` and `metasploit` declare `method="api"` but delegate to
> `scan_single_repo()`, which now also collects via a **blobless git clone**
> (§3.1) rather than the REST commits API.

---

## 3. The 22 fetchers (by tier)

Each RSS/Atom feed on tiers 1–3/5 is a **separately registered** fetcher
generated from one row of the `_FEEDS` table in `app/sources/feeds_rss.py`
(§3.3). The remaining fetchers are hand-written modules.

### Tier 1 — earliest / highest priority

| `name` | Method | Endpoint / URL | Signal | Auth |
|--------|--------|----------------|--------|------|
| `cisa_kev` | api | `cisa.gov/.../known_exploited_vulnerabilities.json` | CVEs exploited in the wild (authoritative KEV) | none |
| `vulncheck_kev` | api | `{vulncheck_api_base}/index/vulncheck-kev` | Broader/earlier KEV (~80% larger than CISA) | Bearer token (`FORESHOCK_VULNCHECK_TOKEN`) — inactive without it |
| `certcc_vu` | rss | `kb.cert.org/vuls/atomfeed/` | VU# notes, often precede the CVE | none |
| `zdi_published` | rss | `zerodayinitiative.com/rss/published/` | Published ZDI advisories (CVE + ZDI ids) | none |
| `zdi_upcoming` | rss | `zerodayinitiative.com/rss/upcoming/` | **Pre-CVE**: upcoming ZDI advisories anchored by `ZDI-CAN-*` (often no CVE yet) | none |
| `certeu` | rss | `cert.europa.eu/publications/security-advisories-rss` | CERT-EU security advisories | none |

### Tier 2 — vendor PSIRTs

| `name` | Method | Endpoint / URL | Signal | Auth |
|--------|--------|----------------|--------|------|
| `redhat_csaf` | api | `access.redhat.com/hydra/rest/securitydata/cve.json` | Recent CVEs + **authoritative** CVSS v3 vector | none |
| `siemens_cert` | rss | `cert-portal.siemens.com/productcert/rss/advisories.atom` | Siemens ProductCERT advisories | none |
| `paloalto` | rss | `security.paloaltonetworks.com/rss.xml` | Palo Alto Networks advisories | none |
| `spring_security` | rss | `spring.io/security.atom` | Spring Security advisories | none |
| `fortiguard_psirt` | rss | `fortiguard.com/rss/ir.xml` | FortiGuard PSIRT IR advisories | none |
| `veeam` | rss | `veeam.com/services/open/kb/security-feed` | Veeam security advisories | none |

### Tier 3 — exploit / detection artefacts & disclosure lists

| `name` | Method | Endpoint / URL | Signal | Auth |
|--------|--------|----------------|--------|------|
| `nessus` | scrape | `tenable.com/plugins/nessus/newest` | Plugin may cite a still-**reserved** CVE | none (browser-like headers) |
| `nuclei_templates` | api (git) | `github.com/projectdiscovery/nuclei-templates` commits | New template ≈ imminent mass exploitation | GitHub PAT recommended |
| `metasploit` | api (git) | `github.com/rapid7/metasploit-framework` commits | New exploit module = reliable exploit exists | GitHub PAT recommended |
| `fulldisclosure` | rss | `seclists.org/rss/fulldisclosure.rss` | Full Disclosure mailing list | none |
| `oss_security` | rss | `seclists.org/rss/oss-sec.rss` | oss-security mailing list | none |

### Tier 4 — advisory feeds & top-N commit scan

| `name` | Method | Endpoint / URL | Signal | Auth |
|--------|--------|----------------|--------|------|
| `github_advisories` | api | `api.github.com/advisories` | GHSA + CVE + affected packages | GitHub PAT optional (raises rate limit) |
| `github_commits` | git | blobless clone + `git log` of the watchlisted repos | CVE citations in commit messages (often reserved) | GitHub PAT (embedded in clone URL) |
| `osv` | api | `osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip` | Ecosystem advisories, rich structured data | none |

### Tier 5 — news / roundups

| `name` | Method | Endpoint / URL | Signal | Auth |
|--------|--------|----------------|--------|------|
| `thehackernews` | rss | `feeds.feedburner.com/TheHackersNews` | News, sometimes early on active campaigns | none |
| `zdi_blog` | rss | `zerodayinitiative.com/blog/?format=rss` | ZDI blog roundups (context) | none |

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
- **RSS fetchers** (`certcc_vu`, all `zdi_*`, `certeu`, the vendor PSIRTs,
  `fulldisclosure`, `oss_security`, `thehackernews`) parse the feed with
  `feedparser`, using the entry's real `published_parsed`/`updated_parsed` as
  `seen_at`. A mention is only produced if the entry contains a **recognized
  code** — see the entry→mention rule in §3.3.

### 3.1 `github_commits` in detail — blobless clone + git-log cache

`app/sources/github_commits.py` watches a **registry of GitHub repositories**
(§3.4) and scans their commits for early vulnerability signal: **commits whose
message cites a CVE** (regex `CVE-\d{4}-\d{4,7}`, case-insensitive) — often
reserved, not yet public in NVD/MITRE.

**One mention per distinct CVE** (`_mentions_from_log`): a commit message may fix
several CVEs. The scanner collects **all distinct** CVEs in the message and emits
**one mention per CVE**, each declaring a single `cve_id` and anchoring its own
candidate — a "batch of N CVEs" commit becomes N independent mentions, never a
merged block (this is the same anti-over-merge policy used across the pipeline).

**Blobless shallow clone instead of the REST API** (`_git_scan`): the old
commit-by-commit REST scan was capped at 5000 req/h. The scanner now runs

```
git clone --filter=blob:none --no-checkout --quiet --shallow-since=<YYYY-MM-DD> <url> <tmp>
git -C <tmp> log --since=<YYYY-MM-DD> --pretty=format:'%H\x1f%cI\x1f%B\x1e'
```

which downloads only commit/tree objects (no file contents) and reads messages
from a local `git log`. No API rate limit, minimal transfer. The clone is written
to a temp dir under `{data_dir}/clones` and removed in a `finally`. If a
`FORESHOCK_GITHUB_TOKEN` is set it is embedded in the clone URL
(`https://x-access-token:<token>@github.com/...`, never logged).

**Compressed git-log cache** (`_write_gitlog_cache`): after each scan the relevant
records — only commits that cite a CVE or match the `_SECFIX` security-language
regex — are gzip-written to `{cache_dir}/gitlog/<owner__repo>.log.gz` (first line
= repo name, then the `\x1e`-separated records). This is lossless for the parser
(irrelevant commits produce nothing anyway) but tiny, and lets the extraction be
**re-run without cloning** after a parser bug: `reextract_from_cache()` re-parses
every cached log with the current code (zero network). It is exposed as
`foreshock sources reextract-commits` (see `CLI.md`).

**Batch scanning** (`GitHubCommitsSource.fetch`): if the registry is empty it
bootstraps it (`harvest_references()` + `harvest_top_n()`). Each run pulls a
`next_batch(github_repos_per_run)` (default 150) of repos, ordered unscanned-first
(§3.4). Per repo, `since = max(cutoff, watermark)` where the cutoff is
`github_commits_since` (fixed, default `2026-05-01`) or a relative
`github_commits_months` (default 5) window. After scanning, the whole batch is
marked via `update_scan()` (records `last_scanned_at` and the newest committer
date as the new `watermark`) so it rotates and never re-scans the same commits. A
repo that errors is caught (`github.repo_error`) and does not sink the batch.

**No bare-commit anchoring by default.** `github_synthesize_candidates` defaults
to **`False`**, so security-fix commits *without* a CVE are **not** emitted as
synthetic `GHCOMMIT` anchors — ingestion would drop them anyway (they are not a
`RECOGNIZED_SCHEME`, see `INGESTION.md`). Only commits that cite a real CVE
produce mentions.

`scan_single_repo(...)` is the helper used by `nuclei_templates` and
`metasploit`: it scans **one** repo over an N-month window (`github_commits_months`,
default 5) with `synthesize=False`, via the same blobless clone.

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

### 3.3 RSS/Atom feed framework (`app/sources/feeds_rss.py`)

All 11 RSS/Atom fetchers are **data-driven**: a single `_FEEDS` table of
`(name, kind, tier, url)` rows, one dynamically generated `BaseSource` subclass
per row (`method="rss"`, `cadence_seconds=3600`), all registered via `register`.
Adding a feed = adding one row.

Each entry is turned into mentions by `_mentions_for_entry`, applying the same
anti-over-merge policy as the rest of the pipeline. It runs
`extract_identifiers(title, summary)`, keeps only **recognized** schemes
(`RECOGNIZED_SCHEMES` = CVE, ZDI-CAN, ZDI, VU, GHSA, MSRC, OSV), and then:

| Entry contains | Result |
|---|---|
| **exactly 1 CVE** | one mention with that `cve_id`; the entry's non-CVE recognized codes (ZDI-CAN, VU, …) ride along as `extra_ids` (same vuln, they merge). |
| **>1 CVE** | one mention **per CVE** (distinct vulns in one bulletin), each anchoring its own candidate — **no bundling**, avoids over-merge. |
| **0 CVE but a recognized code** (e.g. a `ZDI-CAN` from an "upcoming" ZDI advisory) | one mention anchored by that code as `native_id` (**pure pre-CVE**). |
| **no recognized id** | dropped (ingestion would drop it anyway). |

This is why `zdi_upcoming` yields pre-CVE candidates: an upcoming advisory
carries only a `ZDI-CAN-*`, which anchors a candidate that reconciliation merges
with the CVE once it appears.

### 3.4 GitHub repo watchlist / registry (`app/sources/repo_registry.py`)

`github_commits` no longer keeps JSON state files. It consumes the
`github_repos` table (migration `0010`, PK `full_name`), which **unifies every
discovery strategy**: a repo added by several strategies is one row (dedup by
PK), and a per-repo `watermark` guarantees no repo is re-scanned or duplicated.
`upsert_repos` de-dups on conflict, raising `priority` to the `GREATEST` and
filling missing `stars`.

Discovery strategies (each is a `harvest_*` function; `harvest_all` runs them in
order, exposed as `foreshock sources harvest-repos`):

| `origin` | Priority | Source | Enabled |
|---|---|---|---|
| `top_n` | 0 | Top-N repos by stars via the GitHub Search API, descending star windows (`stars:>=50`, then `stars:{floor}..{page_min}`), up to `github_top_n` (default 10000). **Kept — additional, not a replacement.** | always |
| `reference` | 10 | Repos cited in advisory reference URLs: `mentions.url`, `cve_reference.url`, `candidates.reference_urls[]` → `github.com/owner/repo`. | always |
| `past_cve` | 20 | Subset of `reference` whose citing candidate **already has a CVE** (higher priority). | always |
| `criticality` | 15 | OpenSSF Criticality Score CSV (any GitHub URL column). | opt-in via `FORESHOCK_CRITICALITY_CSV_URL` |
| `downloads` | 15 | Top PyPI packages by 30-day downloads → each package's project repo. | opt-in via `FORESHOCK_PYPI_DOWNLOADS_TOP_N > 0` |

`_extract_repo` normalizes a URL to `owner/repo`, skipping non-repo owner
segments (`advisories`, `sponsors`, `orgs`, `security`, …) and a trailing `.git`.

**Scan ordering** (`next_batch`): `ORDER BY last_scanned_at ASC NULLS FIRST,
priority DESC, stars DESC NULLS LAST, full_name` — never-scanned repos first,
then highest priority, then most stars. `update_scan` stamps `last_scanned_at`
and advances `watermark`.

---

## 4. Polite HTTP (`app/sources/http.py`)

All API/scrape fetchers go through this layer.

- **Identifiable User-Agent**: `make_client()` sets `settings.user_agent`
  (default `Foreshock/0.1 (+https://github.com/foreshock; early-CVE research)`),
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

Note: code paths that must not throw on a plain `4xx` (e.g. the registry's
`harvest_top_n`, which walks Search API pages) call `client.get(...)` **directly**
and branch on `resp.status_code`, bypassing `get()`'s `raise_for_status`.
`github_commits` collects via `git`, not this HTTP layer, so it is unaffected by
the API rate limit entirely.

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
  (`interval`, `seconds=cadence`, `max_instances=1`, `jitter=30`). Initial runs
  are deterministically spread across
  `FORESHOCK_SOURCES_STARTUP_SPREAD_SECONDS` (default one hour).
- `run_source()` bounds the **complete** fetch/parse/ingest lifecycle with
  `FORESHOCK_SOURCES_MAX_CONCURRENT` (default 4). Git sources also share
  `FORESHOCK_SOURCES_GIT_MAX_CONCURRENT` (default 1), and large-batch sources
  share `FORESHOCK_SOURCES_HEAVY_MAX_CONCURRENT` (default 1).
- Git children run in their own process groups and are killed **and reaped** on
  timeout or cancellation. Compose enables an init process for both workers as
  a second orphan-reaping layer.
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
