# Sources (fetchers)

Each fetcher lives in `app/sources/<name>.py`, declares a subclass of
`BaseSource` decorated with `@register` and returns `list[FetchedMention]`. It **does
not write to the DB** (ingestion takes care of that) and **isolates itself against
failures**: if a fetcher raises an exception, the worker catches it, logs it, records
`last_error`/`last_error_at` in `sources` and continues with the rest.

---

## The `BaseSource` contract (`app/sources/base.py`)

```python
class BaseSource(abc.ABC):
    name: str = ""            # unique identifier (== sources.name)
    kind: str = ""            # human-readable description of the origin
    method: str = "api"       # api | rss | scrape | browser
    tier: int = 5             # 1..5 (early-signal priority)
    cadence_seconds: int = 3600

    @abc.abstractmethod
    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]: ...

    def seed_row(self) -> dict: ...   # row for the `sources` table
```

`FetchContext` injects the shared resources: `http` (`httpx.AsyncClient`),
`settings` and `browser` (`BrowserPool | None`).

Registration and loading:
- `@register` validates that the class has a `name`, rejects duplicates and adds it to
  `REGISTRY`.
- `load_all()` imports all modules in `app/sources/` (except `base`,
  `browser`, `runner`, `robots`) to populate `REGISTRY`.
- `sync_registry_to_db()` (`app/sources/runner.py`) creates/updates each fetcher's
  `sources` row. **`cadence_seconds` is not overwritten** on re-sync:
  it may have been tuned in operation.

### The 4 methods (`method`)

| `method` | Transport | Library |
|---|---|---|
| `api` | JSON/XML API | `httpx` |
| `rss` | RSS/Atom feed | `feedparser` |
| `scrape` | Static HTML | `httpx` + `selectolax` |
| `browser` | Requires JS | `BrowserPool` (Playwright, optional) |

---

## The 6 fetchers

| Fetcher (`name`) | Tier | `method` | Source / URL | Signal |
|---|---|---|---|---|
| `certcc_vu` | 1 | rss | `https://www.kb.cert.org/vuls/atomfeed/` | CERT/CC VU# notes; usually precede the CVE. |
| `redhat_csaf` | 2 | api | `https://access.redhat.com/hydra/rest/securitydata/cve.json` | Red Hat CVE JSON; **authoritative** CVSS. `lookback_days = 3`. |
| `nessus` | 3 | scrape | `https://www.tenable.com/plugins/nessus/newest` | Nessus plugins citing CVEs that are sometimes only RESERVED. |
| `github_advisories` | 4 | api | `https://api.github.com/advisories` | GHSA with `cve_id` + structured affected packages. |
| `github_commits` | 4 | api | `https://api.github.com` (top-N repos) | Commits citing a CVE or being a security fix without a CVE. |
| `thehackernews` | 5 | rss | `https://feeds.feedburner.com/TheHackersNews` | News; sometimes mention CVEs early (active exploitation). |

The `rss`/`scrape` fetchers often filter by the presence of `CVE-` in the text
before emitting the mention (ingestion filters the same way again).
`redhat_csaf` and `github_advisories` provide `cve_id`/`native_id` when they
know them, saving work for the ingestion regex.

The **tier** encodes the early-signal priority (1 = source that usually
gets ahead of the public CVE the most). It is used to filter in the CLI (`emerging
--tier`) and to attribute average lead per source (`stats`).

---

## `github_commits` in detail (`app/sources/github_commits.py`)

Watches the **top-N repos** on GitHub by stars and scans their commits from the
last N months looking for two signals:

1. **CVE cited** in the commit message (often reserved, not yet public) →
   mention with that `cve_id`.
2. **Security fix without a CVE** (regex `_SECFIX`: `security fix`,
   `vulnerabilit…`, `rce`, `xss`, `sqli`, `auth bypass`, `ssrf`, `deserializ`,
   `path traversal`, `buffer overflow`, `use-after-free`, `privilege
   escalation`, `out-of-bounds`…) → if `github_synthesize_candidates` is
   active, it is anchored as a **pre-CVE candidate** with
   `native_id = "GHCOMMIT:owner/repo@sha12"`, which reconciliation will merge with
   the CVE when it appears.

**Scale and incrementality** (settings with `CVERADAR_` prefix):

- `github_top_n` (default `10000`, scalable to 100k+): number of repos to watch.
- **Repo list cache** (`{data_dir}/github_top_repos.json`): built
  with `_build_repo_list` (Search API with descending star windows,
  because the Search API caps at 1000 results per query) and
  **rebuilt weekly** (rebuild if `built_at` > 7 days).
- **Rotating cursor** (`{data_dir}/github_commits_cursor.txt`): on each
  run a batch of `github_repos_per_run` (default `150`) repos is processed;
  the cursor advances modulo and *wraps*, so the crawl covers the whole
  list over several passes while respecting the rate limit.
- **Per-repo watermark** (`{data_dir}/github_repo_state.json`): `full_name → ISO
  of the last scanned commit`. Each repo's `since` is the max between the
  N-month cutoff (`github_commits_months`, default `5`) and the watermark →
  **incremental** scan. Atomic write (`.tmp` + `os.replace`).
- `github_token` (PAT) raises the rate limit to 5000 req/h.

A repo that fails does not take down the batch (`github.repo_error` and continues).

---

## `BrowserPool` (`app/sources/browser.py`)

Pool of Playwright contexts **concurrency-safe** for `method=browser`
fetchers. Playwright is an **optional** dependency (extra `browser`);
importing the module does not fail if it is not installed — it only fails when building the
pool.

Design and rationale:

- **One persistent context per source** (`launch_persistent_context` with
  its own `user-data-dir` under `{data_dir}/browser/<source>`): durable
  cookies/session and isolation between sources.
- **Per-source lock** (`asyncio.Lock` in `self._locks[source]`): never two
  concurrent fetches over the same context (Playwright contexts are **not**
  safe for concurrent use).
- **Global semaphore** (`asyncio.Semaphore(browser_max_concurrent)`, default `3`):
  bounds simultaneous pages → bounded memory.
- **Recycling** (`browser_recycle_after`, default `50`): after N uses, or on a
  crash when opening a page, the context is closed and reborn on the next attempt
  (contexts leak memory over time).

`page(source)` is an `asynccontextmanager` that combines lock + semaphore, yields an
exclusive `Page` and guarantees close + use count in the `finally`.

---

## Polite HTTP (`app/sources/http.py`)

- **Identifiable User-Agent** from `settings.user_agent`
  (`CVERadar/0.1 (+…; early-CVE research)`), without rotating IP.
- **`robots.txt`** respected (`respect_robots`, default `True`) and **cached**
  per host (`_robots_cache`). If no robots is accessible → it is allowed.
- **Retries with exponential backoff** (`tenacity`: `stop_after_attempt(3)`,
  `wait_exponential(min=1, max=20)`) over `TransportError`/`HTTPStatusError`.
- `follow_redirects=True`, timeout `http_timeout_seconds` (default `30s`).
- `get()` checks robots, does `raise_for_status()` and retries.

---

## How to add a fetcher

1. Create `app/sources/my_source.py`.
2. Subclass `BaseSource`, decorate it with `@register`, define class attributes and
   implement `fetch`.
3. Return `list[FetchedMention]`; do **not** touch the DB.
4. Register it in the table: `cveradar sources sync` (or the `sources-worker`
   startup does it). Run it with `cveradar sources run my_source`.

```python
# app/sources/example_json.py
from __future__ import annotations

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://example.org/api/recent-vulns.json"


@register
class ExampleSource(BaseSource):
    name = "example_json"
    kind = "Example vuln feed (JSON API)"
    method = "api"
    tier = 3
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        resp = await get(ctx.http, API)
        out: list[FetchedMention] = []
        for item in resp.json():
            out.append(
                FetchedMention(
                    url=item.get("url"),
                    title=item.get("title"),
                    snippet=(item.get("description") or "")[:2000],
                    cve_id=item.get("cve"),        # if you know it
                )
            )
        return out
```

Idempotency and correlation are guaranteed by the ingestion pipeline; the
fetcher only has to return clean mentions.
