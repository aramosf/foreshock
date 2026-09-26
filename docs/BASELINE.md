# Baseline — canonical state

The baseline (`app/baseline/`) maintains the **canonical truth** against which
the radar's edge is measured. Three sources feed `published_cves` and
`epss_scores`:

- **cvelistV5** — the official CVE 5.x record dump (`cvelist_*` columns);
- **NVD 2.0 delta** — NVD status/timestamps plus Foreshock's **own** first-
  observation ground truth (`nvd_*` columns);
- **EPSS** — FIRST.org exploitation-probability scores, kept as a per-date
  history.

All writes are idempotent (`INSERT ... ON CONFLICT`). The orchestrator
`app/baseline/service.py` chains the three in one isolated pass; the worker
`app/baseline/__main__.py` schedules each on its own cadence.

---

## 1. cvelistV5 (`cvelist.py`)

`cvelistV5` is maintained as a **shallow git clone** (`--depth 1`). Each run
`git pull`s and processes only the JSON files changed between the previous and
new revision (a cheap delta). On the first clone (or when forced) the whole tree
is processed.

```python
def sync_cvelist(force_full: bool = False) -> dict[str, int]
```

- **Fresh clone** (repo dir absent): `git clone --depth 1 {cvelist_repo_url}
  {cvelist_repo_dir}`, then process **all** `CVE-*.json` under `cves/`
  (`_all_json_files`).
- **Existing**: `git pull --ff-only`, then:
  - `force_full=True` → all files. A full is **auto-forced** too when the mirror
    holds no cvelist data (`mirror_has_mitre_data()` is false — e.g. the table was
    truncated) or a prior full never completed (the `full_import_complete` marker
    is absent from `sync_state.extra`);
  - else `_changed_json_files` = `git diff --name-only {cursor} HEAD`, where
    `{cursor}` is the last **successfully processed** HEAD SHA (the `cvelist` row
    in `sync_state`); with no cursor yet it falls back to the historic reflog base
    `HEAD@{1}`. Only lines under `cves/` ending in `.json` are kept;
  - if the diff fails (`CalledProcessError`, e.g. the saved SHA is gone) → fall
    back to all files.
- `_process_files` parses each JSON with `parse_cve_record` and upserts via
  `upsert_published`, in batches (commit every `_COMMIT_EVERY` = 2000 files), each
  file inside a `begin_nested()` savepoint. A bad JSON is isolated
  (`cvelist.parse_error`) and does not sink the sync. Returns
  `{files, upserted, skipped, errors}`.

`parse_cve_record(raw)` is a **pure** function (no network/DB). It extracts the
`published_cves` columns cvelist owns — `id`, `state`, `cvelist_published_at`,
`cvelist_updated_at`, `assigner_short_name`, `cna` (assigner short name, falling
back to the CNA container's `providerMetadata.shortName`), and `raw_json` — and
**never** touches `nvd_*`. `_parse_dt` yields timezone-aware datetimes.

`upsert_published(session, record)` does `INSERT ... ON CONFLICT (id) DO UPDATE`
refreshing state/cvelist dates/cna/assigner/`raw_json`/`ingested_at`; it
explicitly leaves the `nvd_*` columns alone (those are NVD's ground truth).

**Known limitation**: **deletions are not propagated.** `_changed_json_files`
returns paths that may include deletes; `_process_files` skips a path whose file
is missing (counts it as `skipped`) rather than removing the corresponding
`published_cves` row. A CVE record removed upstream therefore lingers in the DB.

---

## 2. NVD 2.0 delta (`nvd.py`)

Queries the NVD 2.0 API by **last-modified window**
(`lastModStartDate`/`lastModEndDate`) to pull the CVEs touched in the last
`hours` hours, paginating in pages of 2000.

```python
async def sync_nvd_delta(hours: int = 3) -> dict[str, int]
```

- Window: `start = now - hours`, `end = now`, `observed_at = end`.
- **Pagination**: `resultsPerPage=2000` (`_PAGE_SIZE`) + `startIndex`; advances
  by the page size and stops when `startIndex >= totalResults` (or an empty
  page).
- **Auth / rate limit**: sends the `apiKey` header if `nvd_api_key` is set;
  without a key it sleeps `_RATE_LIMIT_SLEEP = 6.0 s` between pages (public NVD
  limit).
- **Per-row isolation**: each vuln is upserted inside a `session.begin_nested()`
  savepoint, so a corrupt record (malformed date, etc.) is caught
  (`nvd.row_error`), counted as `skipped`, and does **not** abort the page or
  the rest of the delta.
- Returns `{pages, fetched, upserted, skipped}`.

**ISO-8601 with milliseconds** (`_iso_z`): NVD documents a millisecond-precision
timestamp and may reject Python's default 6-digit microseconds. `_iso_z` emits
`%Y-%m-%dT%H:%M:%S.` + a **3-digit** fraction (`microsecond // 1000`) + `Z`,
after converting to UTC and dropping tzinfo.

`parse_nvd_vuln(vuln)` is **pure**: accepts either the `{"cve": {...}}` wrapper
or the bare `cve` object, and extracts `id`, `nvd_published_at`,
`nvd_last_modified_at`, `nvd_vuln_status`.

`upsert_nvd(session, record, observed_at)` writes the `nvd_*` fields via
`INSERT ... ON CONFLICT (id) DO UPDATE`. If the CVE is not yet present it is
created with `state='PUBLISHED'`. The **own-observation ground truth** is sealed
once and never overwritten, using `COALESCE`:

- `nvd_first_observed_at = COALESCE(existing, observed_at)` — the first time we
  saw the CVE in NVD;
- `nvd_first_analyzed_observed_at = COALESCE(existing, observed_at)` **only when
  the current `vulnStatus == "Analyzed"`** — the first time we saw it Analyzed.
  On the INSERT it is set to `observed_at` only if already Analyzed, else `None`.

`nvd_published_at` is also `COALESCE`-protected; `nvd_last_modified_at`,
`nvd_vuln_status`, and `ingested_at` are refreshed on every observation. These
two first-observation fields are what let `compute_days_ahead` (see
`INGESTION.md`) measure the radar's lead over NVD.

---

## 3. EPSS (`epss.py`)

Ingests FIRST.org EPSS scores with a **per-date history**: the `epss_scores` PK
is `(cve_id, scored_date)`, so each daily snapshot is retained and the score's
evolution is queryable.

```python
async def sync_epss(cve_ids: list[str] | None = None) -> dict[str, int]
```

- **With `cve_ids`**: query `?cve=...` in batches of `_BATCH_SIZE = 100`.
- **Without**: one request for the highest-EPSS CVEs
  (`?order=!epss&limit=_RECENT_LIMIT` where `_RECENT_LIMIT = 200`).
- Each response payload is persisted by `_ingest_payload`, which reads the model
  version (`model` / `model_version`) and upserts each row. Returns
  `{requests, ingested, skipped}`.

`parse_epss_row(row)` is **pure**: returns `{cve_id, score (float), percentile
(float), scored_date (date)}`.

`upsert_epss(session, record, model_version)` does `INSERT ... ON CONFLICT
(cve_id, scored_date) DO UPDATE` refreshing `score`/`percentile`/
`model_version`/`fetched_at`. Because the PK includes the date, each day
accumulates a new snapshot instead of overwriting the previous one.

---

## 4. Orchestration & worker

### 4.1 Service (`service.py`)

```python
async def run_baseline_async(nvd_hours: int = 3, force_full_cvelist: bool = False) -> dict
def run_baseline_once(nvd_hours: int = 3, force_full_cvelist: bool = False) -> dict
```

Runs the three sources once in order — cvelist (sync `sync_cvelist`, run in a
thread via `asyncio.to_thread` so git+DB doesn't block the loop), then
`sync_nvd_delta`, then `sync_epss`. **Each source is isolated**: a failure is
logged and recorded as `{"error": ...}` without stopping the others.
`run_baseline_once` is the synchronous entry point (`asyncio.run`) for the CLI /
scheduler.

### 4.2 Worker (`__main__.py`)

The `baseline-worker` schedules each source on its own cadence with
`AsyncIOScheduler` (each `max_instances=1`):

| Job | Setting | Default |
|-----|---------|---------|
| `cvelist` | `cvelist_sync_seconds` | 900 s (15 min) |
| `nvd` | `nvd_delta_seconds` | 7200 s (2 h) |
| `epss` | `epss_sync_seconds` | 86400 s (daily) |

Each job wrapper isolates its source's exceptions. An **immediate initial pass**
of all three runs at startup, then the scheduler drives them on interval; the
process blocks on `asyncio.Event().wait()`.
