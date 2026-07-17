# Baseline — canonical state

The baseline maintains the **canonical truth** against which the radar's edge is
measured: `published_cves` (cvelistV5 + NVD 2.0) and `epss_scores` (FIRST.org).
It is orchestrated by the `baseline-worker` (`app/baseline/__main__.py`) with
APScheduler, and `app/baseline/service.py` provides a single chained pass.

The three sources are **idempotent** (`INSERT … ON CONFLICT`) and **isolated**:
the failure of one does not prevent the others.

```python
# app/baseline/service.py
async def run_baseline_async(nvd_hours=3, force_full_cvelist=False) -> dict
def run_baseline_once(nvd_hours=3, force_full_cvelist=False) -> dict  # asyncio.run(...)
```

`sync_cvelist` is synchronous (git + DB) and runs in a thread
(`asyncio.to_thread`); NVD and EPSS are async.

---

## cvelistV5 (`app/baseline/cvelist.py`)

A **shallow git clone** (`--depth 1`) of the official `CVEProject/cvelistV5`
repo. On each run it does `git pull --ff-only` and processes **only the changed
JSON files** between the previous revision and the new one (cheap delta); on the
first clone, or with `force_full`, it processes all of them.

```python
def sync_cvelist(force_full: bool = False) -> dict[str, int]
def parse_cve_record(raw: dict) -> dict        # PURA: JSON CVE 5.x -> columnas
def upsert_published(session, record) -> None  # ON CONFLICT (id) DO UPDATE
```

- `parse_cve_record` is **pure and testable** (no network, no DB): it extracts
  `id`, `state`, `cvelist_published_at`, `cvelist_updated_at`,
  `assigner_short_name`, `cna`, `raw_json`. It **never** touches `nvd_*` fields.
- `_changed_json_files` uses `git diff --name-only HEAD@{1} HEAD` filtering
  `cves/**.json`. If there is no previous revision, it falls back to
  `_all_json_files` (rglob of `CVE-*.json`).
- `upsert_published` updates cvelist state/dates, cna, raw_json, ingested_at and
  does **not** overwrite the `nvd_*` fields. A bad JSON does not take down the
  sync (`cvelist.parse_error`).

Cadence: `CVERADAR_CVELIST_SYNC_SECONDS` (default `900` = 15 min). Directory:
`CVERADAR_CVELIST_REPO_DIR` (default `/data/cvelistV5`).

---

## NVD 2.0 delta + own observation (`app/baseline/nvd.py`)

Queries the NVD 2.0 API filtering by last-modification window
(`lastModStartDate`/`lastModEndDate`) to bring in the CVEs touched in the last
`hours` hours, paginating in batches of 2000 (`resultsPerPage`/`startIndex`).

```python
async def sync_nvd_delta(hours: int = 3) -> dict[str, int]
def parse_nvd_vuln(vuln: dict) -> dict          # PURA: item -> campos nvd_*
def upsert_nvd(session, record, observed_at) -> None
```

- `parse_nvd_vuln` (**pure**) extracts `id`, `nvd_published_at`,
  `nvd_last_modified_at`, `nvd_vuln_status`. It accepts both `{"cve": {...}}` and
  the `cve` object directly.
- **Observation ground truth** — the radar's differential value:
  - `nvd_first_observed_at = COALESCE(existing, observed_at)`: set the **first**
    time we see the CVE in NVD and **not overwritten** afterwards. Immune to NVD
    date backfill.
  - `nvd_first_analyzed_observed_at`: the same, but only sealed when we observe
    `vulnStatus == 'Analyzed'`.
  - `observed_at = end` (now) is our own clock.
- If the CVE does not yet exist in `published_cves`, it is created with
  `state='PUBLISHED'`.
- Without `apiKey`, it respects the public rate limit with a `6s` pause between
  pages (`_RATE_LIMIT_SLEEP`); with `CVERADAR_NVD_API_KEY` it sends the `apiKey`
  header and does not wait.

Cadence: `CVERADAR_NVD_DELTA_SECONDS` (default `7200` = 2 h). These timestamps
feed `days_ahead_vs_nvd_present` / `_analyzed` (see `ARCHITECTURE.md`).

---

## EPSS (`app/baseline/epss.py`)

Ingests EPSS scores from FIRST.org **with history**: the PK of `epss_scores` is
`(cve_id, scored_date)`, so each daily snapshot is preserved and the score's
evolution is visible.

```python
async def sync_epss(cve_ids: list[str] | None = None) -> dict[str, int]
def parse_epss_row(row: dict) -> dict           # PURA: fila data[] -> columnas
def upsert_epss(session, record, model_version) -> None
```

- `parse_epss_row` (**pure**) extracts `cve_id`, `score`, `percentile`,
  `scored_date`.
- With `cve_ids`: queries filtering by `?cve=…` in batches of 100
  (`_BATCH_SIZE`). Without them: the first page of the highest-EPSS ones
  (`?order=!epss&limit=200`, `_RECENT_LIMIT`).
- `upsert_epss` does `ON CONFLICT (cve_id, scored_date) DO UPDATE`; because the
  PK includes the date, it accumulates snapshots instead of overwriting.

Cadence: `CVERADAR_EPSS_SYNC_SECONDS` (default `86400` = daily). The
`epss_current` view exposes the most recent snapshot per CVE.
