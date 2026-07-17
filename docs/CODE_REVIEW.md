# Code review

Summary of the adversarial review of CVERadar and the fixes it produced. The
bulk of the correctness fixes landed in commit `1f0809b` ("fix: correctness bugs
from full code review"); the OSV `published`-window fix and rich-persistence work
are `e46bff9` / `671cf9d`. Deferred items are things the review identified but
consciously left for later, with the reason.

Severity legend: **CRITICAL** = data loss or aborted ingestion; **HIGH** = silent
data gaps under normal operation; **MEDIUM/LOW** = correctness/robustness papercuts.

---

## Critical — fixed

### C1. `merge_candidates` violated UNIQUE on `cvss_scores` / `affected_products`
- **File**: `app/ingest/reconcile.py`.
- **Was**: on merging two candidates, the code blindly reassigned child rows to
  the winner. `cvss_scores` (`UNIQUE(candidate_id, version, provenance, source)`)
  and `affected_products` (`UNIQUE(candidate_id, vendor, product, ecosystem)`)
  include `candidate_id` in their UNIQUE key, so two enriched candidates could
  hold colliding rows. Reassigning raised `IntegrityError` and **aborted the
  whole ingest** whenever two enriched candidates merged.
- **Fix**: `merge_candidates` now, for the UNIQUE-with-`candidate_id` tables,
  iterates loser rows and **deletes** the ones that collide with an existing
  winner row before reassigning the rest; globally-unique tables (`identifiers`,
  `mentions`) still reassign directly. A regression test covers the collision.

### C2. `affected_products` were not actually reassigned on merge
- **File**: `app/ingest/reconcile.py`.
- **Was**: the merge code's comment claimed to reassign affected products +
  version ranges, but the loop only handled `cvss_scores`; affected products
  stayed on the tombstone → **silent structured-data loss** after any merge.
- **Fix**: `affected_products` is included in the reassign/dedupe loop (its
  version ranges follow via the FK / cascade).

---

## High — fixed

### H1. NVD delta had no per-row isolation
- **File**: `app/baseline/nvd.py`.
- **Was**: one malformed record (bad date, etc.) raised inside the page loop,
  aborting that page **and every following page** of the delta.
- **Fix**: each `upsert_nvd` runs inside `session.begin_nested()` (savepoint); a
  bad row increments `skipped` and is logged, the delta continues. Also switched
  NVD date params to the ISO-8601 millisecond `...Z` format the API documents
  (`_iso_z`), since 6-digit microseconds can be rejected.

### H2. Source runner had no per-mention isolation
- **File**: `app/sources/runner.py`.
- **Was**: ingestion of a batch shared one transaction; a single bad mention
  rolled back the entire batch (losing all valid mentions).
- **Fix**: each `ingest_mention` runs in a savepoint; failures increment
  `errors` and are logged, valid mentions persist. `sources.last_error` records a
  partial-failure summary.

### H3. `github_commits` did not paginate
- **File**: `app/sources/github_commits.py`.
- **Was**: only the first 100 commits per repo/run were read. Because the per-repo
  watermark then jumped to the newest commit, commits 101+ in the window were
  **dropped forever**.
- **Fix**: `_scan_repo` follows the `Link: rel="next"` header up to
  `github_commits_max_pages` (100/page), advancing the watermark only after
  paging through the window.

### H4. `redhat_csaf` capped at 100 CVEs/run
- **File**: `app/sources/redhat_csaf.py`.
- **Was**: single-page fetch silently truncated results.
- **Fix**: paginates (`per_page=1000`, up to `max_pages=20`, stops on a short
  page).

### H5. OSV buffered `all.zip` in RAM (OOM risk)
- **File**: `app/sources/osv.py`.
- **Was**: reading `resp.content` into a `BytesIO` for large dumps (npm/Debian,
  hundreds of MB) risked OOM.
- **Fix**: streams the download to a `NamedTemporaryFile` and reads zip entries
  lazily from disk, unlinking the temp file in a `finally`. Per-record parsing was
  factored out (`_to_mention`), and per-ecosystem failures are isolated.

### H6. Candidate flags/extras lost on the duplicate-mention path
- **File**: `app/ingest/service.py`.
- **Was**: a duplicate (same `content_hash`) mention returned early, so a
  re-emission that now carried `in_kev=True`, a fixed version, CWEs, etc. never
  updated the candidate.
- **Fix**: `_apply_candidate_updates` runs on both the new-mention and the
  duplicate-mention path (idempotent upserts), so candidate-level data is never
  dropped on re-emission.

### H7. HTTP retry retried permanent 4xx
- **File**: `app/sources/http.py`.
- **Was**: the retry decorator retried all exceptions, including permanent
  4xx (400/401/403/404) — useless and rate-limit-harming (e.g. a secondary 403
  from GitHub).
- **Fix**: `_is_transient` retries only transport errors and `429`/`5xx`;
  everything else fails fast.

---

## Medium / Low — fixed

| # | File | Was | Fix |
|---|---|---|---|
| M1 | `app/ingest/service.py` | `days_ahead` used `timedelta.days` (floor → `-1` on small negative deltas) | `_days` uses `round(total_seconds/86400)` |
| M2 | `app/ingest/service.py` | `seen_at` could be naive, mixing naive/aware datetimes | normalized to UTC-aware on ingest |
| M3 | `app/ingest/hashing.py` | tracking-param stripping matched `ref`/`source` by prefix, dropping legit `reference=`/`source_id=` | exact-match set (`ref`, `source`, `fbclid`, `gclid`, `mkt_tok`) + prefix set (`utm_`, `mc_`) |
| M4 | `app/enrichment/cvss.py` | a no-op `.replace(...)`; vectors not upper-normalized in one path | removed no-op; `persist_cvss_vectors` upper-normalizes |
| M5 | `app/ingest/identifiers.py` | CVE regex required exactly 4–7 digits | accepts `\d{4,}` (≥4/≥7-digit sequence numbers) |
| M6 | `app/sources/__main__.py` | scheduler set once at startup; enable/disable/cadence needed a restart | `_reconcile_jobs` runs every 60 s → hot enable/disable + cadence change |
| M7 | `app/cli.py::stats` | avg lead double-counted candidates with many mentions; included merged | `DISTINCT (source, candidate)` sub-query; excludes `merged_into IS NOT NULL` |
| M8 | `app/sources/cisa_kev.py`, `app/sources/certcc_vu.py` | `seen_at` = fetch time, distorting `first_seen_at`/lead | use the real publication date (`dateAdded` / advisory date) |
| M9 | `app/sources/osv.py` | window filtered by `modified` → old advisories re-surfaced as new | filter by `published` (fallback `modified`) |
| M10 | `docker-compose.yml` | workers could start before Redis was ready | added `redis: condition: service_healthy` to both workers |

---

## Deferred / known limitations (not yet addressed)

### D1. NVD and EPSS block the event loop on DB work
- **File**: `app/baseline/nvd.py`, `app/baseline/epss.py`.
- **What**: the fetch is `async` (httpx), but the DB upserts use the synchronous
  `session_scope()` directly inside the coroutine, so persistence blocks the loop.
- **Why deferred**: baseline runs as its own single-purpose worker with generous
  cadences (2 h / daily) and page-level rate-limit sleeps dominate wall time, so
  the block is not currently a bottleneck. cvelist already offloads with
  `asyncio.to_thread`; NVD/EPSS could do the same later.

### D2. Deleted cvelist files are not propagated
- **File**: `app/baseline/cvelist.py`.
- **What**: `_process_files` counts a file that no longer exists in the delta as
  `skipped`; a CVE removed/renamed upstream is not reflected in `published_cves`
  (no state change / delete).
- **Why deferred**: upstream deletions are rare and destructive to mirror
  blindly; a reconciling sweep (mark REJECTED/withdrawn) is preferable to a
  delete and is left as future work.

### D3. Distinct authoritative vectors of the same version collapse
- **File**: `app/ingest/affected.py`, migration `0001` (`cvss_scores` UNIQUE).
- **What**: `UNIQUE(candidate_id, version, provenance, source)` means two
  authoritative CVSS v3.1 vectors from the *same* source (e.g. two CNAs merged
  under `source='osv'`) upsert onto one row; the last writer wins.
- **Why deferred**: rare, and picking a "winner" vector is acceptable for now;
  distinguishing them would need the source identity (CNA) in the key.

### D4. Stage B fuzzy correlation not implemented
- **File**: `candidate_links` (migration `0001`) exists but is unused.
- **What**: only deterministic (shared-identifier) linking runs today. Fuzzy
  linking by name/fingerprint/embedding — proposing `candidate_links` rows with
  `status='suggested'` — is designed (table, `method`/`confidence`/`status`
  columns) but has no producer.
- **Why deferred**: deterministic linking covers the high-confidence cases;
  fuzzy linking needs a similarity model and a human/LLM confirmation loop.

### D5. Layer 4 prediction not implemented
- **What**: *P(enters KEV in N days)*. Label (`in_kev`/`kev_date`) and features
  (lead, mentions, sources, CVSS, EPSS, PoC, exploit-tool presence) are all in
  the schema, but there is no feature-extraction job, model, or serving path.
- **Why deferred**: needs a labelled history to accumulate first; see
  `USE_CASES.md §5`.

### D6. Alerts + watchlist not implemented
- **What**: no per-tenant watchlist table (against
  `product_catalog`/`product_aliases`) and no alert/notification path. "Affects my
  stack" is expressed by hand-written SQL today.
- **Why deferred**: product canonicalization (`affected_products`, aliases) is the
  prerequisite and is only partially populated; alerting is downstream of it.

### D7. No metrics / observability endpoint
- **What**: no Prometheus exporter or `/metrics`; visibility is via structured
  logs (`structlog`) and `sources.last_success_at` / `last_error`.
- **Why deferred**: headless backend; operational metrics can be added once the
  ingest cadence stabilizes.

### D8. No CI pipeline
- **What**: tests, `ruff`, and `mypy --strict` are configured in `pyproject.toml`
  but there is no CI workflow running them on push.
- **Why deferred**: single-maintainer stage; wiring CI (GitHub Actions with a
  Postgres service) is a mechanical follow-up.
