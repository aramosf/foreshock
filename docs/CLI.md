# CLI — `cveradar`

Complete reference for the operations and query CLI (Typer + Rich), defined in
`app/cli.py` and exposed as the `cveradar` console script (`pyproject.toml
[project.scripts] → app.cli:app`). Inside a container it is invoked identically
(`cveradar …`) or as `python -m app.cli`.

The app is built with `typer.Typer(no_args_is_help=True)`. It has three
sub-applications registered with `app.add_typer(...)` — `db`, `sources`,
`baseline` — plus the top-level query commands `emerging`, `cve`, `enrich`,
`stats`, `pending`, `trend`, and `backfill-products`.

Query commands share two helpers:

- **`_emit(fmt, columns, rows, meta=None, title=None)`** — the single output
  formatter (see [Output formats](#output-formats-_emit)).
- **`_parse_since(s)`** — parses relative windows `Nh` / `Nd` / `Nw`
  (`re.fullmatch(r"(\d+)\s*([hdw])")`). Anything else raises
  `typer.BadParameter("usa formato como 24h, 7d, 2w")`. Returns
  `datetime.now(UTC) - delta`. Units: `h` hours, `d` days, `w` weeks.

---

## Output formats (`_emit`)

Every query command (`emerging`, `stats`, `pending`, `trend`) accepts
`--format` / `-f` bound to the parameter `fmt`, with three values:

| `fmt` | Behaviour |
|---|---|
| `table` (default) | Renders a Rich `Table` with `title`. If `meta` is present it is printed as a dim footer line: `key=value  key=value …`. `None` cells render as empty strings. |
| `json` | Emits `json.dumps({"data": [ {col: val, …}, … ], "meta": {…}}, default=str, ensure_ascii=False, indent=2)`. `meta` is included only if non-empty. Datetimes/UUIDs serialize via `default=str`. |
| `csv` | Writes a header row of `columns` followed by data rows to stdout via `csv.writer`. `None` becomes an empty field. **`meta` is intentionally omitted** so the CSV stays machine-clean. |

Notes:
- Any value other than `json`/`csv` falls through to the `table` branch (there is
  no strict validation of `fmt`).
- Only `table` renders the histogram bar / footer meta; scripts should use
  `json` or `csv`.

---

## `db` — database / migrations

```bash
cveradar db init          # alembic upgrade head
```

`db init` shells out to `subprocess.run(["alembic", "upgrade", "head"])` and
`raise typer.Exit(res.returncode)` — it propagates Alembic's exit code. It must
run with `alembic.ini` reachable and `DATABASE_URL` set (the same variable
Alembic's `env.py` reads).

---

## `sources` — source management

```bash
cveradar sources sync                 # register the code's fetchers into `sources`
cveradar sources list                 # list sources and their state
cveradar sources enable <name>        # enable a source
cveradar sources disable <name>       # disable a source
cveradar sources run <name>           # run a fetcher once and print metrics
```

### `sources sync`
Calls `app.sources.runner.sync_registry_to_db()`. For each `@register`-ed
fetcher it inserts a `sources` row (`seed_row()`) if missing, or updates
`kind` / `method` / `tier` if it already exists. **`cadence_seconds` is never
overwritten** — an operator's cadence tuning survives re-syncs. Prints
`Fuentes sincronizadas.`

### `sources list`
Selects all `Source` rows ordered by `(tier, name)` and renders a table:

| Column | Source |
|---|---|
| `name` | `sources.name` |
| `tier` | `sources.tier` (1–5) |
| `method` | `api` / `rss` / `scrape` / `browser` |
| `enabled` | `✓` / `✗` |
| `cadence` | `f"{cadence_seconds}s"` |
| `last_success` | `last_success_at.isoformat()` or `-` |
| `last_error` | `sources.last_error` truncated to 40 chars |

This command always renders a Rich table (no `--format`).

### `sources enable` / `sources disable`
Both call `_set_enabled(name, bool)`, which flips `Source.enabled` in a
write transaction. Unknown name → prints `fuente desconocida: <name>` and
`raise typer.Exit(1)`. Enable/disable is picked up **hot** by the
`sources-worker` (its `_reconcile_jobs` re-reads the table every 60 s).

### `sources run`
`asyncio.run(run_source(name))` executes one fetch + ingest cycle and prints the
returned stats dict. `run_source` is failure-isolated: a fetcher exception is
caught, logged, written to `last_error`/`last_error_at`, and yields empty
metrics rather than crashing. Per-mention ingestion runs inside a savepoint
(`session.begin_nested()`) so a single bad mention does not roll back the batch.

```bash
cveradar sources run redhat_csaf
# {'fetched': 100, 'created': 12, 'duplicate': 88, 'errors': 0}
```

Stats keys: `fetched` (mentions returned by the fetcher), `created` (new
mentions inserted), `duplicate` (idempotent hits), `errors` (mentions that
raised during ingest).

---

## `baseline` — canonical state synchronization

```bash
cveradar baseline sync                        # cvelistV5 + NVD delta + EPSS, one pass
cveradar baseline sync --nvd-hours 6          # NVD lastMod window in hours (default 3)
cveradar baseline sync --full-cvelist         # reprocess ALL of cvelistV5 (default False)
```

| Option | Type / default | Effect |
|---|---|---|
| `--nvd-hours` | `int` = `3` | Width of the NVD 2.0 `lastModStartDate…lastModEndDate` delta window, in hours. |
| `--full-cvelist` | `bool` = `False` | If set, `sync_cvelist(force_full=True)` reprocesses every JSON in the clone instead of only the git delta. |

Calls `run_baseline_once(nvd_hours=…, force_full_cvelist=…)` (which runs the
three baseline sources under `asyncio.run`, each failure-isolated) and prints the
per-source metrics dict, e.g.:

```
{'cvelist': {'files': 40, 'upserted': 40, 'skipped': 0, 'errors': 0},
 'nvd': {'pages': 1, 'fetched': 120, 'upserted': 118, 'skipped': 2},
 'epss': {'requests': 1, 'ingested': 200, 'skipped': 0}}
```

---

## `emerging` — emerging candidates (with filters)

```bash
cveradar emerging list
cveradar emerging list --since 24h --tier 1 --min-mentions 2
cveradar emerging list --source certcc_vu --limit 100 --format json
```

Signature: `emerging(action="list", --since, --source, --tier, --min-mentions,
--limit, --format/-f)`.

| Option | Type / default | Effect |
|---|---|---|
| `action` (positional) | `str` = `list` | Only `list` is accepted; anything else raises `typer.BadParameter`. |
| `--since` | `str \| None` = `None` | Relative window `Nh`/`Nd`/`Nw` applied as `Candidate.last_seen_at >= now-Δ`. |
| `--source` | `str \| None` = `None` | Restrict to candidates that have a mention from `sources.name == source` (EXISTS sub-select joining `mentions`→`sources`). |
| `--tier` | `int \| None` = `None` | Restrict to candidates that have a mention from a source of that `tier`. |
| `--min-mentions` | `int` = `1` | `Candidate.mention_count >= min_mentions`. |
| `--limit` | `int` = `50` | Row cap. |
| `--format` / `-f` | `str` = `table` | `table` / `json` / `csv`. |

Only **live** candidates are listed (`Candidate.merged_into IS NULL`), ordered by
`last_seen_at DESC`. For each candidate the severity cell is the highest
`cvss_scores.base_score` (with its version) if any, else the candidate's
`severity_hint`.

Columns:

| Column | Meaning |
|---|---|
| `cve_id` | `candidate.cve_id`, or the first 8 chars of the candidate UUID if no CVE yet. |
| `status` | `candidate` / `emerging` / `published` / `rejected` / `merged`. |
| `vuln` | `candidate.vuln_type` (from enrichment). |
| `sev` | `"<base_score> (v<version>)"` from the top CVSS score, else `severity_hint`. |
| `mentions` | `candidate.mention_count`. |
| `sources` | `candidate.source_count` (distinct sources). |
| `days_ahead` | `candidate.days_ahead_vs_nvd_present` (lead vs the moment we first observed the CVE in NVD). |
| `last_seen` | `last_seen_at` formatted `%Y-%m-%d %H:%M`. |

---

## `cve show` — timeline and enrichment of one candidate

```bash
cveradar cve show CVE-2026-12345
cveradar cve show 3f8e5b6a-....-uuid      # also accepts a candidate UUID
```

Signature: `cve(action="show", cve_id)`. Only `show` is accepted. Resolution is
via `_find_candidate(session, key)`: it first looks up `Candidate.cve_id ==
key.upper()`; failing that, it tries to parse `key` as a UUID and `session.get`
the candidate. Not found → `no encontrado: <key>` and `typer.Exit(1)`.

Prints (Rich, no `--format`):

- Header: `<cve_id or UUID>  status=<status>`.
- Enrichment line: `vuln=<vuln_type> vector=<attack_vector> poc=<has_public_poc>
  hint=<severity_hint>`.
- Lead line: `days_ahead present=<…_present> analyzed=<…_analyzed>`.
- `ids:` all `identifiers` as `scheme:value` (e.g. `CVE:CVE-2026-… , GHSA:… ,
  GHCOMMIT:owner/repo@sha`).
- A **CVSS table** (only if scores exist): `version`, `score`, `sev`,
  `provenance` (`authoritative`/`derived`), `source`.
- **EPSS** (only if the candidate has a `cve_id` and an EPSS row):
  `EPSS: <score> (pct <percentile>) @ <scored_date>` — latest by `scored_date`.
- **Timeline**: every `mention` joined to its source, ordered by `seen_at`, as a
  table of `seen_at` (`%Y-%m-%d %H:%M`), `source`, `title` (≤50 chars), `url`
  (≤50 chars).

---

## `enrich` — enrich a candidate

```bash
cveradar enrich CVE-2026-12345
cveradar enrich <candidate-uuid>
```

Resolves the candidate with `_find_candidate` (not found → `typer.Exit(1)`), then
runs `enrich_candidate` (Layer 3) under `asyncio.run` inside a write transaction.
Prints `enriquecido` if enrichment was written, else `sin datos` (no snippets to
work from). Enrichment: extracts authoritative CVSS vectors verbatim from mention
text, calls the configured LLM for structured metrics, derives a CVSS v3.1 vector
if all 8 base metrics are present, sets `severity_hint` only when no numeric score
exists, and upserts `affected_products`. The LLM backend is chosen by
`CVERADAR_LLM_PROVIDER` (default `mock`, no network).

---

## `stats` — lead metrics per source

```bash
cveradar stats
cveradar stats --format json
```

| Option | Default | Effect |
|---|---|---|
| `--format` / `-f` | `table` | `table` / `json` / `csv`. |

Meta (footer in table / `meta` object in JSON; omitted in CSV):

| Meta key | Meaning |
|---|---|
| `candidates` | Count of live candidates (`merged_into IS NULL`). |
| `promoted` | Count of live candidates with `status='published'`. |
| `promotion_rate_pct` | `promoted / candidates * 100`, one decimal (0 if none). |

Rows — **average lead days per source vs NVD `present`**:

| Column | Meaning |
|---|---|
| `source` | `sources.name`. |
| `avg_days_ahead` | `avg(days_ahead_vs_nvd_present)`, one decimal. |
| `candidates` | Number of distinct candidates contributing. |

The average is computed over a `DISTINCT (source, candidate)` sub-query so a
candidate with many mentions from one source is not over-weighted; merged
candidates (`merged_into IS NOT NULL`) and NULL leads are excluded. Sorted by
`avg_days DESC`.

```
      Días de ventaja por fuente (vs NVD present)
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ source        ┃ avg_days_ahead ┃ candidates ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ certcc_vu     │ 9.4            │ 12         │
│ github_commits│ 4.1            │ 233        │
└───────────────┴────────────────┴────────────┘
candidates=812  promoted=104  promotion_rate_pct=12.8
```

---

## `pending` — software with vulnerabilities that have no official CVE

```bash
cveradar pending
cveradar pending --kind product --top 30
cveradar pending --kind all --format json
```

| Option | Type / default | Effect |
|---|---|---|
| `--top` | `int` = `20` | Number of software entries in the ranking (`Counter.most_common(top)`). |
| `--kind` | `str` = `product` | `product` / `distro` / `malware` / `all` — which class of affected software to rank. |
| `--format` / `-f` | `str` = `table` | `table` / `json` / `csv`. |

### What "pending" means
Both `pending` and `trend` read the shared query `_PENDING_AP_SQL`
(`_load_pending`), which LEFT JOINs `candidates` to `affected_products` and keeps
a candidate iff:

```sql
c.merged_into IS NULL
AND ( c.cve_id IS NULL
   OR NOT EXISTS (SELECT 1 FROM published_cves p
                  WHERE p.id = c.cve_id AND p.state = 'PUBLISHED') )
```

So a candidate is **pending** when it is live and either (a) has **no** CVE yet,
or (b) references a CVE that is **not `PUBLISHED`** in our baseline (only
`RESERVED`/`REJECTED`, or not ingested at all). This is the set of things the
official catalogs have not (fully) published while the radar already tracks them.

### Kind classification
`affected_products.kind` is set at ingest time by `classify_kind(ecosystem,
is_malware)` in `app/ingest/affected.py`:

- `malware` — the OSV id starts with `MAL-` (OSV malware advisories).
- `distro` — the ecosystem name starts with a known Linux distro / OS token
  (`ubuntu`, `debian`, `alpine`, `rocky`, `almalinux`, `suse`, `opensuse`,
  `red hat`/`redhat`, `chainguard`, `wolfi`, `linux`, `android`, `bitnami`,
  `mageia`, `photon`, `gentoo`, `oracle`).
- `product` — everything else (real package ecosystems: PyPI, Go, npm, …).

### Aggregation
Rows are grouped per candidate into a set of `(product, kind)` pairs. The meta
counts candidates (a candidate counts once per distinct kind it touches); the
ranking counts, per product name, how many pending candidates reference it,
filtered to the requested `kind` (or all).

Columns: `software`, `cves_pendientes` (count of pending candidates naming that
software).

Meta keys: `total` (pending candidates), `con_software` (those with any resolved
product), `product` / `distro` / `malware` (candidate counts by kind), `kind`
(the filter used).

```
                 Top software (kind=product)
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ software             ┃ cves_pendientes ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ tensorflow           │ 14              │
│ pillow               │ 9               │
└──────────────────────┴─────────────────┘
total=512  con_software=430  product=380  distro=95  malware=37  kind=product
```

---

## `trend` — time series of pending vulnerabilities

```bash
cveradar trend
cveradar trend --kind product --granularity month --months 6
cveradar trend --kind all --granularity year --months 0 --format csv
```

| Option | Type / default | Effect |
|---|---|---|
| `--kind` | `str` = `all` | `product` / `distro` / `malware` / `all` — restrict to candidates touching that kind. |
| `--granularity` | `str` = `month` | `month` (`%Y-%m` buckets) or `year` (`%Y` buckets). |
| `--months` | `int` = `12` | Look-back window in months (`cutoff = now - 30*months days`). `0` (or negative) disables the cutoff (all history). |
| `--format` / `-f` | `str` = `table` | `table` / `json` / `csv`. |

Buckets each pending candidate by its **`first_seen_at`** — the earliest radar
signal for it (earliest commit date, OSV `published`, KEV `dateAdded`, etc.), not
the CVE's official date. A candidate with `first_seen_at IS NULL`, outside the
kind filter, or older than the cutoff is skipped. Empty result →
`sin datos temporales` and returns.

- **`table`**: columns `periodo`, `pendientes`, and an unlabeled bar column
  (`"█" * round(40 * count / peak)`) — an ASCII histogram to eyeball the
  hockey-stick. Meta footer `kind=… months=…`.
- **`json` / `csv`**: columns `periodo`, `pendientes` only (no bar). JSON carries
  the `meta` object; CSV omits it.

---

## `backfill-products` — populate `affected_products` for older candidates

```bash
cveradar backfill-products
cveradar backfill-products --batch 2000
```

| Option | Type / default | Effect |
|---|---|---|
| `--batch` | `int` = `1000` | `session.flush()` every N persisted candidates. |

Idempotent. For every live candidate that has **no** `affected_products` row yet,
it derives one software string via a COALESCE of three heuristics, in order:

1. A `GHCOMMIT:owner/repo@sha` identifier → `owner/repo` (regex-stripped).
2. A mention `snippet` containing `affected: <token>` (OSV-style label).
3. A mention `title` shaped `owner/repo: …` (prefix before the first `:`).

Malware is detected from an `OSV` identifier `ILIKE 'MAL-%'`. `to_affected`
turns the raw string into an `AffectedInput`: an `owner/repo` form (a `/` with no
`:` before it) becomes `ecosystem="github"`, otherwise it splits on `:` into
`ecosystem:name` and classifies the kind with `classify_kind`. Rows are persisted
through `persist_affected` (the same upsert OSV uses at ingest time), so re-runs
don't duplicate. Prints `backfill: <n> candidates con affected_products`.

> OSV already populates `affected_products` at ingest; this command backfills the
> remaining sources (GitHub commits, GHSA, KEV, …) whose structured product data
> was not persisted natively.

---

## Command / option quick index

| Command | Options |
|---|---|
| `db init` | — |
| `sources sync` | — |
| `sources list` | — |
| `sources enable <name>` | — |
| `sources disable <name>` | — |
| `sources run <name>` | — |
| `baseline sync` | `--nvd-hours`, `--full-cvelist` |
| `emerging [list]` | `--since`, `--source`, `--tier`, `--min-mentions`, `--limit`, `--format/-f` |
| `cve show <key>` | — |
| `enrich <key>` | — |
| `stats` | `--format/-f` |
| `pending` | `--top`, `--kind`, `--format/-f` |
| `trend` | `--kind`, `--granularity`, `--months`, `--format/-f` |
| `backfill-products` | `--batch` |
