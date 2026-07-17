# CLI — `cveradar`

Operations and query CLI (Typer + Rich), defined in `app/cli.py` and exposed as
the `cveradar` script (`pyproject.toml [project.scripts]`). Inside the container
it is invoked the same way (`cveradar …`) or with `python -m app.cli`.

Subcommand structure: `db`, `sources`, `baseline`, plus the top-level query
commands `emerging`, `cve`, `enrich`, `stats`.

---

## `db` — database / migrations

```bash
cveradar db init          # alembic upgrade head
```

`db init` runs `alembic upgrade head` and propagates the exit code.

---

## `sources` — source management

```bash
cveradar sources sync                 # registers the code's fetchers into the sources table
cveradar sources list                 # lists sources and their state
cveradar sources enable <name>        # enables a source
cveradar sources disable <name>       # disables a source
cveradar sources run <name>           # runs a fetcher once and prints metrics
```

- `sources sync` → `sync_registry_to_db()` (creates/updates rows; does not
  overwrite `cadence_seconds`).
- `sources list` shows `name / tier / method / enabled / cadence /
  last_success / last_error`.
- `sources run` → `run_source(name)` (async) and prints
  `{"fetched", "created", "duplicate"}`.

```bash
cveradar sources run redhat_csaf
# {'fetched': 100, 'created': 12, 'duplicate': 88}
```

---

## `baseline` — canonical state synchronization

```bash
cveradar baseline sync                        # cvelistV5 + NVD + EPSS, one pass
cveradar baseline sync --nvd-hours 6          # NVD delta window (default 3)
cveradar baseline sync --full-cvelist         # reprocess all of cvelistV5 (default False)
```

Calls `run_baseline_once(nvd_hours=…, force_full_cvelist=…)` and prints the
per-source metrics.

---

## `emerging` — emerging candidates (with filters)

```bash
cveradar emerging list
cveradar emerging list --since 24h --tier 1 --min-mentions 2
cveradar emerging list --source certcc_vu --limit 100
```

| Option | Effect |
|---|---|
| `--since` | Relative window `Nh`/`Nd`/`Nw` (e.g. `24h`, `7d`, `2w`) over `last_seen_at`. |
| `--source` | Filters by `sources.name` (join with `mentions`). |
| `--tier` | Filters by `sources.tier`. |
| `--min-mentions` | Minimum `mention_count` (default `1`). |
| `--limit` | Maximum number of rows (default `50`). |

Only lists live candidates (`merged_into IS NULL`), ordered by `last_seen_at
DESC`. Columns: `cve/id`, `status`, `vuln`, `sev` (best `base_score` or
`severity_hint`), `mentions`, `sources`, `days_ahead`
(`days_ahead_vs_nvd_present`), `last_seen`.

> Note: the positional argument `action` only accepts `list`.

---

## `cve show` — timeline and enrichment

```bash
cveradar cve show CVE-2026-12345
cveradar cve show 3f8e...-uuid        # also accepts a candidate UUID
```

`_find_candidate` looks up by `cve_id` (uppercased) and, failing that,
interprets the key as a candidate UUID. It prints: status, enrichment (`vuln`,
`vector`, `poc`, `hint`), `days_ahead` present/analyzed, the list of
`identifiers`, a `cvss_scores` table (version/score/sev/provenance/source), the
latest EPSS and the mentions **timeline** (`seen_at`, source, title, url).

---

## `enrich` — enrich a candidate

```bash
cveradar enrich CVE-2026-12345
cveradar enrich <uuid-candidate>
```

Locates the candidate and runs `enrich_candidate` (LLM + CVSS). Prints
`enriquecido` or `sin datos`. The LLM provider depends on
`CVERADAR_LLM_PROVIDER` (default `mock`, no network).

---

## `stats` — edge metrics

```bash
cveradar stats
```

Prints:
- Total candidates, promoted (`status='published'`) and promotion rate.
- **Average days of edge per source** (vs NVD *present*):
  `AVG(days_ahead_vs_nvd_present)` grouped by `sources.name`, sorted descending,
  with the number of distinct candidates per source.
