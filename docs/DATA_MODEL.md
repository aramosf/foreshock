# Data model

The **hand-written Alembic migrations are the source of truth for the schema**
(`migrations/versions/0001_initial_schema.py`, `0002_affected_products.py`,
`0003_soft_cve_ref.py`). `app/core/models.py` is an ORM mapping (SQLModel) over
those tables; `env.py` uses `target_metadata=None`, so the models never
autogenerate or create tables on their own.

Postgres 16. It leverages `gen_random_uuid()`, `TIMESTAMP WITH TIME ZONE`,
`JSONB`, `ARRAY(Text)` and partial indexes.

---

## Baseline

### `published_cves`
Canonical state of each CVE (cvelistV5 + NVD 2.0). PK `id` = `CVE-YYYY-NNNN`
(`Text`).

| Column | Type | Notes |
|---|---|---|
| `id` | Text PK | `CVE-YYYY-NNNN` |
| `state` | Text | `RESERVED` / `PUBLISHED` / `REJECTED` (CHECK `ck_pubcves_state`) |
| `cvelist_published_at`, `cvelist_updated_at` | timestamptz | Dates self-reported by cvelistV5. |
| `nvd_published_at`, `nvd_last_modified_at` | timestamptz | Dates self-reported by NVD (**may come with backfill**). |
| `nvd_vuln_status` | Text | e.g. `Analyzed`, `Awaiting Analysis`. |
| `nvd_first_observed_at` | timestamptz | **Own observation**: when we first saw it in NVD (immune to backfill). |
| `nvd_first_analyzed_observed_at` | timestamptz | When we first saw it in `Analyzed` state. |
| `cna`, `assigner_short_name` | Text | Authorship of the record. |
| `raw_json` | JSONB | Original CVE 5.x record. |
| `ingested_at` | timestamptz | `server_default now()`. |

The `cvelist_*` fields are filled by `app/baseline/cvelist.py`; the `nvd_*` ones by
`app/baseline/nvd.py`. Neither overwrites the other (disjoint upserts by columns).
The `nvd_first_*` columns are sealed once via `COALESCE` — they are the
**observation ground truth** that makes the `days_ahead_present` metric robust.

### `sources`
Registry of fetchers. `name` unique; `method IN ('api','rss','scrape','browser')`
(CHECK `ck_sources_method`); `tier BETWEEN 1 AND 5` (CHECK `ck_sources_tier`).
Stores `enabled`, `cadence_seconds`, `last_success_at`, `last_error`,
`last_error_at`. Partial index `idx_sources_enabled WHERE enabled`.

---

## Tracking

### `candidates` — the tracking unit
A candidate exists **with or without a CVE**. PK `id` UUID (`gen_random_uuid()`).

- `status` — `candidate` / `emerging` / `published` / `rejected` / `merged`
  (CHECK `ck_cand_status`).
- **`cve_id` (Text) — SOFT reference, NO FK.** The `0003` migration drops
  the `candidates_cve_id_fkey` constraint. Reason: a candidate may reference
  a CVE that is only RESERVED and not yet ingested by the baseline (or that MITRE/NVD
  have not published yet). Enforcing the FK would prevent recording the early
  signal, which is CVERadar's premise. Reconciliation is done by *lookup*
  (`compute_days_ahead` does `session.get(PublishedCVE, cve_id)`), not by
  referential integrity. Index `idx_cand_cve`.
- `merged_into` — self-FK for the merge union-find (tombstone). Partial
  index `idx_cand_merged_into WHERE merged_into IS NOT NULL`.
- `cluster_fingerprint` — fingerprint for fuzzy dedup.
- Mention aggregates: `first_seen_at`, `last_seen_at`, `mention_count`,
  `source_count` (recomputed by `_refresh_aggregates`).
- Reconciliation with NVD: `promoted_at`, `days_ahead_vs_nvd_published`,
  `days_ahead_vs_nvd_present`, `days_ahead_vs_nvd_analyzed`.
- Enrichment (Layer 3): `affected_product`, `affected_versions`,
  `vuln_type`, `attack_vector` (CHECK `network/adjacent/local/physical`),
  `requires_auth`, `requires_interaction`, `has_public_poc`, `poc_urls[]`,
  `severity_hint` (CHECK `likely-critical/high/medium/low`),
  `enrichment_confidence` (CHECK 0..1), `enrichment_method`,
  `enrichment_updated_at`.

### `identifiers` — deterministic link
Each `(scheme, value)` anchors to **a single** candidate.
`UNIQUE(scheme, value)` (`uq_identifiers_scheme_value`) is the key of the
deterministic link (Stage A of the correlation). FK `candidate_id` with
`ON DELETE CASCADE`. Schemes: `CVE`, `ZDI-CAN`, `ZDI`, `VU`, `GHSA`, `MSRC`,
`GHCOMMIT` (see `INGESTION.md`).

### `mentions` — raw observations
Each appearance of a vulnerability in a source. FKs to `candidates`
(CASCADE) and `sources`.

- **Idempotency by `content_hash`**: `UNIQUE(source_id, content_hash)`
  (`uq_mentions_source_hash`). The hash is computed over the **semantic excerpt**
  (normalized CVE + native + title + snippet + canonical URL), **not** over the
  raw HTML. An identical re-listing → same hash → no duplicate; a real
  content change → new hash → legitimate new mention in the timeline. See
  `app/ingest/hashing.py`. The CVE identity goes **inside** the hash, which is why
  the constraint does not include `cve_id`.
- `extracted_cve`, `extracted_native`, `url`, `title`, `snippet`,
  `raw_html_path` (on-disk path to the persisted raw HTML), `seen_at`.

### `candidate_links` — PROPOSED fuzzy dedup, non-destructive
Fuzzy links between candidates that **are suggested but not merged**. Composite
PK `(a, b)` with CHECK `a < b` (canonical pair, `ck_links_canonical_pair`).

- `method IN ('fingerprint','embedding','llm')` (CHECK `ck_links_method`).
- `confidence` 0..1; `status IN ('suggested','confirmed','rejected')`
  (default `suggested`).
- `rationale` for auditing. Partial index
  `idx_links_status WHERE status = 'suggested'`.

It is non-destructive: unlike the `identifiers` union-find (which really merges
by deterministic evidence), here a link is only proposed for review.

### `cvss_scores` — v3/v4, authoritative vs derived, multi-source
Several rows per candidate. `UNIQUE(candidate_id, version, provenance, source)`
(`uq_cvss_candidate_version_prov_source`).

- `version IN ('3.0','3.1','4.0')` (CHECK `ck_cvss_version`).
- `vector` (verbatim or constructed), `base_score` (0..10), `base_severity`
  (`NONE/LOW/MEDIUM/HIGH/CRITICAL`).
- **`provenance IN ('authoritative','derived')`** (CHECK `ck_cvss_provenance`):
  `authoritative` = vector extracted verbatim from the source text and scored
  with the `cvss` library; `derived` = computed from the metrics inferred by
  the LLM.
- `source` — textual origin (`source-text`, `llm-derived`, …).
- `inferred_metrics[]` and `confidence` — only for `derived`.

See `ENRICHMENT.md` for the selection precedence.

### `epss_scores` — history
Composite PK `(cve_id, scored_date)` (`pk_epss_scores`) → each daily snapshot
of the model is kept; the score evolution is visible. `score` and `percentile`
0..1. **No FK to `published_cves`**: EPSS may refer to a CVE not yet ingested.

---

## Software canonicalization (migration `0002`)

### `product_catalog`
Canonical vocabulary (seeded from CPE-dict / OSV / manual). The "truth" against
which dirty names are linked. Fields `vendor`, `product` (NOT NULL),
`ecosystem` (PyPI/npm/Go…; NULL for classic software), `cpe23`, `purl`, `source`.
`UNIQUE(vendor, product, ecosystem)` with **`NULLS NOT DISTINCT`** (PG15+): two
rows with `ecosystem NULL` also dedup (without that clause, `NULL != NULL`
would allow duplicates). Same in `affected_products.uq_affected_candidate_product`.

### `product_aliases`
Normalized key → canonical entry. `UNIQUE(alias_normalized)`: an alias
resolves **deterministically** to ONE entry. It grows with what the
LLM/human confirms; next time it resolves in Layer 1 without calling the LLM again.
`source IN ('seed','llm','manual')`, `confidence` 0..1.

### `affected_products`
Products affected per candidate (multi-row). Stores the **extracted raw**
(`raw`, `product`, `vendor`, `ecosystem`, `cpe23`, `purl`, `exact_versions[]`,
`default_status`) **plus** the canonical link `catalog_id` (FK
`ON DELETE SET NULL`) and the canonicalization traceability:
`normalization_method IN ('exact','alias','fuzzy','llm','unresolved')`,
`normalization_confidence`. Partial index `idx_affected_unresolved WHERE
catalog_id IS NULL` = queue of items pending resolution.

### `affected_version_ranges`
Structured ranges per affected product (OSV / CVE-5.0 style):
`introduced`, `fixed` (exclusive), `last_affected` (inclusive), `version_type`
(semver/rpm/custom…), `raw` (e.g. `< 7.4.3`). FK to `affected_products` CASCADE.

---

## Convenience views

Defined in `0001_initial_schema.py`:

- **`epss_current`** — `DISTINCT ON (cve_id) … ORDER BY cve_id, scored_date DESC`:
  the most recent EPSS snapshot per CVE over the history.
- **`cvss_selected`** — `DISTINCT ON (candidate_id)` with precedence order:
  `provenance = 'authoritative'` first, then highest version
  (`4.0 > 3.1 > 3.0`), then `base_score DESC NULLS LAST`. Selects the "best"
  CVSS per candidate.
- **`radar`** — main consumption view: `candidates` LEFT JOIN
  `cvss_selected` LEFT JOIN `epss_current`, filtering
  `status IN ('candidate','emerging','published') AND merged_into IS NULL`.
  Exposes `days_ahead_vs_nvd_present` and `days_ahead_vs_nvd_analyzed`, the selected
  CVSS, `severity_hint` and the current EPSS.
