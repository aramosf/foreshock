# Ingestion pipeline

The pipeline turns a **mention** captured by a fetcher
(`FetchedMention`) into `mentions` / `candidates` / `identifiers` rows
**idempotently**. Fetchers do NOT write to the DB; they only return
`list[FetchedMention]`. All persistence happens in
`app/ingest/service.py::ingest_mention()`.

```python
@dataclass
class FetchedMention:            # app/ingest/service.py
    url: str | None = None
    title: str | None = None
    snippet: str | None = None
    cve_id: str | None = None      # if the fetcher already knows it
    native_id: str | None = None   # e.g. ZDI-CAN-nnnn, GHSA-…, GHCOMMIT:…
    raw_html: str | None = None    # raw content to persist
    seen_at: datetime | None = None
```

---

## Step 1 — Identifier extraction (`app/ingest/identifiers.py`)

`extract_identifiers(*texts)` runs a battery of regexes over the concatenation
of `cve_id`, `native_id`, `title`, `snippet` and `url`, preserving **priority
order**. The first scheme in the list is the preferred "native" one when there is no
CVE.

| Scheme | Pattern (summary) |
|---|---|
| `CVE` | `\bCVE-\d{4}-\d{4,7}\b` |
| `ZDI-CAN` | `\bZDI-CAN-\d{3,6}\b` |
| `ZDI` | `\bZDI-\d{2}-\d{3,5}\b` |
| `VU` | `\bVU#\d{5,7}\b` |
| `GHSA` | `\bGHSA-xxxx-xxxx-xxxx\b` (restricted base32 alphabet) |
| `MSRC` | `\bADV\d{6}\b` |
| `GHCOMMIT` | `\bGHCOMMIT:owner/repo@<sha7-40>\b` |

`GHCOMMIT` is a **synthetic** identifier to anchor pre-CVE candidates
from security commits with no assigned CVE (see `SOURCES.md`).

Normalization (`_canon`): `GHSA` keeps the prefix uppercase and the body
lowercase (`GHSA-jfh8-c2jp-5v3q`); `GHCOMMIT` is **not** normalized (owner/repo
and sha are case-sensitive); everything else is uppercased.

Helpers: `primary_cve(ids)` returns the first CVE; `primary_native(ids)`
returns the first non-CVE identifier.

If **no** identifier is extracted, the mention is discarded
(`ingest.skip_no_identifier`): without an anchor it cannot be correlated.

---

## Step 2 — `content_hash` (`app/ingest/hashing.py`)

Design rule: **the raw HTML is not hashed**. Timestamps, banners and CSRF
tokens would change the hash on every fetch and generate new rows. What is hashed
is the **semantic excerpt**:

```python
content_hash(cve, native, title, snippet, url) = sha256(
    "\x1f".join([
        (cve or "").upper(),
        (native or "").upper(),
        normalize_text(title),      # collapses spaces, lowercase
        normalize_text(snippet),
        canonical_url(url),         # no fragment, no utm_/gclid/…, sorted query
    ])
)
```

`canonical_url` removes the fragment, strips tracking parameters
(`utm_`, `mc_`, `fbclid`, `gclid`, `ref`, `source`), sorts the query, lowercases
the host and normalizes the trailing slash. Consequence: identical re-listing →
same hash → no duplicate; a real change → new hash → legitimate mention.

---

## Step 3 — `resolve_candidate` + union-find merge (`app/ingest/reconcile.py`)

Stage A of the correlation (**deterministic** link): a `(scheme, value)`
belongs to a single candidate.

`resolve_candidate(session, ids)`:

1. For each identifier it looks up its current candidate via
   `_candidate_for_identifier` → `find_root` (follows the `merged_into` chain
   to the live root, with anti-cycle protection).
2. **None known** → creates a new `Candidate(status="candidate")`.
3. **One** → reuses it.
4. **Several** → **merges** them into a winner (`_pick_winner` +
   `merge_candidates`).
5. Attaches the missing identifiers and sets `cve_id` if a CVE appears and
   the candidate did not have one yet.

**`_pick_winner`**: the one that already has a `cve_id` wins; on a tie, the
oldest `first_seen_at`.

**`merge_candidates(winner, loser)` — reversible tombstone**:
- Reassigns the loser's children to the winner: `UPDATE … SET candidate_id = winner`
  on `Identifier`, `Mention`, `CVSSScore`.
- Marks the loser: `merged_into = winner.id`, `status = 'merged'` (not deleted →
  **reversible**: it can be undone by following `merged_into`).
- Propagates the loser's `cve_id` to the winner if the winner did not have one.

This union-find is the **destructive merge by deterministic evidence** (same
identifier). The **fuzzy** dedup (similar names/fingerprints) goes through
`candidate_links` and is only a proposal, it does not merge (see `DATA_MODEL.md`).

---

## Step 4 — Raw HTML persistence

If `FetchedMention.raw_html` is provided, `_persist_raw` writes it to
`{raw_html_dir}/{source_id}/{content_hash}.html` (only if it does not exist). The path is
saved in `mentions.raw_html_path` for re-parsing without going back to the source.

---

## Step 5 — Aggregates and `compute_days_ahead`

After inserting the mention:

- **`_refresh_aggregates`** recomputes via SQL: `mention_count`, `source_count`
  (distinct `source_id`), `first_seen_at = min(seen_at)`,
  `last_seen_at = max(seen_at)`. If `status == 'candidate'` and there is ≥1 mention,
  it promotes to `emerging`.
- **`compute_days_ahead`** — only if the candidate has a reconciled `cve_id` and
  the CVE exists in `published_cves`: computes the three deltas
  (`published`/`present`/`analyzed`, see `ARCHITECTURE.md`) against
  `candidate.first_seen_at`. If the CVE is `PUBLISHED` and the candidate is in
  `candidate`/`emerging`, it promotes it to `published` and seals `promoted_at`.

---

## Idempotency rules (summary)

1. **Mention dedup**: before inserting, it looks up
   `(source_id, content_hash)`; if it exists, `IngestResult(duplicate=True)` and nothing
   is done. Backed by `UNIQUE(source_id, content_hash)`.
2. **Identifiers**: `UNIQUE(scheme, value)`; only the missing ones are
   attached.
3. **No own commit**: `ingest_mention` requires an open session and does **not**
   commit; the `runner` manages the transaction per mention batch.
4. Re-running an identical fetch creates no new rows and does not distort the
   aggregates.
