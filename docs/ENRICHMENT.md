# Enrichment (Layer 3)

Enrichment (`app/enrichment/`) consolidates a candidate's mentions and derives
structured metadata: vulnerability type, attack vector, auth/interaction
requirements, PoC availability, affected products, CVSS scores, and a qualitative
`severity_hint`. Entry point: `enrich_candidate(session, candidate_id)` in
`app/enrichment/service.py` (open session, no commit).

The guiding principle: **never invent a CVSS number.** The LLM extracts *base
metrics*, and the score is computed deterministically with the `cvss` library.

---

## 1. `enrich_candidate` flow (`service.py`)

1. **Gather snippets** (`gather_snippets`): for each mention, join
   `title + snippet` into a text blob; also returns `candidate.cve_id`. No
   snippets → return `False` (nothing to enrich).
2. **Authoritative CVSS** (§3.1): `parse_authoritative(blob)` extracts CVSS
   vectors verbatim from the source text and upserts them as
   `provenance="authoritative", source="source-text", confidence=1.0`.
3. **LLM extraction** (§2): `out, method = await enrich(cve_id, snippets)` →
   validated `EnrichmentOut`.
4. **Derived CVSS** (§3.2): `derive_from_metrics(out.cvss_metrics)` — only if all
   8 base metrics are present — upserts as `provenance="derived",
   source="llm-derived", inferred_metrics=[...], confidence=out.confidence`.
5. **Candidate fields**: `vuln_type`, `attack_vector`, `requires_auth`,
   `requires_interaction`, `has_public_poc`, `poc_urls`. If any affected products
   were extracted, the first fills the denormalized `affected_product`
   (`vendor/product` or `product`) and `affected_versions`. Also
   `enrichment_confidence`, `enrichment_method`, `enrichment_updated_at`.
6. **`severity_hint`** (§4): computed **only if no numeric score exists** (no
   authoritative or derived `base_score` on the candidate); otherwise `None`.
7. **Affected products** (§5): each `AffectedProductOut` is upserted with
   deterministic alias canonicalization (`source="llm"`).

`_upsert_cvss` and `_upsert_affected` use Postgres `ON CONFLICT` on the same
UNIQUE constraints as the ingest path (`uq_cvss_candidate_version_prov_source`,
`uq_affected_candidate_product`), so ingest-time and enrich-time writes coexist
without duplication.

---

## 2. The LLM extracts metrics, not a number

### 2.1 Output schema (`schema.py`)

`EnrichmentOut` (Pydantic, `extra="forbid"`):

- `affected_products: list[AffectedProductOut]` — `{vendor?, product,
  ecosystem?, versions_raw?, fixed_version?}`.
- `vuln_type`, `attack_vector` (`network|adjacent|local|physical`),
  `requires_auth`, `requires_interaction`, `has_public_poc`, `poc_urls`,
  `summary`.
- `cvss_metrics: CVSSMetricsOut | None` — the **8 base metrics**
  (`attack_vector`, `attack_complexity`, `privileges_required`,
  `user_interaction`, `scope`, `confidentiality`, `integrity`, `availability`),
  each nullable.
- `confidence: float ∈ [0, 1]`.

The LLM **never returns a CVSS score**; it returns `cvss_metrics`, from which the
score is computed. Authoritative vectors come from regex over the source text,
not from the LLM.

### 2.2 Prompt (`prompts.py`)

`SYSTEM_PROMPT` instructs the model to return **only** strict JSON (no markdown),
to fill `cvss_metrics` when inferable (else null), never to invent a numeric
score, to use `null`/empty for unknowns, and to set `confidence`.
`build_user_prompt(cve_id, snippets)` prepends the CVE header (or "not yet
assigned") and joins the snippets with `---` separators.

### 2.3 Providers (`llm.py`)

`get_provider()` dispatches on `settings.llm_provider`:

| Provider | Endpoint | Key env / notes |
|----------|----------|-----------------|
| `mock` (default) | none | Deterministic heuristic, no network — for dev/tests. |
| `openai` | `{llm_base_url or https://api.openai.com/v1}/chat/completions` | `Authorization: Bearer {llm_api_key}`, `response_format={"type":"json_object"}`. |
| `anthropic` | `{llm_base_url or https://api.anthropic.com}/v1/messages` | `x-api-key: {llm_api_key}`, `anthropic-version: 2023-06-01`; reads first `text` block. |
| `ollama` | `{llm_base_url or http://localhost:11434}/api/chat` | `format: "json"`, `stream: false`, local. |

Relevant settings: `llm_provider`, `llm_model`, `llm_api_key`, `llm_base_url`,
`llm_max_tokens` (1024).

**`MockProvider`** is a deterministic, network-free heuristic: regex flags
`vuln_type` (RCE / AuthBypass / SQLi / XSS), `has_public_poc`, `attack_vector`
(`network` on remote/network/unauthenticated), `requires_auth=False` on
"unauthenticated", extracts up to 5 URLs, and reports `confidence: 0.35` (low —
it is heuristic, not a real LLM). `cvss_metrics` is `None`.

`enrich(...)` builds the prompts, calls `provider.complete(...)`, parses the
first JSON object (`_extract_json` tolerates ```` ``` ```` fences and a
`{...}` substring fallback), validates against `EnrichmentOut`, and returns
`(result, method="{provider}:{model}")`.

---

## 3. CVSS precedence — three levels (`cvss.py`)

Scores are never guessed. There are three levels of decreasing authority:

### 3.1 Authoritative (regex over source text)

`parse_authoritative(text)` finds every CVSS vector embedded verbatim
(`_VECTOR_RE`: `CVSS:(3.[01]|4.0)/...`), dedupes, and scores each with
`_score_severity`. Result: `provenance="authoritative"`. This is the trusted
path (Red Hat, MSRC, CNA, OSV `severity`). `_score_severity(vector, version)`
uses `CVSS4` for v4 and `CVSS3` for v3.x from the `cvss` library, returning
`(base_score, severity.upper())`; an invalid vector yields `(None, None)`.

The ingest path writes authoritative scores from **structured** vectors
(`persist_cvss_vectors` in `app/ingest/affected.py`), and the enrichment path
writes them from **regex over text** — same `provenance`, both scored with the
same library.

### 3.2 Derived (LLM base metrics → computed score)

`derive_from_metrics(metrics)` builds a CVSS v3.1 vector from the 8 base
metrics, mapping each enum to its letter (`_AV`, `_AC`, `_PR`, `_UI`, `_S`,
`_CIA`). **All 8 must be present** — if any maps to `None`, it returns `None`
(insufficient metrics → fall back to `severity_hint`). Otherwise it scores the
vector and returns `provenance="derived"` with
`inferred_metrics=["AV","AC","PR","UI","S","C","I","A"]` (all from LLM
inference).

### 3.3 `severity_hint` (qualitative fallback)

Only when there is **no numeric score at all**. See §4.

Precedence in practice: authoritative scores are always written when present;
derived is written when metrics allow; `severity_hint` is set **only if the
candidate has no row with a non-null `base_score`** (checked against
`cvss_scores`).

---

## 4. `severity_hint`

`severity_hint(vuln_type, attack_vector, has_public_poc)` is a cheap qualitative
estimate (explicitly **not** CVSS). Returns `None` if neither `vuln_type` nor
`attack_vector` is known. Otherwise it sums weights:

- `vuln_type` via `_TYPE_WEIGHT` (e.g. `rce`/`deserialization`=4, `auth
  bypass`/`sqli`/`privilege escalation`=3, `ssrf`/`xss`/`dos`=2, `info leak`=1;
  unknown type=1);
- `attack_vector`: `network` +2, `adjacent` +1;
- `has_public_poc`: +1.

Buckets: `>=6` → `likely-critical`, `>=4` → `likely-high`, `>=2` →
`likely-medium`, else `likely-low`.

---

## 5. Structured persistence helpers

### 5.1 CVSS vectors → authoritative scores (`persist_cvss_vectors`, `affected.py`)

Normalizes each vector to uppercase, detects the version by prefix
(`CVSS:4` → 4.0, `CVSS:3.1` → 3.1, `CVSS:3.0` → 3.0; else skip), scores it, and
upserts `cvss_scores` with `provenance="authoritative"` and the given `source`.

### 5.2 Affected products (`persist_affected`, `affected.py`)

Upserts `affected_products` on `uq_affected_candidate_product` with
`source="structured"`, canonicalizing the ecosystem, then **replaces** the row's
`affected_version_ranges` (delete existing by `affected_product_id`, insert the
new ranges). Used by the ingest path (OSV structured data).

The enrichment path's `_upsert_affected` writes `source="llm"`, resolving the
alias to a `catalog_id` via `_resolve_alias` (§6) and storing `raw=versions_raw`
and `normalization_method`.

### 5.3 `classify_kind` / `canonical_ecosystem`

- `classify_kind(ecosystem, is_malware)` → `"malware"` if `is_malware`;
  `"distro"` if the ecosystem starts with a known distro name (`ubuntu`,
  `debian`, `alpine`, `red hat`, `android`, …); else `"product"`.
- `canonical_ecosystem(eco)` → lowercased, mapped through `ECO_ALIAS` (e.g.
  `pip`→`pypi`, `cargo`/`rust`/`crates`→`crates.io`, `node`→`npm`,
  `gem`→`rubygems`, `composer`→`packagist`, `golang`→`go`).

---

## 6. `normalize.py` — software canonicalization (skeleton)

`normalize.py` describes a layered vendor/product canonicalizer that links a
"dirty" name to the canonical vocabulary (`product_catalog`) cheapest-first:

1. **exact/alias** — deterministic match against `product_aliases` (normalized
   key);
2. **fuzzy** — top-K catalog candidates (trigram/embedding);
3. **llm** — LLM as a *constrained linker* (picks among the K candidates or
   "none"), never a free-text corrector — this avoids hallucinating products and
   keeps results reproducible;
4. **unresolved** — low confidence → review queue, raw preserved.

**Honest status**: this module is a **skeleton**. `normalize_key(raw)` (Layer 1's
deterministic normalization: NFKD ASCII fold, lowercase, collapse non-alphanum to
single spaces) is **real and in use** — `service._resolve_alias` calls it to look
up `product_aliases` and resolve a `catalog_id`, so **Layer 1 (deterministic
alias resolution) is operational** in the enrichment service. `ProductNormalizer`
and its ports (`AliasRepo`, `CatalogSearch`, `LLMLinker`) are **placeholders**:
the fuzzy (Layer 2) and LLM-linker (Layer 3) layers and their DB-backed
persistence are **not yet implemented** — `AUTO_ACCEPT_THRESHOLD = 0.85` and the
`resolve()` orchestration exist but are wired against interface stubs. Confirmed
LLM/human resolutions are intended to be written back as `product_aliases` so
future lookups hit Layer 1 without an LLM call.

---

## 7. Re-enrichment (`should_reenrich`)

```python
should_reenrich(candidate, *, reenrich_hours, min_new_mentions, mentions_since) -> bool
```

Returns `True` if the candidate has never been enriched
(`enrichment_updated_at is None`), or the enrichment is older than
`reenrich_hours` (setting `enrichment_reenrich_hours`, default 24), or at least
`min_new_mentions` new mentions arrived since (setting
`enrichment_reenrich_min_mentions`, default 3).
