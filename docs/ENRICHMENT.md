# Enrichment (Layer 3)

Enrichment consolidates a candidate's mentions and extracts structured metadata:
vulnerability type, attack vector, PoC, affected products and **CVSS**.
Orchestrated by `app/enrichment/service.py::enrich_candidate()` (requires an open
session, does **not** commit).

---

## Principle: the LLM extracts METRICS, not a CVSS number

The LLM **never** returns a numeric CVSS score. It returns the CVSS v3.1 **base
metrics** (validated by `app/enrichment/schema.py::CVSSMetricsOut`), and the
score is **computed** deterministically with the `cvss` library. This makes the
result reproducible and auditable, with no "guessed" number. See
`DESIGN_DECISIONS.md`.

`EnrichmentOut` (validated LLM output, Pydantic `extra="forbid"`):
`affected_products[]`, `vuln_type`, `attack_vector`, `requires_auth`,
`requires_interaction`, `has_public_poc`, `poc_urls[]`, `cvss_metrics`,
`summary`, `confidence` (0..1). `CVSSMetricsOut` carries the 8 base metrics:
`attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`,
`scope`, `confidentiality`, `integrity`, `availability`.

---

## 3-level CVSS precedence (`app/enrichment/cvss.py`)

The service never invents a number. There are three paths, in order of
preference:

### 1. Authoritative — `parse_authoritative(text)`
Extracts by **regex** the CVSS vectors present **verbatim** in the source text
(Red Hat, MSRC, CNA…): `CVSS:(3.0|3.1|4.0)/…`. Scores each vector with the
`cvss` library (`CVSS3`/`CVSS4`). Persisted as `provenance='authoritative'`,
`source='source-text'`, `confidence=1.0`. An invalid vector is discarded (no
score).

### 2. Derived — `derive_from_metrics(metrics)`
From the 8 base metrics inferred by the LLM it builds a `CVSS:3.1/…` vector and
scores it. **Only if all 8 metrics are present**; if any is missing, it returns
`None` (an incomplete vector is not forced). Persisted as `provenance='derived'`,
`source='llm-derived'`, with `inferred_metrics` and `confidence = out.confidence`.

### 3. Qualitative `severity_hint` — `severity_hint(...)`
When **there is no numeric score at all** (neither authoritative nor derived), a
qualitative label (`likely-critical/high/medium/low`) is computed from cheap
proxies: `vuln_type` weight (`_TYPE_WEIGHT`: rce=4, deserialization=4,
sqli/auth-bypass/lpe=3…), `attack_vector` (network +2, adjacent +1) and
`has_public_poc` (+1). **This is not CVSS** — it is an estimate.

In `enrich_candidate`, after persisting CVSS, `severity_hint` is set **only** if
there is no `cvss_scores` row with a non-null `base_score` for the candidate.

The `cvss_selected` view (see `DATA_MODEL.md`) picks the best CVSS per candidate,
prioritizing `authoritative` over `derived`, the highest version and the highest
score.

---

## LLM providers (`app/enrichment/llm.py`)

A **provider-neutral** design over `httpx` (not coupled to any SDK). It is chosen
with `get_provider()` based on `CVERADAR_LLM_PROVIDER`:

| `llm_provider` | Class | Endpoint |
|---|---|---|
| `mock` (default) | `MockProvider` | No network. Deterministic heuristic regex extraction; `confidence=0.35`. Useful without an API key and in tests. |
| `openai` | `OpenAIProvider` | `{base}/chat/completions` with `response_format=json_object`. |
| `anthropic` | `AnthropicProvider` | `{base}/v1/messages` (`anthropic-version: 2023-06-01`). |
| `ollama` | `OllamaProvider` | `{base}/api/chat` with `format=json`, local. |

Environment variables (prefix `CVERADAR_`): `LLM_PROVIDER`, `LLM_MODEL`
(default `mock-model`), `LLM_API_KEY`, `LLM_BASE_URL` (e.g. Ollama
`http://ollama:11434`), `LLM_MAX_TOKENS` (default `1024`).

`enrich(cve_id, snippets)` builds the prompt (`app/enrichment/prompts.py`:
`SYSTEM_PROMPT` + `build_user_prompt`), calls the provider, extracts the JSON
(`_extract_json` tolerates markdown wrappers) and validates it against
`EnrichmentOut`. It returns `(result, method)` where `method = "{provider}:{model}"`
(stored in `candidates.enrichment_method`).

---

## Product canonicalization via deterministic alias

Affected products are canonicalized by linking the "dirty" name against the
canonical vocabulary (`product_catalog`) in **layers**, from cheap to expensive.
The LLM is used **only as a constrained *linker*** (choosing among existing
candidates), never as a free-text corrector: this avoids hallucinating products
and keeps the result reproducible.

`app/enrichment/normalize.py::ProductNormalizer.resolve(raw)`:

1. **exact/alias** — `normalize_key(raw)` (lowercase, no accents, collapses
   separators) against `product_aliases`. Deterministic → `confidence=1.0`.
2. **fuzzy** — top-K candidates from the catalog (trigram/embedding).
3. **llm** — the LLM chooses among those K or "none"; if it exceeds
   `AUTO_ACCEPT_THRESHOLD = 0.85`, it **learns**: it writes the alias into
   `product_aliases` so that next time it resolves in Layer 1 without the LLM.
4. **unresolved** — low confidence → review queue, the `raw` value is kept.

> Note: `ProductNormalizer` (layers 2–3) is a skeleton with ports
> (`AliasRepo`/`CatalogSearch`/`LLMLinker`) to be implemented against the real
> DB. The operational path **today** is the deterministic Layer 1 in the service:
> `_resolve_alias` does `normalize_key(f"{vendor} {product}")` → lookup in
> `product_aliases`; on a hit, `normalization_method='alias'`, otherwise
> `'unresolved'` (it stays in the `idx_affected_unresolved` queue).

---

## `enrich_candidate` flow

1. `gather_snippets` collects `title + snippet` from all of the candidate's
   mentions; if there are none, it does not enrich.
2. **Authoritative CVSS**: `parse_authoritative(blob)` → `_upsert_cvss` for each
   vector found.
3. **LLM**: `enrich(cve_id, snippets)` → `EnrichmentOut`.
4. **Derived CVSS**: `derive_from_metrics(out.cvss_metrics)` (if all 8) →
   `_upsert_cvss`.
5. Writes fields onto the candidate: `vuln_type`, `attack_vector`,
   `requires_auth`, `requires_interaction`, `has_public_poc`, `poc_urls`,
   `affected_product` / `affected_versions` (from the first product),
   `enrichment_confidence`, `enrichment_method`, `enrichment_updated_at`.
6. `severity_hint` only if there is no numeric score.
7. Structured `affected_products` → `_upsert_affected` (with alias
   canonicalization).

The upserts use `ON CONFLICT` on the unique constraints
(`uq_cvss_candidate_version_prov_source`, `uq_affected_candidate_product`) → so
re-enrichment updates instead of duplicating.

---

## Re-enrichment — `should_reenrich`

```python
def should_reenrich(candidate, *, reenrich_hours, min_new_mentions,
                    mentions_since) -> bool:
    if candidate.enrichment_updated_at is None:
        return True                 # nunca enriquecido
    age_h = (now - candidate.enrichment_updated_at) / 3600
    return age_h >= reenrich_hours or mentions_since >= min_new_mentions
```

It re-enriches if it was never done, if enough time has passed
(`CVERADAR_ENRICHMENT_REENRICH_HOURS`, default `24`) or if enough new mentions
have arrived (`CVERADAR_ENRICHMENT_REENRICH_MIN_MENTIONS`, default `3`).
