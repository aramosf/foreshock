# Enriquecimiento (Capa 3)

El enriquecimiento consolida las menciones de un candidate y extrae metadatos
estructurados: tipo de vulnerabilidad, vector de ataque, PoC, productos
afectados y **CVSS**. Orquestado por
`app/enrichment/service.py::enrich_candidate()` (requiere sesión abierta, **no**
hace commit).

---

## Principio: el LLM extrae MÉTRICAS, no un número CVSS

El LLM **nunca** devuelve un score CVSS numérico. Devuelve las **métricas base**
CVSS v3.1 (validadas por `app/enrichment/schema.py::CVSSMetricsOut`), y el score
se **calcula** de forma determinista con la librería `cvss`. Así el resultado es
reproducible y auditable, y no se "adivina" un número. Ver `DESIGN_DECISIONS.md`.

`EnrichmentOut` (salida validada del LLM, Pydantic `extra="forbid"`):
`affected_products[]`, `vuln_type`, `attack_vector`, `requires_auth`,
`requires_interaction`, `has_public_poc`, `poc_urls[]`, `cvss_metrics`,
`summary`, `confidence` (0..1). `CVSSMetricsOut` lleva las 8 métricas base:
`attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`,
`scope`, `confidentiality`, `integrity`, `availability`.

---

## Precedencia CVSS de 3 niveles (`app/enrichment/cvss.py`)

El servicio nunca inventa un número. Hay tres caminos, en orden de preferencia:

### 1. Autoritativo — `parse_authoritative(text)`
Extrae por **regex** los vectores CVSS presentes **verbatim** en el texto de las
fuentes (Red Hat, MSRC, CNA…): `CVSS:(3.0|3.1|4.0)/…`. Puntúa cada vector con la
librería `cvss` (`CVSS3`/`CVSS4`). Se persiste como
`provenance='authoritative'`, `source='source-text'`, `confidence=1.0`. Un
vector inválido se descarta (sin score).

### 2. Derivado — `derive_from_metrics(metrics)`
A partir de las 8 métricas base inferidas por el LLM construye un vector
`CVSS:3.1/…` y lo puntúa. **Solo si están las 8 métricas**; si falta cualquiera,
devuelve `None` (no se fuerza un vector incompleto). Se persiste como
`provenance='derived'`, `source='llm-derived'`, con `inferred_metrics` y
`confidence = out.confidence`.

### 3. `severity_hint` cualitativo — `severity_hint(...)`
Cuando **no hay ningún score numérico** (ni autoritativo ni derivado), se calcula
una etiqueta cualitativa (`likely-critical/high/medium/low`) a partir de proxies
baratos: peso del `vuln_type` (`_TYPE_WEIGHT`: rce=4, deserialization=4,
sqli/auth-bypass/lpe=3…), `attack_vector` (network +2, adjacent +1) y
`has_public_poc` (+1). **No es CVSS** — es una estimación.

En `enrich_candidate`, tras persistir CVSS, `severity_hint` se fija **solo** si
no existe ninguna fila de `cvss_scores` con `base_score` no nulo para el
candidate.

La vista `cvss_selected` (ver `DATA_MODEL.md`) elige el mejor CVSS por candidate
priorizando `authoritative` sobre `derived`, versión más alta y score más alto.

---

## Proveedores LLM (`app/enrichment/llm.py`)

Diseño **provider-neutral** sobre `httpx` (sin acoplar a un SDK). Se elige con
`get_provider()` según `CVERADAR_LLM_PROVIDER`:

| `llm_provider` | Clase | Endpoint |
|---|---|---|
| `mock` (default) | `MockProvider` | Sin red. Extracción heurística determinista por regex; `confidence=0.35`. Útil sin API key y en tests. |
| `openai` | `OpenAIProvider` | `{base}/chat/completions` con `response_format=json_object`. |
| `anthropic` | `AnthropicProvider` | `{base}/v1/messages` (`anthropic-version: 2023-06-01`). |
| `ollama` | `OllamaProvider` | `{base}/api/chat` con `format=json`, local. |

Variables de entorno (prefijo `CVERADAR_`): `LLM_PROVIDER`, `LLM_MODEL`
(default `mock-model`), `LLM_API_KEY`, `LLM_BASE_URL` (p.ej. Ollama
`http://ollama:11434`), `LLM_MAX_TOKENS` (default `1024`).

`enrich(cve_id, snippets)` construye el prompt (`app/enrichment/prompts.py`:
`SYSTEM_PROMPT` + `build_user_prompt`), llama al proveedor, extrae el JSON
(`_extract_json` tolera envoltorios de markdown) y valida contra `EnrichmentOut`.
Devuelve `(resultado, método)` donde `método = "{provider}:{model}"` (se guarda
en `candidates.enrichment_method`).

---

## Canonicalización de producto por alias determinista

Los productos afectados se canonicalizan enlazando el nombre "sucio" contra el
vocabulario canónico (`product_catalog`) por **capas**, de barato a caro. El LLM
se usa **solo como *linker* restringido** (elige entre candidatos existentes),
nunca como corrector de texto libre: evita alucinar productos y mantiene el
resultado reproducible.

`app/enrichment/normalize.py::ProductNormalizer.resolve(raw)`:

1. **exact/alias** — `normalize_key(raw)` (lowercase, sin acentos, colapsa
   separadores) contra `product_aliases`. Determinista → `confidence=1.0`.
2. **fuzzy** — top-K candidatos del catálogo (trigram/embedding).
3. **llm** — el LLM elige entre esos K o "ninguno"; si supera
   `AUTO_ACCEPT_THRESHOLD = 0.85`, **aprende**: escribe el alias en
   `product_aliases` para que la próxima vez resuelva en Capa 1 sin LLM.
4. **unresolved** — baja confianza → cola de revisión, se guarda el `raw`.

> Nota: `ProductNormalizer` (capas 2–3) es un esqueleto con puertos
> (`AliasRepo`/`CatalogSearch`/`LLMLinker`) a implementar contra la BD real. La
> ruta operativa **hoy** es la Capa 1 determinista en el servicio:
> `_resolve_alias` hace `normalize_key(f"{vendor} {product}")` → lookup en
> `product_aliases`; si acierta, `normalization_method='alias'`, si no,
> `'unresolved'` (queda en la cola `idx_affected_unresolved`).

---

## Flujo de `enrich_candidate`

1. `gather_snippets` reúne `title + snippet` de todas las menciones del
   candidate; si no hay ninguna, no enriquece.
2. **CVSS autoritativo**: `parse_authoritative(blob)` → `_upsert_cvss` por cada
   vector encontrado.
3. **LLM**: `enrich(cve_id, snippets)` → `EnrichmentOut`.
4. **CVSS derivado**: `derive_from_metrics(out.cvss_metrics)` (si las 8) →
   `_upsert_cvss`.
5. Vuelca campos al candidate: `vuln_type`, `attack_vector`, `requires_auth`,
   `requires_interaction`, `has_public_poc`, `poc_urls`, `affected_product` /
   `affected_versions` (del primer producto), `enrichment_confidence`,
   `enrichment_method`, `enrichment_updated_at`.
6. `severity_hint` solo si no hay score numérico.
7. `affected_products` estructurados → `_upsert_affected` (con canonicalización
   por alias).

Los upserts usan `ON CONFLICT` sobre las restricciones únicas
(`uq_cvss_candidate_version_prov_source`, `uq_affected_candidate_product`) → el
re-enriquecimiento actualiza en vez de duplicar.

---

## Re-enriquecimiento — `should_reenrich`

```python
def should_reenrich(candidate, *, reenrich_hours, min_new_mentions,
                    mentions_since) -> bool:
    if candidate.enrichment_updated_at is None:
        return True                 # nunca enriquecido
    age_h = (now - candidate.enrichment_updated_at) / 3600
    return age_h >= reenrich_hours or mentions_since >= min_new_mentions
```

Se re-enriquece si nunca se hizo, si pasó suficiente tiempo
(`CVERADAR_ENRICHMENT_REENRICH_HOURS`, default `24`) o si llegaron bastantes
menciones nuevas (`CVERADAR_ENRICHMENT_REENRICH_MIN_MENTIONS`, default `3`).
