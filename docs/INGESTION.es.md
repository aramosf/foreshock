# Pipeline de ingesta

El pipeline convierte una **mención** captada por un fetcher
(`FetchedMention`) en filas de `mentions` / `candidates` / `identifiers` de
forma **idempotente**. Los fetchers NO escriben en BD; solo devuelven
`list[FetchedMention]`. Toda la persistencia ocurre en
`app/ingest/service.py::ingest_mention()`.

```python
@dataclass
class FetchedMention:            # app/ingest/service.py
    url: str | None = None
    title: str | None = None
    snippet: str | None = None
    cve_id: str | None = None      # si el fetcher ya lo conoce
    native_id: str | None = None   # p.ej. ZDI-CAN-nnnn, GHSA-…
    extra_ids: list[str] = field(default_factory=list)  # ids declarados que SÍ fusionan; no para CVEs citados en prosa
    raw_html: str | None = None    # contenido crudo a persistir
    seen_at: datetime | None = None
```

---

## Paso 1 — Identidad: solo ids declarados (`app/ingest/identifiers.py`)

La identidad del candidate proviene **solo** de lo que la fuente *declara*:
`extract_identifiers(m.cve_id, m.native_id, *m.extra_ids)`. Estos ids anclan y
fusionan (union-find). Los CVEs meramente citados en `title`/`snippet` **no** se
usan para fusionar: un commit que "arregla 21 CVEs" o una noticia que lista
varios no deben colapsar vulnerabilidades distintas en un solo candidate. Si la
fuente **no declara nada**, se usa como respaldo el **primer** identificador
hallado en el texto (`text_ids[:1]`), no todos. Si aun así queda vacío, la
mención se descarta (`ingest.skip_no_identifier`): sin ancla no puede
correlacionarse.

`extract_identifiers(*texts)` corre una batería de regex sobre la concatenación
de las entradas no vacías, preservando **orden de prioridad**. El primer scheme
de la lista es el "nativo" preferido cuando no hay CVE.

| Scheme | Patrón (resumen) |
|---|---|
| `CVE` | `\bCVE-\d{4}-\d{4,}\b` |
| `ZDI-CAN` | `\bZDI-CAN-\d{3,6}\b` |
| `ZDI` | `\bZDI-\d{2}-\d{3,5}\b` |
| `VU` | `\bVU#\d{5,7}\b` |
| `GHSA` | `\bGHSA-xxxx-xxxx-xxxx\b` (alfabeto base32 restringido) |
| `MSRC` | `\bADV\d{6}\b` |
| `GHCOMMIT` | `\bGHCOMMIT:owner/repo@<sha7-40>\b` (definido, **no** reconocido) |

**Política de descarte — `RECOGNIZED_SCHEMES`** (`{CVE, ZDI-CAN, ZDI, VU, GHSA,
MSRC, OSV}`): si **ninguno** de los ids de identidad pertenece a un scheme
reconocido, la mención se **descarta** (`ingest.skip_unrecognized`) — no se
almacena nada sin un CVE o código oficial equivalente. `GHCOMMIT` es un scheme
**definido** pero deliberadamente **no** reconocido: un commit de seguridad sin
código asignado no se ancla ni se guarda. Junto con
`github_synthesize_candidates=False` (por defecto), `github_commits` por tanto
emite **solo** commits que citan un CVE real.

Normalización (`_canon`): `GHSA` conserva el prefijo en mayúsculas y el cuerpo
en minúsculas (`GHSA-jfh8-c2jp-5v3q`); `GHCOMMIT` **no** se normaliza (owner/repo
y sha son sensibles a mayúsculas); el resto se pasa a mayúsculas.

Helpers: `primary_cve(ids)` devuelve el primer CVE; `primary_native(ids)`
devuelve el primer identificador no-CVE.

---

## Paso 2 — `content_hash` (`app/ingest/hashing.py`)

Regla de diseño: **no se hashea el HTML crudo**. Timestamps, anuncios y tokens
CSRF cambiarían el hash en cada fetch y generarían filas nuevas. Se hashea el
**extracto semántico**:

```python
content_hash(cve, native, title, snippet, url) = sha256(
    "\x1f".join([
        (cve or "").upper(),
        (native or "").upper(),
        normalize_text(title),      # colapsa espacios, lowercase
        normalize_text(snippet),
        canonical_url(url),         # sin fragmento, sin utm_/gclid/…, query ordenada
    ])
)
```

`canonical_url` quita el fragmento, elimina parámetros de tracking
(`utm_`, `mc_`, `fbclid`, `gclid`, `ref`, `source`), ordena la query, baja host
a minúsculas y normaliza la barra final. Consecuencia: re-listado idéntico →
mismo hash → no duplica; cambio real → hash nuevo → mención legítima.

---

## Paso 3 — `resolve_candidate` + merge union-find (`app/ingest/reconcile.py`)

Etapa A de la correlación (enlace **determinista**): un `(scheme, value)`
pertenece a un solo candidate.

`resolve_candidate(session, ids)`:

1. Para cada identificador busca su candidate actual vía
   `_candidate_for_identifier` → `find_root` (sigue la cadena `merged_into`
   hasta la raíz viva, con protección anti-ciclos).
2. **Ninguno conocido** → crea un `Candidate(status="candidate")` nuevo.
3. **Uno** → lo reutiliza.
4. **Varios** → los **fusiona** en un ganador (`_pick_winner` +
   `merge_candidates`).
5. Adjunta los identificadores que falten y fija `cve_id` si aparece un CVE y
   el candidate aún no lo tenía.

**`_pick_winner`**: gana el que ya tiene `cve_id`; a igualdad, el
`first_seen_at` más antiguo.

**`merge_candidates(winner, loser)` — tombstone reversible**:
- Reasigna los hijos del loser al winner: `UPDATE … SET candidate_id = winner`
  en `Identifier`, `Mention`, `CVSSScore`.
- Marca el loser: `merged_into = winner.id`, `status = 'merged'` (no se borra →
  **reversible**: se puede deshacer siguiendo `merged_into`).
- Propaga `cve_id` del loser al winner si el winner no lo tenía.

Este union-find es la fusión **destructiva por evidencia determinista** (mismo
identificador). El dedup **difuso** (nombres/huellas parecidas) va por
`candidate_links` y es solo una propuesta, no fusiona (ver `DATA_MODEL.md`).

---

## Paso 4 — Persistencia del HTML crudo

Si `FetchedMention.raw_html` viene informado, `_persist_raw` lo escribe en
`{raw_html_dir}/{source_id}/{content_hash}.html` (solo si no existe). La ruta se
guarda en `mentions.raw_html_path` para re-parseo sin volver a la fuente.

---

## Paso 5 — Agregados y `compute_days_ahead`

Tras insertar la mención:

- **`_record_soft_references`** (solo ruta nueva): tras insertar la fila
  `mentions`, registra los CVEs citados en la prosa de la nota
  (`extract_identifiers(title, snippet, url)`) que **no** son el CVE anclado en
  `cve_soft_references` (`{cve_id, mention_id, source_id, from_candidate_id,
  context}`). Se **cuentan, no se fusionan** ni entran en identifiers/union-find:
  un cuerpo GHSA o mensaje de commit que cita otros CVEs no debe arrastrar esas
  vulnerabilidades distintas a este candidate; el CVE citado puede ni estar
  publicado aún — ese es el caso interesante. Idempotente vía
  `ON CONFLICT DO NOTHING` en `uq_soft_ref_mention_cve` (ver `DATA_MODEL.md`).
- **`_refresh_aggregates`** recalcula por SQL: `mention_count`, `source_count`
  (distinct `source_id`), `first_seen_at = min(seen_at)`,
  `last_seen_at = max(seen_at)`. Si `status == 'candidate'` y hay ≥1 mención,
  promueve a `emerging`.
- **`compute_days_ahead`** — solo si el candidate tiene `cve_id` reconciliado y
  el CVE existe en `published_cves`: calcula los tres deltas
  (`published`/`present`/`analyzed`, ver `ARCHITECTURE.md`) contra
  `candidate.first_seen_at`. **Promoción = "NVD ya tiene datos"**: si
  `pub.nvd_published_at IS NOT NULL` y el candidate está en `candidate`/`emerging`,
  lo promueve a `published` y sella `promoted_at`. Se gatilla por la **fecha de
  publicación en NVD**, no por el mero estado `state='PUBLISHED'` de cvelist: un
  CVE reservado o sin fecha NVD permanece pre-publicado.

---

## Reglas de idempotencia (resumen)

1. **Dedup de mención**: antes de insertar, se busca
   `(source_id, content_hash)`; si existe, `IngestResult(duplicate=True)` y no se
   hace nada. Respaldado por `UNIQUE(source_id, content_hash)`.
2. **Identificadores**: `UNIQUE(scheme, value)`; solo se adjuntan los que
   faltan.
3. **Sin commit propio**: `ingest_mention` requiere una sesión abierta y **no**
   hace commit; el `runner` gestiona la transacción por lote de mención.
4. Reejecutar un fetch idéntico no crea filas nuevas ni distorsiona los
   agregados.
