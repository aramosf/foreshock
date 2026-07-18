# Decisiones de diseño

Registro de las decisiones no obvias de Foreshock y su porqué. Cada una remite al
código que la implementa.

---

## 1. El `candidate` está desacoplado del CVE

**Decisión**: la unidad de rastreo es `candidates`, no el CVE. Un candidate
puede existir **antes** de que exista su CVE, anclado por un identificador
nativo (`ZDI-CAN`, `VU#`, `GHCOMMIT`, …).

**Por qué**: la premisa del radar es captar la señal temprana. Muchas señales
(reservas ZDI, notas de CERT/CC, fixes en commits) preceden a la asignación
pública del CVE. Si la clave primaria fuera el CVE, no habría dónde registrar esa
ventana. Cuando el CVE aparece, la reconciliación fusiona los candidates.

*Código*: `app/core/models.py::Candidate`, `app/ingest/reconcile.py`.

---

## 2. `content_hash` sobre el extracto, no sobre el HTML crudo

**Decisión**: la idempotencia de menciones (`UNIQUE(source_id, content_hash)`)
se calcula hasheando `cve + native + title + snippet + url canónica`
normalizados, **no** el HTML de la página.

**Por qué**: el HTML crudo cambia en cada fetch (timestamps, anuncios, tokens
CSRF), lo que crearía una mención nueva cada vez. El extracto semántico es
estable ante re-listados idénticos y solo cambia cuando cambia el contenido
real, que sí merece una entrada nueva en el timeline.

*Código*: `app/ingest/hashing.py`.

---

## 3. El CVSS se calcula, no se adivina

**Decisión**: el LLM devuelve las **métricas base** CVSS; el score se calcula con
la librería `cvss`. Los vectores autoritativos se extraen por regex del texto de
la fuente. Nunca se pide al LLM un número.

**Por qué**: un score CVSS es determinista dado su vector. Pedir el número al LLM
introduce alucinación y hace irreproducible el resultado. Separar "extraer
métricas" (juicio) de "calcular score" (aritmética) da resultados auditables:
`provenance='authoritative'` (vector verbatim) o `'derived'` (métricas LLM), y un
`severity_hint` cualitativo solo cuando no hay número.

*Código*: `app/enrichment/cvss.py`, `app/enrichment/schema.py`,
`app/enrichment/service.py`.

---

## 4. `days_ahead` vs observación propia (`present`)

**Decisión**: se guardan tres deltas de ventaja, pero la métrica de referencia es
`days_ahead_vs_nvd_present`, medida contra `nvd_first_observed_at` (cuándo
Foreshock vio por primera vez el CVE en NVD), no contra `nvd_published_at`.

**Por qué**: NVD hace *backfill* — publica CVEs con fechas retroactivas o
reescribe timestamps. Un delta contra `nvd_published_at` queda distorsionado.
`nvd_first_observed_at` es ground truth de nuestro propio reloj, se sella una
sola vez con `COALESCE` y es inmune al backfill.

*Código*: `app/baseline/nvd.py::upsert_nvd`,
`app/ingest/service.py::compute_days_ahead`.

---

## 5. Canonicalización: el LLM como *linker*, no como corrector

**Decisión**: para canonicalizar nombres de producto, el LLM **elige entre
candidatos existentes** del catálogo (o "ninguno"); nunca reescribe texto libre.
Las resoluciones confirmadas se guardan como `product_aliases` para resolver de
forma determinista la próxima vez.

**Por qué**: un LLM corrigiendo nombres alucina productos inexistentes y produce
salidas no reproducibles, veneno para el dedup y el `cluster_fingerprint`.
Restringirlo a una elección acotada mantiene el resultado determinista y hace que
el sistema **aprenda** (cada acierto se convierte en un alias barato de Capa 1).

*Código*: `app/enrichment/normalize.py`, `app/enrichment/service.py::_resolve_alias`,
migración `0002` (`product_catalog`, `product_aliases`).

---

## 6. FK blanda de `candidates.cve_id`

**Decisión**: `candidates.cve_id` **no** tiene FK a `published_cves`. La
migración `0003_soft_cve_ref.py` elimina el constraint
`candidates_cve_id_fkey`.

**Por qué**: un candidate puede referenciar un CVE solo RESERVADO y aún no
ingerido por el baseline (o que MITRE/NVD no publican todavía). Un FK duro
rechazaría el INSERT y bloquearía justo la señal temprana que es la razón de ser
del proyecto. La reconciliación se hace por *lookup*
(`session.get(PublishedCVE, cve_id)`), no por integridad referencial. El índice
`idx_cand_cve` sostiene ese lookup.

*Código*: `migrations/versions/0003_soft_cve_ref.py`.

---

## 7. Fusión reversible (union-find con tombstone) vs enlace difuso propuesto

**Decisión**: dos mecanismos de correlación distintos.
- **Determinista** (mismo `(scheme, value)`): fusión real por union-find; el
  perdedor queda como *tombstone* (`merged_into`, `status='merged'`), **no se
  borra** → reversible.
- **Difuso** (nombres/huellas parecidas): `candidate_links` solo **propone** un
  enlace (`status='suggested'`), no fusiona nada.

**Por qué**: la evidencia determinista (un identificador compartido) justifica
fusionar; la similitud difusa no, porque un falso positivo mezclaría dos vulns
distintas de forma difícil de deshacer. Mantener la fusión reversible y separar
lo difuso como sugerencia protege la integridad de los datos.

*Código*: `app/ingest/reconcile.py::merge_candidates`, migración `0001`
(`candidate_links`).

---

## 8. Migraciones reversibles y escritas a mano

**Decisión**: las migraciones Alembic son la **fuente de verdad** del esquema,
escritas a mano, con `downgrade()` completo. `env.py` usa
`target_metadata=None` (sin autogenerate). Los modelos SQLModel son solo un
mapeo ORM.

**Por qué**: escribir el DDL a mano permite features de Postgres que el
autogenerate no maneja bien (índices parciales, `NULLS NOT DISTINCT`, vistas,
CHECKs con expresiones). Que los modelos no dirijan el esquema evita que un
cambio accidental en el ORM "cree" o altere tablas. Cada migración es reversible
para poder hacer rollback limpio.

*Código*: `migrations/versions/*.py`, `migrations/env.py`,
`app/core/models.py` (docstring).

---

## 9. Aislamiento de fallos de fetchers y fuentes

**Decisión**: un fetcher que lanza excepción **no tumba el worker**. `run_source`
captura la excepción del `fetch`, la loguea, registra `last_error`/`last_error_at`
en `sources` y devuelve métricas vacías. El baseline aísla igual sus tres
fuentes; el scan de github aísla por repo.

**Por qué**: con muchas fuentes heterogéneas (APIs que cambian, HTML que se
rompe, rate limits), el fallo de una no debe interrumpir la recolección del
resto. El worker sigue vivo y la fuente rota queda marcada para diagnóstico.

*Código*: `app/sources/runner.py::run_source`,
`app/baseline/service.py::run_baseline_async`,
`app/sources/github_commits.py` (try/except por repo),
`app/sources/__main__.py` (doble red de seguridad).
