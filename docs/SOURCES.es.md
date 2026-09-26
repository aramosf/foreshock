# Fuentes (fetchers)

Cada fetcher vive en `app/sources/<nombre>.py`, declara una subclase de
`BaseSource` decorada con `@register` y devuelve `list[FetchedMention]`. **No
escribe en BD** (de eso se encarga la ingesta) y **se aísla ante fallos**: si un
fetcher lanza excepción, el worker la captura, la loguea, registra
`last_error`/`last_error_at` en `sources` y sigue con el resto.

---

## El contrato `BaseSource` (`app/sources/base.py`)

```python
class BaseSource(abc.ABC):
    name: str = ""            # identificador único (== sources.name)
    kind: str = ""            # descripción legible del origen
    method: str = "api"       # api | rss | scrape | browser | git
    tier: int = 5             # 1..9 CHECK (0009); en uso 1..5 (prioridad de señal temprana)
    cadence_seconds: int = 3600

    @abc.abstractmethod
    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]: ...

    def seed_row(self) -> dict: ...   # fila para la tabla `sources`
```

`FetchContext` inyecta los recursos compartidos: `http` (`httpx.AsyncClient`),
`settings` y `browser` (`BrowserPool | None`).

Registro y carga:
- `@register` valida que la clase tenga `name`, rechaza duplicados y la añade a
  `REGISTRY`.
- `load_all()` importa todos los módulos de `app/sources/` (excepto `base`,
  `browser`, `runner`, `__main__`) para poblar `REGISTRY`. El resto de módulos
  sin fetchers (`http`, `cache`, `feeds_rss`, `repo_registry`, `gitproc`,
  `gitsrc`) se importan pero no registran nada.
- `sync_registry_to_db()` (`app/sources/runner.py`) crea/actualiza la fila de
  `sources` de cada fetcher. **`cadence_seconds` no se pisa** al re-sincronizar:
  puede haberse ajustado en operación.

### Los 5 métodos (`method`)

Metadato declarativo (guardado en `sources.method`, `CHECK method IN
('api','rss','scrape','browser','git')` desde `0008`); no hay dispatch, cada
`fetch()` implementa su propia recolección.

| `method` | Transporte | Librería / herramienta |
|---|---|---|
| `api` | API JSON/XML | `httpx` |
| `rss` | Feed RSS/Atom | `feedparser` |
| `scrape` | HTML estático | `httpx` + `selectolax` |
| `browser` | Requiere JS | `BrowserPool` (Playwright, opcional; sin fetcher activo) |
| `git` | `git clone --filter=blob:none` + `git log` (sin REST API) | `github_commits` (añadido en `0008`) |

> `nuclei_templates` y `metasploit` declaran `method="api"` pero delegan en
> `scan_single_repo()`, que hoy también recolecta con un **clone git blobless**
> (§github_commits) en vez de la API REST de commits.

---

## Los 32 fetchers (por tier)

La mayoría de feeds RSS/Atom son fetchers **registrados por separado**, generados
a partir de una fila de la tabla `_FEEDS` en `app/sources/feeds_rss.py` (ver
framework RSS abajo). Unos pocos RSS (`certcc_vu`, `thehackernews`,
`jenkins_security`, `kernel_cve`) y todos los no-RSS son módulos escritos a mano.

### Tier 1 — más temprano / máxima prioridad

| `name` | Method | Fuente / URL | Señal |
|---|---|---|---|
| `cisa_kev` | api | `cisa.gov/.../known_exploited_vulnerabilities.json` | CVEs explotados in-the-wild (KEV autoritativo). |
| `vulncheck_kev` | api | `{vulncheck_api_base}/index/vulncheck-kev` | KEV más amplio/temprano (~80% mayor que CISA). Bearer token (`FORESHOCK_VULNCHECK_TOKEN`); inactivo sin él. |
| `certcc_vu` | rss | `kb.cert.org/vuls/atomfeed/` | Notas VU# de CERT/CC; suelen preceder al CVE. |
| `zdi_published` | rss | `zerodayinitiative.com/rss/published/` | Advisories ZDI publicados (CVE + ids ZDI). |
| `zdi_upcoming` | rss | `zerodayinitiative.com/rss/upcoming/` | **Pre-CVE**: advisories ZDI próximos anclados por `ZDI-CAN-*` (a menudo sin CVE aún). |
| `certeu` | rss | `cert.europa.eu/publications/security-advisories-rss` | Advisories de seguridad de CERT-EU. |

### Tier 2 — PSIRTs de fabricante

| `name` | Method | Fuente / URL | Señal |
|---|---|---|---|
| `redhat_csaf` | api | `access.redhat.com/hydra/rest/securitydata/cve.json` | CVEs recientes + vector CVSS v3 **autoritativo**. |
| `siemens_cert` | rss | `cert-portal.siemens.com/productcert/rss/advisories.atom` | Advisories de Siemens ProductCERT. |
| `paloalto` | rss | `security.paloaltonetworks.com/rss.xml` | Advisories de Palo Alto Networks. |
| `spring_security` | rss | `spring.io/security.atom` | Advisories de Spring Security. |
| `fortiguard_psirt` | rss | `fortiguard.com/rss/ir.xml` | Advisories IR de FortiGuard PSIRT. |
| `veeam` | rss | `veeam.com/services/open/kb/security-feed` | Advisories de seguridad de Veeam. |
| `cisco_psirt` | api | `sec.cloudapps.cisco.com/security/center/publicationService.x?advisoryFormat=json` | Advisories de Cisco PSIRT. |
| `msrc` | rss | `api.msrc.microsoft.com/update-guide/rss` | Microsoft Security Response Center (Update Guide). |
| `jenkins_security` | rss | `jenkins.io/security/advisories/rss.xml` | Advisories de seguridad de Jenkins. |
| `github_repo_advisories` | api | `api.github.com/repos/{o}/{r}/security/advisories` + `/releases` | GHSA por-repo + notas de release escaneadas por CVE. PAT opcional (sube el rate limit). |

### Tier 3 — artefactos de exploit/detección y listas de disclosure

| `name` | Method | Fuente / URL | Señal |
|---|---|---|---|
| `nessus` | scrape | `tenable.com/plugins/nessus/newest` | Plugin puede citar un CVE aún **RESERVADO**. |
| `nuclei_templates` | api (git) | `github.com/projectdiscovery/nuclei-templates` (commits) | Plantilla nueva ≈ explotación masiva inminente. PAT de GitHub recomendado. |
| `metasploit` | api (git) | `github.com/rapid7/metasploit-framework` (commits) | Módulo de exploit nuevo = exploit fiable existe. PAT de GitHub recomendado. |
| `fulldisclosure` | rss | `seclists.org/rss/fulldisclosure.rss` | Lista Full Disclosure. |
| `oss_security` | rss | `seclists.org/rss/oss-sec.rss` | Lista oss-security. |
| `exploitdb` | api (CSV) | `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | Archivo de Exploit-DB; existe un exploit público (puede citar un CVE aún reservado). |
| `wordfence` | api | `wordfence.com/api/intelligence/v3/vulnerabilities/production` | Vulns de WordPress (plugins/themes/core). API key gratuita (`FORESHOCK_WORDFENCE_API_KEY`); inactivo sin ella. |
| `poc_in_github` | git | `github.com/nomi-sec/PoC-in-GitHub` | CVE → repos con PoC público. |
| `trickest_cve` | git | `github.com/trickest/cve` | CVE → PoC + producto. |

### Tier 4 — feeds de advisories y escaneo de commits

| `name` | Method | Fuente / URL | Señal |
|---|---|---|---|
| `github_advisories` | api | `api.github.com/advisories` | GHSA + CVE + paquetes afectados. PAT opcional (sube el rate limit). |
| `github_commits` | git | clone blobless + `git log` de los repos vigilados | CVEs citados en mensajes de commit (a menudo reservados). PAT (embebido en la URL del clone). |
| `osv` | api | `osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip` | Advisories por ecosistema, datos estructurados ricos. |
| `gemnasium` | git | `gitlab.com/gitlab-org/security-products/gemnasium-db` | Snapshot de la GitLab Advisory Database. |
| `kernel_cve` | rss | `lore.kernel.org/linux-cve-announce/new.atom` | CVEs del kernel Linux (linux-cve-announce). |

### Tier 5 — noticias / resúmenes

| `name` | Method | Fuente / URL | Señal |
|---|---|---|---|
| `thehackernews` | rss | `feeds.feedburner.com/TheHackersNews` | Noticias; a veces tempranas en campañas activas. |
| `zdi_blog` | rss | `zerodayinitiative.com/blog/?format=rss` | Resúmenes del blog de ZDI (contexto). |

Notas transversales:

- Los fetchers **KEV** (`cisa_kev`, `vulncheck_kev`) fijan `flags={"in_kev":
  True, "kev_date": <fecha>, "kev_source": "cisa"|"vulncheck"}`; `in_kev` es la
  señal de máxima prioridad. `vulncheck_kev` abre un registro KEV con varios
  `cve` en una mención por CVE.
- `redhat_csaf` coloca el vector CVSS en el snippet (`... | CVSS: <vector>`), que
  el enriquecimiento extrae como autoritativo; la `severity` va como
  `[severity] descripción`.
- `github_advisories` adjunta `native_id=ghsa_id`, `cve_id=cve` (si asignado) y
  pliega los paquetes afectados en el snippet (`... | affected: ...`).
- Los fetchers **RSS** parsean con `feedparser` usando
  `published_parsed`/`updated_parsed` como `seen_at`; solo emiten mención si la
  entrada contiene un **código reconocido** — ver la regla entrada→mención en el
  framework RSS.

El **tier** codifica la prioridad de señal temprana (1 = fuente que suele
adelantarse más al CVE público). Se usa para filtrar en la CLI (`emerging
--tier`) y para atribuir ventaja media por fuente (`stats`).

### Framework de feeds RSS/Atom (`app/sources/feeds_rss.py`)

La tabla `_FEEDS` genera **12** fetchers RSS/Atom **data-driven**: filas
`(name, kind, tier, url)` (con un 5º elemento opcional `browser_ua`), una subclase
de `BaseSource` generada dinámicamente por fila (`method="rss"`,
`cadence_seconds=3600`), todas registradas vía `register`. Añadir un feed = añadir
una fila. (Los otros cuatro RSS —`certcc_vu`, `thehackernews`, `jenkins_security`,
`kernel_cve`— son módulos escritos a mano con parseo propio, no filas de `_FEEDS`.)

Cada entrada se convierte en menciones con `_mentions_for_entry`, aplicando la
misma política anti-sobre-fusión del resto del pipeline. Corre
`extract_identifiers(title, summary)`, conserva solo los esquemas **reconocidos**
(`RECOGNIZED_SCHEMES` = CVE, ZDI-CAN, ZDI, VU, GHSA, MSRC, OSV) y luego:

| La entrada contiene | Resultado |
|---|---|
| **exactamente 1 CVE** | una mención con ese `cve_id`; los otros códigos reconocidos no-CVE (ZDI-CAN, VU, …) viajan como `extra_ids` (misma vuln, fusionan). |
| **>1 CVE** | una mención **por CVE** (vulns distintas en un mismo boletín), cada una anclando su candidate — **sin bundling**, evita sobre-fusión. |
| **0 CVE pero un código reconocido** (p. ej. un `ZDI-CAN` de un advisory ZDI «upcoming») | una mención anclada por ese código como `native_id` (**pre-CVE puro**). |
| **ningún id reconocido** | descartada (la ingesta la descartaría igual). |

Por eso `zdi_upcoming` produce candidates pre-CVE: un advisory upcoming solo
lleva un `ZDI-CAN-*`, que ancla un candidate que la reconciliación fusiona con el
CVE cuando aparece.

---

## `github_commits` en detalle — clone blobless + caché de git-log

`app/sources/github_commits.py` vigila un **registro de repos de GitHub** (ver
watchlist abajo) y escanea sus commits buscando señal temprana: **commits cuyo
mensaje cita un CVE** (regex `CVE-\d{4}-\d{4,7}`, case-insensitive), a menudo
reservado, aún no público en NVD/MITRE.

**Una mención por CVE distinto** (`_mentions_from_log`): un mensaje de commit
puede corregir varios CVEs. El escáner recoge **todos los CVEs distintos** del
mensaje y emite **una mención por CVE**, cada una con un único `cve_id` anclando
su propio candidate — un commit «lote de N CVEs» se vuelve N menciones
independientes, nunca un bloque fusionado (misma política anti-sobre-fusión del
pipeline).

**Clone shallow blobless en vez de la API REST** (`_git_scan`): el viejo escaneo
commit-a-commit por REST topaba en 5000 req/h. Ahora corre

```
git clone --filter=blob:none --no-checkout --quiet --shallow-since=<YYYY-MM-DD> <url> <tmp>
git -C <tmp> log --since=<YYYY-MM-DD> --pretty=format:'%H\x1f%cI\x1f%B\x1e'
```

que descarga solo objetos commit/tree (sin contenido de archivos) y lee los
mensajes de un `git log` local. **Sin rate limit de API**, transferencia mínima.
El clone va a un tmp bajo `{data_dir}/clones` y se elimina en un `finally`. Si hay
`FORESHOCK_GITHUB_TOKEN` se embebe en la URL del clone
(`https://x-access-token:<token>@github.com/...`, nunca logueado).

**Caché comprimida de git-log** (`_write_gitlog_cache`): tras cada escaneo los
registros relevantes —solo commits que citan un CVE o casan con la regex de
lenguaje de seguridad `_SECFIX`— se escriben con gzip en
`{cache_dir}/gitlog/<owner__repo>.log.gz` (primera línea = nombre del repo, luego
los registros separados por `\x1e`). Es lossless para el parser (los commits
irrelevantes no producen nada) pero diminuto, y permite **re-extraer sin clonar**
tras un bug del parser: `reextract_from_cache()` re-parsea cada log cacheado con
el código actual (cero red). Se expone como `foreshock sources reextract-commits`
(ver `CLI.md`).

**Escaneo por lotes** (`GitHubCommitsSource.fetch`): si el registro está vacío lo
bootstrappea (`harvest_references()` + `harvest_top_n()`). Cada ejecución toma un
`next_batch(github_repos_per_run)` (default `150`) de repos, ordenados
no-escaneados-primero (ver watchlist). Por repo, `since = max(cutoff, watermark)`
donde el cutoff es `github_commits_since` (fijo, default `2026-05-01`) o una
ventana relativa `github_commits_months` (default `5`). Tras escanear, el lote
entero se marca con `update_scan()` (registra `last_scanned_at` y la fecha de
commit más nueva como nuevo `watermark`) para que rote y nunca re-escanee los
mismos commits. Un repo que falla se captura (`github.repo_error`) y no tumba el
lote.

**Sin anclaje de commits desnudos por defecto.** `github_synthesize_candidates`
vale **`False`** por defecto, así que los fixes de seguridad *sin* CVE **no** se
emiten como anclas sintéticas `GHCOMMIT` — la ingesta los descartaría igual (no
son un `RECOGNIZED_SCHEME`, ver `INGESTION.md`). Solo los commits que citan un CVE
real producen menciones.

`scan_single_repo(...)` es el helper que usan `nuclei_templates` y `metasploit`:
escanea **un** repo sobre una ventana de N meses (`github_commits_months`, default
`5`) con `synthesize=False`, vía el mismo clone blobless.

## Watchlist / registro de repos de GitHub (`app/sources/repo_registry.py`)

`github_commits` ya no guarda ficheros JSON de estado. Consume la tabla
`github_repos` (migración `0010`, PK `full_name`), que **unifica toda estrategia
de descubrimiento**: un repo añadido por varias estrategias es una sola fila
(dedup por PK), y un `watermark` por repo garantiza que ninguno se re-escanee ni
duplique. `upsert_repos` deduplica en conflicto, subiendo `priority` al `GREATEST`
y rellenando `stars` faltantes.

Estrategias de descubrimiento (cada una es una función `harvest_*`; `harvest_all`
las corre en orden, expuesta como `foreshock sources harvest-repos`):

| `origin` | Prioridad | Fuente | Activada |
|---|---|---|---|
| `top_n` | 0 | Top-N repos por estrellas vía Search API de GitHub, ventanas descendentes de estrellas (`stars:>=50`, luego `stars:{floor}..{page_min}`), hasta `github_top_n` (default `1000`). **Se mantiene — adicional, no reemplazo.** | siempre |
| `reference` | 10 | Repos citados en URLs de referencia de advisories: `mentions.url`, `cve_reference.url`, `candidates.reference_urls[]` → `github.com/owner/repo`. | siempre |
| `past_cve` | 20 | Subconjunto de `reference` cuyo candidate citante **ya tiene un CVE** (mayor prioridad). | siempre |
| `criticality` | 15 | CSV de OpenSSF Criticality Score (cualquier columna con URL de GitHub). | opt-in vía `FORESHOCK_CRITICALITY_CSV_URL` |
| `downloads` | 15 | Top paquetes PyPI por descargas → el repo de cada paquete. | opt-in vía `FORESHOCK_PYPI_DOWNLOADS_TOP_N > 0` |

`_extract_repo` normaliza una URL a `owner/repo`, saltándose segmentos de owner
no-repo (`advisories`, `sponsors`, `orgs`, `security`, …) y un `.git` final.

**Orden de escaneo** (`next_batch`): `ORDER BY last_scanned_at ASC NULLS FIRST,
priority DESC, stars DESC NULLS LAST, full_name` — repos nunca escaneados
primero, luego mayor prioridad, luego más estrellas. `update_scan` sella
`last_scanned_at` y avanza el `watermark`.

---

## `BrowserPool` (`app/sources/browser.py`)

Pool de contextos Playwright **seguro ante concurrencia** para fetchers
`method=browser`. Playwright es dependencia **opcional** (extra `browser`);
importar el módulo no falla si no está instalada — solo falla al construir el
pool.

Diseño y motivos:

- **Un contexto persistente por fuente** (`launch_persistent_context` con
  `user-data-dir` propio bajo `{data_dir}/browser/<source>`): cookies/sesión
  durables y aislamiento entre fuentes.
- **Lock por fuente** (`asyncio.Lock` en `self._locks[source]`): nunca dos
  fetches concurrentes sobre el mismo contexto (los contextos Playwright **no**
  son seguros para uso concurrente).
- **Semáforo global** (`asyncio.Semaphore(browser_max_concurrent)`, default `3`):
  acota páginas simultáneas → memoria acotada.
- **Reciclado** (`browser_recycle_after`, default `50`): tras N usos, o ante
  crash al abrir una página, el contexto se cierra y renace en el próximo intento
  (los contextos leakean memoria con el tiempo).

`page(source)` es un `asynccontextmanager` que combina lock + semáforo, cede una
`Page` exclusiva y garantiza cierre + conteo de usos en el `finally`.

---

## HTTP educado (`app/sources/http.py`)

- **User-Agent identificable** desde `settings.user_agent`
  (`Foreshock/0.1 (+…; early-CVE research)`), sin rotar IP.
- **`robots.txt`** respetado (`respect_robots`, default `True`) y **cacheado**
  por host (`_robots_cache`). Si no hay robots accesible → se permite.
- **Retries con backoff exponencial** (`tenacity`: `stop_after_attempt(3)`,
  `wait_exponential(min=1, max=20)`) sobre `TransportError`/`HTTPStatusError`.
- `follow_redirects=True`, timeout `http_timeout_seconds` (default `30s`).
- `get()` comprueba robots, hace `raise_for_status()` y reintenta.

---

## Cómo añadir un fetcher

1. Crea `app/sources/mi_fuente.py`.
2. Subclasa `BaseSource`, decórala con `@register`, define atributos de clase e
   implementa `fetch`.
3. Devuelve `list[FetchedMention]`; **no** toques la BD.
4. Registra en la tabla: `foreshock sources sync` (o el arranque del
   `sources-worker` lo hace). Ejecútalo con `foreshock sources run mi_fuente`.

```python
# app/sources/example_json.py
from __future__ import annotations

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://example.org/api/recent-vulns.json"


@register
class ExampleSource(BaseSource):
    name = "example_json"
    kind = "Example vuln feed (JSON API)"
    method = "api"
    tier = 3
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        resp = await get(ctx.http, API)
        out: list[FetchedMention] = []
        for item in resp.json():
            out.append(
                FetchedMention(
                    url=item.get("url"),
                    title=item.get("title"),
                    snippet=(item.get("description") or "")[:2000],
                    cve_id=item.get("cve"),        # si lo conoces
                )
            )
        return out
```

La idempotencia y la correlación las garantiza el pipeline de ingesta; el
fetcher solo tiene que devolver menciones limpias.
