"""Sincronización del repo CVEProject/cvelistV5 (baseline de `published_cves`).

cvelistV5 es el volcado oficial y canónico de los registros CVE 5.x. Lo
mantenemos como clon git superficial (`--depth 1`) y en cada ejecución hacemos
`git pull`, procesando únicamente los ficheros JSON que hayan cambiado entre la
revisión anterior y la nueva (delta barato). En el primer clon, o si se fuerza,
se procesan todos los JSON del árbol.

El parseo (`parse_cve_record`) es una función pura y testeable: no toca red ni
BD, solo transforma el dict del JSON CVE 5.x en el dict de columnas de
`PublishedCVE`. La escritura es idempotente vía `INSERT ... ON CONFLICT`.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dateutil.parser import isoparse
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.baseline.state import read_cursor, write_cursor
from app.core.config import get_settings
from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import PublishedCVE

log = get_logger(__name__)

_SYNC_ID = "cvelist"  # fila de sync_state con el SHA del último HEAD PROCESADO
_COMMIT_EVERY = 2000  # ficheros por transacción en procesados masivos


def _parse_dt(value: str | None) -> datetime | None:
    """Convierte una fecha ISO-8601 a datetime *aware* (o None)."""
    if not value:
        return None
    dt = isoparse(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def parse_cve_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Extrae de un JSON CVE 5.x el subconjunto de columnas de `PublishedCVE`.

    Función PURA: sin efectos de red ni BD. Devuelve un dict con las claves de
    `PublishedCVE` que gestiona cvelist (nunca los campos ``nvd_*``) más
    ``raw_json`` con el registro original.
    """
    meta = raw.get("cveMetadata") or {}
    containers = raw.get("containers") or {}
    cna_container = containers.get("cna") or {}
    cna_provider = (cna_container.get("providerMetadata") or {}).get("shortName")

    assigner = meta.get("assignerShortName")
    cna = assigner or cna_provider

    return {
        "id": meta.get("cveId"),
        "state": meta.get("state"),
        "cvelist_published_at": _parse_dt(meta.get("datePublished")),
        "cvelist_updated_at": _parse_dt(meta.get("dateUpdated")),
        "assigner_short_name": assigner,
        "cna": cna,
        "raw_json": raw,
    }


def upsert_published(session: Session, record: dict[str, Any]) -> None:
    """Inserta/actualiza una fila de `published_cves` desde cvelist (idempotente).

    Usa ``ON CONFLICT (id) DO UPDATE`` actualizando estado, fechas de cvelist,
    cna/assigner, raw_json e ``ingested_at``. NO toca los campos ``nvd_*``: esos
    son ground truth propio poblado por el módulo NVD.
    """
    now = datetime.now(UTC)
    values = {
        "id": record["id"],
        "state": record.get("state") or "PUBLISHED",
        "cvelist_published_at": record.get("cvelist_published_at"),
        "cvelist_updated_at": record.get("cvelist_updated_at"),
        "assigner_short_name": record.get("assigner_short_name"),
        "cna": record.get("cna"),
        "raw_json": record.get("raw_json"),
        "ingested_at": now,
    }
    stmt = insert(PublishedCVE).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["id"],
        set_={
            "state": stmt.excluded.state,
            "cvelist_published_at": stmt.excluded.cvelist_published_at,
            "cvelist_updated_at": stmt.excluded.cvelist_updated_at,
            "assigner_short_name": stmt.excluded.assigner_short_name,
            "cna": stmt.excluded.cna,
            "raw_json": stmt.excluded.raw_json,
            "ingested_at": stmt.excluded.ingested_at,
        },
    )
    session.execute(stmt)


def _run_git(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    """Ejecuta git de forma segura (sin shell) y devuelve el proceso completado."""
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _clone(repo_dir: str, repo_url: str) -> None:
    """Clon superficial del repositorio cvelistV5."""
    Path(repo_dir).parent.mkdir(parents=True, exist_ok=True)
    _run_git(["clone", "--depth", "1", repo_url, repo_dir])


def _head_sha(repo_dir: str) -> str:
    """SHA del HEAD actual del clon."""
    return _run_git(["rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()


def _filter_cve_json(lines: list[str]) -> list[str]:
    """Filtra las rutas a los JSON de registros CVE (cves/**/*.json)."""
    return [
        line.strip()
        for line in lines
        if line.strip().endswith(".json") and line.strip().startswith("cves/")
    ]


def _changed_json_files(repo_dir: str, base: str = "HEAD@{1}") -> list[str]:
    """Lista los JSON cambiados entre ``base`` y el HEAD actual.

    ``base`` es el SHA del último HEAD PROCESADO con éxito (cursor de
    sync_state); con el fallback histórico ``HEAD@{1}`` una pasada fallida
    perdía para siempre sus ficheros, porque el pull ya había movido el reflog.
    """
    proc = _run_git(["diff", "--name-only", base, "HEAD"], cwd=repo_dir)
    return _filter_cve_json(proc.stdout.splitlines())


def _all_json_files(repo_dir: str) -> list[str]:
    """Lista (relativa) todos los JSON de registros CVE del árbol clonado."""
    root = Path(repo_dir)
    cves_dir = root / "cves"
    base = cves_dir if cves_dir.is_dir() else root
    return [
        str(p.relative_to(root))
        for p in base.rglob("*.json")
        if p.name.startswith("CVE-")
    ]


def _strip_nul(obj: Any) -> Any:
    """Elimina recursivamente ``\\u0000`` de los strings de un JSON.

    Postgres rechaza NUL dentro de JSONB (``unsupported Unicode escape
    sequence``); algunos registros de cvelist lo traen en descripciones. Se
    sanea ANTES del upsert para que la fila no envenene la transacción.
    """
    if isinstance(obj, str):
        return obj.replace("\u0000", "")
    if isinstance(obj, dict):
        return {_strip_nul(k): _strip_nul(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_nul(v) for v in obj]
    return obj


def _process_files(repo_dir: str, rel_paths: list[str]) -> dict[str, int]:
    """Parsea y hace upsert de la lista de ficheros JSON dada. Idempotente.

    - Savepoint (``begin_nested``) por fichero: una fila mala (JSON inválido
      para Postgres, etc.) se revierte sola y NO envenena la transacción del
      resto del lote (mismo patrón que nvd.py).
    - Lotes con commit periódico (``_COMMIT_EVERY``): el procesado masivo
      inicial (~270k ficheros) no acumula una única transacción gigante.
    """
    root = Path(repo_dir)
    stats = {"files": 0, "upserted": 0, "skipped": 0, "errors": 0}
    for i in range(0, len(rel_paths), _COMMIT_EVERY):
        batch = rel_paths[i : i + _COMMIT_EVERY]
        with session_scope() as session:
            for rel in batch:
                path = root / rel
                if not path.is_file():
                    # Fichero borrado en el delta: no hay nada que insertar.
                    stats["skipped"] += 1
                    continue
                stats["files"] += 1
                try:
                    raw = _strip_nul(json.loads(path.read_text(encoding="utf-8")))
                    record = parse_cve_record(raw)
                    if not record.get("id"):
                        stats["skipped"] += 1
                        continue
                    with session.begin_nested():
                        upsert_published(session, record)
                    stats["upserted"] += 1
                except Exception as exc:  # noqa: BLE001 - un JSON malo no tumba el sync
                    stats["errors"] += 1
                    log.warning("cvelist.parse_error", path=rel, error=str(exc))
        if len(rel_paths) > _COMMIT_EVERY:
            log.info("cvelist.progress", done=min(i + _COMMIT_EVERY, len(rel_paths)),
                     total=len(rel_paths))
    return stats


def sync_cvelist(force_full: bool = False) -> dict[str, int]:
    """Sincroniza el repo cvelistV5 y persiste los registros CVE cambiados.

    - Si el directorio no existe: ``git clone --depth 1`` y se procesan TODOS
      los JSON del árbol.
    - Si existe: ``git pull`` y se procesan los JSON cambiados desde el ÚLTIMO
      HEAD PROCESADO con éxito (cursor 'cvelist' en ``sync_state``), salvo que
      ``force_full`` fuerce el reprocesado completo. El cursor se guarda SOLO
      tras completar el procesado: una pasada fallida se recupera en la
      siguiente ejecución en lugar de perder sus ficheros (el ``git pull``
      mueve el reflog antes de procesar, así que ``HEAD@{1}`` no servía).
    - Primera ejecución sin cursor sobre un clon existente: delta por reflog
      (comportamiento histórico) con fallback a full.

    Devuelve un dict de métricas (ficheros procesados, upserts, saltados,
    errores). Idempotente: reejecutar no duplica filas.
    """
    settings = get_settings()
    repo_dir = settings.cvelist_repo_dir
    repo_url = settings.cvelist_repo_url

    fresh_clone = not Path(repo_dir).is_dir()
    if fresh_clone:
        log.info("cvelist.clone", repo_dir=repo_dir, url=repo_url)
        _clone(repo_dir, repo_url)
        rel_paths = _all_json_files(repo_dir)
    else:
        _run_git(["pull", "--ff-only"], cwd=repo_dir)
        if force_full:
            rel_paths = _all_json_files(repo_dir)
        else:
            cursor = read_cursor(_SYNC_ID)
            if cursor:
                try:
                    rel_paths = _changed_json_files(repo_dir, base=cursor)
                except subprocess.CalledProcessError:
                    # El SHA guardado ya no existe (re-clon, gc del shallow...):
                    # reprocesado completo para no dejar huecos.
                    log.warning("cvelist.cursor_lost", cursor=cursor)
                    rel_paths = _all_json_files(repo_dir)
            else:
                try:
                    # Sin cursor todavía: delta por reflog (comportamiento previo).
                    rel_paths = _changed_json_files(repo_dir)
                except subprocess.CalledProcessError:
                    # Sin revisión previa (p.ej. primer pull tras clone manual).
                    rel_paths = _all_json_files(repo_dir)

    stats = _process_files(repo_dir, rel_paths)
    # Procesado completado: confirmar el HEAD como último punto procesado.
    write_cursor(_SYNC_ID, _head_sha(repo_dir))
    log.info(
        "cvelist.sync",
        fresh_clone=fresh_clone,
        force_full=force_full,
        candidates=len(rel_paths),
        **stats,
    )
    return stats
