"""Estado operativo de la plataforma para el dashboard administrativo.

La API permanece de solo lectura. Los workers publican un heartbeat mínimo en
``sync_state`` porque la API no debe montar el socket privilegiado de Docker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.queries import PENDING_BASE_WHERE_SQL
from app.core.runtime import collect_runtime_metrics

_WORKER_ROLES = ("baseline-worker", "sources-worker")
_HEARTBEAT_STALE_SECONDS = 90
_PENDING_MIN_DATE = "2016-01-01"
_KEY_TABLES = (
    "published_cves",
    "candidates",
    "mentions",
    "affected_products",
    "identifiers",
    "cvss_scores",
    "epss_scores",
    "github_repos",
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _age_seconds(value: datetime | None, now: datetime) -> int | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return max(0, int((now - value).total_seconds()))


def _runtime_rows(session: Session, now: datetime) -> list[dict[str, Any]]:
    stored = {
        row["id"].removeprefix("runtime:"): row
        for row in session.execute(text("""
            SELECT id, extra, updated_at
            FROM sync_state
            WHERE id LIKE 'runtime:%'
        """)).mappings()
    }
    rows: list[dict[str, Any]] = []
    for role in _WORKER_ROLES:
        stored_row = stored.get(role)
        metrics = dict((stored_row or {}).get("extra") or {})
        updated_at = (stored_row or {}).get("updated_at")
        age = _age_seconds(updated_at, now)
        metrics.update({
            "role": role,
            "observed_at": metrics.get("observed_at") or _iso(updated_at),
            "heartbeat_age_seconds": age,
            "online": age is not None and age <= _HEARTBEAT_STALE_SECONDS,
        })
        rows.append(metrics)

    api = collect_runtime_metrics("api")
    api.update({
        "heartbeat_age_seconds": 0,
        "online": True,
    })
    rows.append(api)
    return rows


def _source_rows(
    session: Session,
    now: datetime,
    runtime_rows: list[dict[str, Any]],
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    source_runtime = next(
        (row for row in runtime_rows if row["role"] == "sources-worker"),
        {},
    )
    active = set(source_runtime.get("active") or [])
    queued = set(source_runtime.get("queued") or [])

    rows: list[dict[str, Any]] = []
    summary = {
        "total": 0,
        "enabled": 0,
        "ok": 0,
        "active": 0,
        "queued": 0,
        "error": 0,
        "stale": 0,
        "never": 0,
        "disabled": 0,
    }
    db_rows = session.execute(text("""
        SELECT name, kind, method, tier, enabled, cadence_seconds,
               last_success_at, last_error, last_error_at
        FROM sources
        ORDER BY enabled DESC, tier, name
    """)).mappings()
    for db_row in db_rows:
        row = dict(db_row)
        name = row["name"]
        success_age = _age_seconds(row["last_success_at"], now)
        error_is_current = (
            row["last_error_at"] is not None
            and (
                row["last_success_at"] is None
                or row["last_error_at"] >= row["last_success_at"]
            )
        )
        stale_after = max(int(row["cadence_seconds"]) * 2, 900)
        if not row["enabled"]:
            state = "disabled"
        elif name in active:
            state = "active"
        elif name in queued:
            state = "queued"
        elif error_is_current:
            state = "error"
        elif row["last_success_at"] is None:
            state = "never"
        elif success_age is not None and success_age > stale_after:
            state = "stale"
        else:
            state = "ok"
        row.update({
            "state": state,
            "last_success_at": _iso(row["last_success_at"]),
            "last_error_at": _iso(row["last_error_at"]),
            "success_age_seconds": success_age,
            "stale_after_seconds": stale_after,
        })
        rows.append(row)
        summary["total"] += 1
        summary["enabled"] += int(bool(row["enabled"]))
        summary[state] += 1
    return summary, rows


def _database_status(session: Session) -> dict[str, Any]:
    activity = session.execute(text("""
        SELECT
          count(*)::int AS total,
          count(*) FILTER (WHERE state = 'active')::int AS active,
          count(*) FILTER (WHERE state = 'idle')::int AS idle,
          count(*) FILTER (
            WHERE state = 'idle in transaction' AND pid <> pg_backend_pid()
          )::int
            AS idle_in_transaction,
          count(*) FILTER (
            WHERE state = 'idle in transaction'
              AND pid <> pg_backend_pid()
              AND now() - state_change > interval '30 seconds'
          )::int
            AS long_idle_in_transaction,
          count(*) FILTER (WHERE wait_event_type = 'Lock')::int AS blocked,
          COALESCE(max(EXTRACT(epoch FROM (now() - xact_start)))
            FILTER (
              WHERE xact_start IS NOT NULL AND pid <> pg_backend_pid()
            ), 0)::bigint AS max_transaction_age_seconds
        FROM pg_stat_activity
        WHERE datname = current_database()
    """)).mappings().one()
    database_size = session.execute(
        text("SELECT pg_database_size(current_database())")
    ).scalar_one()
    migration = session.execute(
        text("SELECT version_num FROM alembic_version LIMIT 1")
    ).scalar_one_or_none()
    return {
        **dict(activity),
        "size_bytes": int(database_size),
        "migration": migration,
    }


def _table_inventory(session: Session) -> list[dict[str, Any]]:
    rows = session.execute(text("""
        SELECT relname AS table_name, n_live_tup::bigint AS estimated_rows,
               n_dead_tup::bigint AS dead_rows,
               last_autovacuum, last_autoanalyze
        FROM pg_stat_user_tables
        WHERE relname = ANY(:tables)
        ORDER BY relname
    """), {"tables": list(_KEY_TABLES)}).mappings()
    return [
        {
            **dict(row),
            "last_autovacuum": _iso(row["last_autovacuum"]),
            "last_autoanalyze": _iso(row["last_autoanalyze"]),
        }
        for row in rows
    ]


def _ingestion_status(session: Session) -> dict[str, Any]:
    counts = session.execute(text(f"""
        WITH pending_archive AS MATERIALIZED (
          SELECT c.first_seen_at
          FROM candidates c
          WHERE {PENDING_BASE_WHERE_SQL}
        )
        SELECT
          (SELECT count(*) FROM candidates WHERE merged_into IS NULL)::bigint
            AS candidates,
          (SELECT count(*) FROM mentions)::bigint AS mentions,
          (SELECT count(*) FROM affected_products)::bigint AS affected_products,
          (SELECT count(*) FROM published_cves)::bigint AS published_cves,
          (SELECT count(*) FROM published_cves
             WHERE nvd_published_at IS NOT NULL)::bigint AS nvd_published,
          (SELECT count(*) FROM published_cves
             WHERE state = 'REJECTED')::bigint AS rejected_cves,
          (SELECT count(*) FROM pending_archive
             WHERE first_seen_at >= '{_PENDING_MIN_DATE}'::timestamptz)::bigint
            AS pending_operational,
          (SELECT count(*) FROM pending_archive
             WHERE first_seen_at < '{_PENDING_MIN_DATE}'::timestamptz)::bigint
            AS historical_inconsistencies
    """)).mappings().one()
    repos = session.execute(text("""
        SELECT
          count(*)::bigint AS total,
          count(*) FILTER (WHERE last_scanned_at IS NOT NULL)::bigint
            AS commits_scanned,
          count(*) FILTER (WHERE last_scanned_at IS NULL)::bigint
            AS commits_pending,
          count(*) FILTER (WHERE adv_last_scanned_at IS NOT NULL)::bigint
            AS advisories_scanned,
          count(*) FILTER (WHERE adv_last_scanned_at IS NULL)::bigint
            AS advisories_pending
        FROM github_repos
    """)).mappings().one()
    return {
        **{key: int(value) for key, value in counts.items()},
        "pending_min_date": _PENDING_MIN_DATE,
        "github_repos": {key: int(value) for key, value in repos.items()},
        "tables": _table_inventory(session),
    }


def _sync_rows(session: Session, now: datetime) -> list[dict[str, Any]]:
    rows = session.execute(text("""
        SELECT id, cursor, updated_at
        FROM sync_state
        WHERE id NOT LIKE 'runtime:%'
        ORDER BY id
    """)).mappings()
    return [
        {
            "id": row["id"],
            "cursor": row["cursor"],
            "updated_at": _iso(row["updated_at"]),
            "age_seconds": _age_seconds(row["updated_at"], now),
        }
        for row in rows
    ]


def _alerts(
    runtime_rows: list[dict[str, Any]],
    source_summary: dict[str, int],
    database: dict[str, Any],
) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for worker in runtime_rows:
        if not worker.get("online"):
            alerts.append({
                "severity": "critical",
                "code": "worker_offline",
                "message": f"{worker['role']} no publica heartbeat reciente.",
            })
        elif int(worker.get("zombie_count") or 0) > 0:
            alerts.append({
                "severity": "critical",
                "code": "zombie_processes",
                "message": (
                    f"{worker['role']} informa de "
                    f"{worker['zombie_count']} procesos zombie."
                ),
            })
    if database["blocked"]:
        alerts.append({
            "severity": "critical",
            "code": "database_blocked",
            "message": f"PostgreSQL tiene {database['blocked']} sesiones esperando locks.",
        })
    if database["long_idle_in_transaction"]:
        alerts.append({
            "severity": "warning",
            "code": "idle_transaction",
            "message": (
                "PostgreSQL tiene "
                f"{database['long_idle_in_transaction']} sesiones idle in transaction "
                "durante más de 30 segundos."
            ),
        })
    for state, label in (
        ("error", "con error"),
        ("stale", "retrasados"),
        ("never", "sin una ejecución completada"),
    ):
        if source_summary[state]:
            alerts.append({
                "severity": "warning",
                "code": f"sources_{state}",
                "message": f"{source_summary[state]} fetchers {label}.",
            })
    return alerts


def platform_status(session: Session) -> dict[str, Any]:
    """Construye un snapshot coherente y JSON-friendly del estado operativo."""
    now = datetime.now(UTC)
    runtime_rows = _runtime_rows(session, now)
    source_summary, source_rows = _source_rows(session, now, runtime_rows)
    database = _database_status(session)
    ingestion = _ingestion_status(session)
    sync = _sync_rows(session, now)
    alerts = _alerts(runtime_rows, source_summary, database)
    severity = {alert["severity"] for alert in alerts}
    health = "critical" if "critical" in severity else "degraded" if alerts else "ok"

    online_runtime = [row for row in runtime_rows if row.get("online")]
    return {
        "generated_at": now.isoformat(),
        "health": health,
        "summary": {
            "processes": sum(int(row.get("process_count") or 0) for row in online_runtime),
            "zombies": sum(int(row.get("zombie_count") or 0) for row in online_runtime),
            "threads": sum(int(row.get("thread_count") or 0) for row in online_runtime),
            "workers_online": sum(
                int(bool(row.get("online")))
                for row in runtime_rows
                if row["role"] in _WORKER_ROLES
            ),
            "workers_expected": len(_WORKER_ROLES),
            "fetchers_enabled": source_summary["enabled"],
            "fetchers_total": source_summary["total"],
            "pending_operational": ingestion["pending_operational"],
            "historical_inconsistencies": ingestion["historical_inconsistencies"],
        },
        "workers": runtime_rows,
        "fetchers": {"summary": source_summary, "rows": source_rows},
        "database": database,
        "ingestion": ingestion,
        "sync": sync,
        "alerts": alerts,
    }
