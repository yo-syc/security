import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "netguard.db"
TRUSTED_PATH = BASE_DIR / "trusted_devices.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                hostname TEXT NOT NULL DEFAULT 'Unknown',
                is_trusted BOOLEAN NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'offline'
                    CHECK (status IN ('online', 'offline')),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                alert_type TEXT NOT NULL CHECK (alert_type IN ('Warning', 'Normal')),
                message TEXT NOT NULL,
                is_acknowledged BOOLEAN NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                event TEXT NOT NULL
                    CHECK (event IN ('Connected', 'Disconnected', 'Trusted', 'Untrusted')),
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                subnet TEXT NOT NULL DEFAULT '192.168.1.0/24',
                scan_interval INTEGER NOT NULL DEFAULT 5,
                desktop_notifications BOOLEAN NOT NULL DEFAULT 1
            );
            INSERT INTO settings (subnet, scan_interval, desktop_notifications)
            SELECT '192.168.1.0/24', 5, 1
            WHERE NOT EXISTS (SELECT 1 FROM settings);
            """
        )


def _read_trusted_file() -> set[str]:
    try:
        data = json.loads(TRUSTED_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return set()
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unable to read {TRUSTED_PATH}: {error}") from error
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected an object in {TRUSTED_PATH}")
    trusted = data.get("trusted", [])
    if not isinstance(trusted, list):
        raise RuntimeError(f"Expected a list in {TRUSTED_PATH}")
    return {str(mac).strip().lower() for mac in trusted if str(mac).strip()}


def _write_trusted_file(trusted: set[str]) -> None:
    try:
        TRUSTED_PATH.write_text(
            json.dumps({"trusted": sorted(trusted)}, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise RuntimeError(f"Unable to write {TRUSTED_PATH}: {error}") from error


def sync_trusted_devices() -> None:
    trusted = _read_trusted_file()
    with get_connection() as connection:
        if trusted:
            placeholders = ",".join("?" for _ in trusted)
            connection.execute(
                f"UPDATE devices SET is_trusted = 0 WHERE mac NOT IN ({placeholders})",
                tuple(trusted),
            )
            for mac in trusted:
                connection.execute(
                    """
                    INSERT INTO devices
                        (mac, ip, hostname, is_trusted, status, first_seen, last_seen)
                    VALUES (?, 'Unknown', 'Unknown', 1, 'offline', ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET is_trusted = 1
                    """,
                    (mac, utc_now(), utc_now()),
                )
        else:
            connection.execute("UPDATE devices SET is_trusted = 0")


def initialize() -> None:
    init_db()
    sync_trusted_devices()


def get_settings() -> dict[str, Any]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT subnet, scan_interval, desktop_notifications FROM settings LIMIT 1"
        ).fetchone()
    return dict(row)


def update_settings(values: dict[str, Any]) -> dict[str, Any]:
    current = get_settings()
    subnet = str(values.get("subnet", current["subnet"])).strip()
    scan_interval = int(values.get("scan_interval", current["scan_interval"]))
    notification_value = values.get(
        "desktop_notifications", current["desktop_notifications"]
    )
    if isinstance(notification_value, str):
        notification_value = notification_value.strip().lower() in {"1", "true", "yes", "on"}
    desktop_notifications = int(bool(notification_value))
    if not subnet or scan_interval < 1:
        raise ValueError("A subnet and a scan interval of at least one second are required")
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE settings
            SET subnet = ?, scan_interval = ?, desktop_notifications = ?
            """,
            (subnet, scan_interval, desktop_notifications),
        )
    return get_settings()


def trusted_macs() -> set[str]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT mac FROM devices WHERE is_trusted = 1"
        ).fetchall()
    return {row["mac"] for row in rows}


def set_trusted(mac: str, trusted: bool, ip: str = "Unknown") -> dict[str, Any]:
    mac = mac.strip().lower()
    now = utc_now()
    with get_connection() as connection:
        row = connection.execute(
            "SELECT mac, ip, hostname, status, first_seen, last_seen FROM devices WHERE mac = ?",
            (mac,),
        ).fetchone()
        if row:
            connection.execute(
                "UPDATE devices SET is_trusted = ?, ip = ? WHERE mac = ?",
                (int(trusted), ip if ip != "Unknown" else row["ip"], mac),
            )
        else:
            connection.execute(
                """
                INSERT INTO devices
                    (mac, ip, hostname, is_trusted, status, first_seen, last_seen)
                VALUES (?, ?, 'Unknown', ?, 'offline', ?, ?)
                """,
                (mac, ip, int(trusted), now, now),
            )
        connection.execute(
            "INSERT INTO history (mac, ip, event, timestamp) VALUES (?, ?, ?, ?)",
            (mac, ip, "Trusted" if trusted else "Untrusted", now),
        )
        if trusted:
            connection.execute(
                """
                INSERT INTO alerts (mac, ip, alert_type, message, created_at)
                VALUES (?, ?, 'Normal', 'New trusted device connected', ?)
                """,
                (mac, ip, now),
            )
    trusted_set = trusted_macs()
    _write_trusted_file(trusted_set)
    return get_device(mac)


def get_device(mac: str) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac.lower(),)
        ).fetchone()
    return dict(row) if row else None


def upsert_scan_device(ip: str, mac: str, hostname: str, trusted: bool) -> tuple[bool, dict[str, Any]]:
    now = utc_now()
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        was_online = bool(existing and existing["status"] == "online")
        connection.execute(
            """
            INSERT INTO devices
                (mac, ip, hostname, is_trusted, status, first_seen, last_seen)
            VALUES (?, ?, ?, ?, 'online', ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = excluded.hostname,
                is_trusted = excluded.is_trusted,
                status = 'online',
                last_seen = excluded.last_seen
            """,
            (mac, ip, hostname, int(trusted), now, now),
        )
        if not was_online:
            connection.execute(
                "INSERT INTO history (mac, ip, event, timestamp) VALUES (?, ?, 'Connected', ?)",
                (mac, ip, now),
            )
        if not trusted and not was_online:
            connection.execute(
                """
                INSERT INTO alerts (mac, ip, alert_type, message, created_at)
                VALUES (?, ?, 'Warning', 'Unknown device detected', ?)
                """,
                (mac, ip, now),
            )
    return not was_online, get_device(mac) or {}


def mark_missing_offline(seen_macs: set[str]) -> None:
    now = utc_now()
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT mac, ip FROM devices WHERE status = 'online'"
        ).fetchall()
        for row in rows:
            if row["mac"] not in seen_macs:
                connection.execute(
                    "UPDATE devices SET status = 'offline' WHERE mac = ?",
                    (row["mac"],),
                )
                connection.execute(
                    "INSERT INTO history (mac, ip, event, timestamp) VALUES (?, ?, 'Disconnected', ?)",
                    (row["mac"], row["ip"], now),
                )


def list_devices() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM devices ORDER BY status = 'online' DESC, last_seen DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def list_alerts(include_acknowledged: bool = True) -> list[dict[str, Any]]:
    query = "SELECT * FROM alerts"
    if not include_acknowledged:
        query += " WHERE is_acknowledged = 0"
    query += " ORDER BY created_at DESC"
    with get_connection() as connection:
        rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]


def acknowledge_alerts() -> None:
    with get_connection() as connection:
        connection.execute("UPDATE alerts SET is_acknowledged = 1")


def list_history() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM history ORDER BY timestamp DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def delete_device(mac: str) -> bool:
    with get_connection() as connection:
        mac = mac.lower()
        cursor = connection.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        deleted = cursor.rowcount > 0
    if deleted:
        _write_trusted_file(trusted_macs())
    return deleted
