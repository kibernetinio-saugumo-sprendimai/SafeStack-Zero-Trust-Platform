"""Secure, localized SQLite storage for Zero Trust devices, policies, and decisions."""
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from .common import resolve_parent


class Store:
    """Zero Trust SQLite persistence layer with strict permissions and WAL mode."""

    def __init__(self, path: str = "zero-trust.db"):
        self.raw_path = path
        if path == ":memory:":
            self.path = ":memory:"
        else:
            p = Path(path).expanduser()
            if p.is_symlink():
                raise ValueError(f"Database path cannot be a symlink: {p}")
            resolve_parent(p)
            self.path = str(p.resolve())

        self.db = sqlite3.connect(self.path, check_same_thread=False)
        if self.path != ":memory:":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self.db.execute("PRAGMA journal_mode = WAL")
        self.init()

    def init(self) -> None:
        """Initialize database schema with strict integrity constraints."""
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner TEXT NOT NULL,
                posture TEXT NOT NULL CHECK(posture IN ('unknown', 'degraded', 'compliant')),
                registered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
                subject TEXT NOT NULL,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                min_posture TEXT NOT NULL CHECK(min_posture IN ('unknown', 'degraded', 'compliant'))
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                allowed INTEGER NOT NULL CHECK(allowed IN (0, 1)),
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );
            """
        )
        self.db.commit()

    def add_device(self, device_tuple: Sequence[str]) -> None:
        """Register or update device information."""
        if len(device_tuple) != 5:
            raise ValueError("Device record requires exactly 5 fields (id, name, owner, posture, registered_at)")
        self.db.execute("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?)", device_tuple)
        self.db.commit()

    def add_policy(self, policy_tuple: Sequence[str]) -> None:
        """Register or update an access control policy."""
        if len(policy_tuple) != 6:
            raise ValueError("Policy record requires exactly 6 fields (id, effect, subject, resource, action, min_posture)")
        self.db.execute("INSERT OR REPLACE INTO policies VALUES (?, ?, ?, ?, ?, ?)", policy_tuple)
        self.db.commit()

    def device(self, device_id: str) -> Optional[sqlite3.Row]:
        """Fetch a registered device by its identifier."""
        return self.db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    def policies(self, subject: str, resource: str, action: str) -> List[sqlite3.Row]:
        """Query applicable policies matching subject, resource, and action, with deny taking precedence."""
        return self.db.execute(
            """
            SELECT * FROM policies
            WHERE (subject = ? OR subject = '*')
              AND (resource = ? OR resource = '*')
              AND (action = ? OR action = '*')
            ORDER BY effect DESC
            """,
            (subject, resource, action),
        ).fetchall()

    def decision(self, decision_tuple: Sequence[Any]) -> None:
        """Record an access decision into the audit log."""
        if len(decision_tuple) != 7:
            raise ValueError("Decision record requires exactly 7 fields")
        self.db.execute(
            """
            INSERT INTO decisions(device_id, subject, resource, action, allowed, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            decision_tuple,
        )
        self.db.commit()

    def close(self) -> None:
        """Close the database connection safely."""
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
