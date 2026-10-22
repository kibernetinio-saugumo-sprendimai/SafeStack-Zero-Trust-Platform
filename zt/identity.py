"""Local identity registry: PBKDF2 password verification, roles and audit events."""
import base64
import binascii
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone
from typing import List, Optional
from .store import Store

ITERATIONS = 600_000
MIN_ROUNDS = 10_000
MAX_ROUNDS = 5_000_000
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.@]{2,64}$")


def validate_username(username: str) -> None:
    """Ensure username is a valid, sanitized identifier."""
    if not isinstance(username, str) or not USERNAME_REGEX.fullmatch(username):
        raise ValueError("username must be 2-64 characters (alphanumeric, underscore, dash, dot, or @)")


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 600,000 iterations."""
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    salt_bytes = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, ITERATIONS)
    b64_salt = base64.urlsafe_b64encode(salt_bytes).decode("ascii")
    b64_digest = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"pbkdf2_sha256${ITERATIONS}${b64_salt}${b64_digest}"


def verify_password(password: str, encoded: str) -> bool:
    """Verify password against stored PBKDF2 hash with bounds checking and constant-time compare."""
    if not isinstance(password, str) or not isinstance(encoded, str):
        return False
    try:
        parts = encoded.split("$")
        if len(parts) != 4:
            return False
        algorithm, rounds_str, salt_b64, expected_b64 = parts
        if algorithm != "pbkdf2_sha256":
            return False
        rounds = int(rounds_str)
        if rounds < MIN_ROUNDS or rounds > MAX_ROUNDS:
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        actual_b64 = base64.urlsafe_b64encode(actual).decode("ascii")
        return hmac.compare_digest(actual_b64, expected_b64)
    except (ValueError, TypeError, binascii.Error, AttributeError):
        return False


def init_identity_schema(store: Store) -> None:
    """Ensure identity and RBAC tables exist in the SQLite store."""
    store.db.executescript(
        """
        CREATE TABLE IF NOT EXISTS identities (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS roles (
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            PRIMARY KEY(username, role),
            FOREIGN KEY(username) REFERENCES identities(username)
        );

        CREATE TABLE IF NOT EXISTS identity_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            event TEXT NOT NULL,
            success INTEGER NOT NULL CHECK(success IN (0, 1)),
            created_at TEXT NOT NULL
        );
        """
    )
    store.db.commit()


def create_user(store: Store, username: str, password: str) -> None:
    """Create a new identity record with hashed password."""
    validate_username(username)
    init_identity_schema(store)
    now = datetime.now(timezone.utc).isoformat()
    hashed = hash_password(password)
    store.db.execute(
        "INSERT INTO identities (username, password_hash, status, created_at) VALUES (?, ?, ?, ?)",
        (username, hashed, "active", now),
    )
    store.db.commit()
    event(store, username, "user_created", True)


def assign_role(store: Store, username: str, role: str) -> None:
    """Assign an access role to a registered identity."""
    init_identity_schema(store)
    if not isinstance(role, str) or not role.strip():
        raise ValueError("role must be a non-empty string")
    user = store.db.execute("SELECT 1 FROM identities WHERE username = ?", (username,)).fetchone()
    if not user:
        raise ValueError(f"unknown user: '{username}'")
    store.db.execute("INSERT OR IGNORE INTO roles (username, role) VALUES (?, ?)", (username, role.strip()))
    store.db.commit()
    event(store, username, f"role_assigned:{role.strip()}", True)


def get_roles(store: Store, username: str) -> List[str]:
    """Retrieve assigned roles for a given identity."""
    init_identity_schema(store)
    rows = store.db.execute("SELECT role FROM roles WHERE username = ? ORDER BY role", (username,)).fetchall()
    return [r["role"] for r in rows]


def disable_user(store: Store, username: str) -> None:
    """Disable an active user account."""
    init_identity_schema(store)
    store.db.execute("UPDATE identities SET status = 'disabled' WHERE username = ?", (username,))
    store.db.commit()
    event(store, username, "user_disabled", True)


def authenticate(store: Store, username: str, password: str) -> bool:
    """Authenticate user credentials and log the event in audit store."""
    init_identity_schema(store)
    row = store.db.execute("SELECT password_hash, status FROM identities WHERE username = ?", (username,)).fetchone()
    ok = bool(row and row["status"] == "active" and verify_password(password, row["password_hash"]))
    event(store, username, "authentication", ok)
    return ok


def event(store: Store, username: str, name: str, success: bool) -> None:
    """Record an identity audit event."""
    now = datetime.now(timezone.utc).isoformat()
    store.db.execute(
        "INSERT INTO identity_events (username, event, success, created_at) VALUES (?, ?, ?, ?)",
        (username, name, int(bool(success)), now),
    )
    store.db.commit()
