"""Local identity registry: PBKDF2 password verification, roles and audit events."""
import base64, hashlib, hmac, secrets
from datetime import datetime, timezone
from typing import Optional
from .store import Store

ITERATIONS = 600_000

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError('password must contain at least 12 characters')
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}'

def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split('$')
        if algorithm != 'pbkdf2_sha256': return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.urlsafe_b64decode(salt), int(rounds))
        return hmac.compare_digest(base64.urlsafe_b64encode(actual).decode(), expected)
    except (ValueError, TypeError):
        return False

def init_identity_schema(store: Store) -> None:
    store.db.executescript('''CREATE TABLE IF NOT EXISTS identities(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','disabled')), created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS roles(username TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY(username, role), FOREIGN KEY(username) REFERENCES identities(username)); CREATE TABLE IF NOT EXISTS identity_events(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, event TEXT NOT NULL, success INTEGER NOT NULL, created_at TEXT NOT NULL);'''); store.db.commit()

def create_user(store: Store, username: str, password: str) -> None:
    init_identity_schema(store)
    now = datetime.now(timezone.utc).isoformat()
    store.db.execute('INSERT INTO identities VALUES (?,?,?,?)', (username, hash_password(password), 'active', now)); store.db.commit()
    event(store, username, 'user_created', True)

def assign_role(store: Store, username: str, role: str) -> None:
    init_identity_schema(store)
    if not store.db.execute('SELECT 1 FROM identities WHERE username=?', (username,)).fetchone(): raise ValueError('unknown user')
    store.db.execute('INSERT OR IGNORE INTO roles VALUES (?,?)', (username, role)); store.db.commit(); event(store, username, 'role_assigned:' + role, True)

def authenticate(store: Store, username: str, password: str) -> bool:
    init_identity_schema(store); row=store.db.execute('SELECT password_hash,status FROM identities WHERE username=?',(username,)).fetchone()
    ok=bool(row and row['status']=='active' and verify_password(password,row['password_hash'])); event(store, username, 'authentication', ok); return ok

def event(store, username, name, success):
    store.db.execute('INSERT INTO identity_events(username,event,success,created_at) VALUES (?,?,?,?)',(username,name,int(success),datetime.now(timezone.utc).isoformat())); store.db.commit()
