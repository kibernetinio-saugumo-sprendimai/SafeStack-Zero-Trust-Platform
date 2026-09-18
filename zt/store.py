import os, sqlite3
from pathlib import Path

class Store:
    def __init__(self, path='zero-trust.db'):
        self.path = str(Path(path).expanduser()); self.db = sqlite3.connect(self.path, check_same_thread=False)
        if self.path != ':memory:': os.chmod(self.path, 0o600)
        self.db.row_factory = sqlite3.Row; self.db.execute('PRAGMA foreign_keys=ON'); self.db.execute('PRAGMA journal_mode=WAL'); self.init()
    def init(self):
        self.db.executescript('''CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, posture TEXT NOT NULL, registered_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY, effect TEXT NOT NULL CHECK(effect IN ('allow','deny')), subject TEXT NOT NULL, resource TEXT NOT NULL, action TEXT NOT NULL, min_posture TEXT NOT NULL); CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, subject TEXT NOT NULL, resource TEXT NOT NULL, action TEXT NOT NULL, allowed INTEGER NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(device_id) REFERENCES devices(id));'''); self.db.commit()
    def add_device(self, d): self.db.execute('INSERT OR REPLACE INTO devices VALUES (?,?,?,?,?)', d); self.db.commit()
    def add_policy(self, p): self.db.execute('INSERT OR REPLACE INTO policies VALUES (?,?,?,?,?,?)', p); self.db.commit()
    def device(self, device_id): return self.db.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
    def policies(self, subject, resource, action): return self.db.execute('SELECT * FROM policies WHERE (subject=? OR subject=?) AND (resource=? OR resource=?) AND (action=? OR action=?) ORDER BY effect DESC', (subject,'*',resource,'*',action,'*')).fetchall()
    def decision(self, row): self.db.execute('INSERT INTO decisions(device_id,subject,resource,action,allowed,reason,created_at) VALUES (?,?,?,?,?,?,?)', row); self.db.commit()
