"""
db.py - SQLite storage layer for Hypernova.

Two conceptual tables of "captured" data plus attack session/result tracking:
- captured_traffic   : requests/responses seen by the MITM capture layer
- attack_sessions    : one row per configured attack (sniper/pitchfork/etc)
- attack_results     : one row per request fired during an attack
"""

import sqlite3
import json
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".hypernova" / "hypernova.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS captured_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    headers TEXT,
    body TEXT,
    response_status INTEGER,
    response_body TEXT,
    response_headers TEXT
);

CREATE TABLE IF NOT EXISTS attack_sessions (
    session_id TEXT PRIMARY KEY,
    base_request TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    payload_config TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    last_completed_index INTEGER NOT NULL DEFAULT -1,
    created_at REAL NOT NULL,
    target_summary TEXT
);

CREATE TABLE IF NOT EXISTS attack_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    request_no INTEGER NOT NULL,
    payloads TEXT NOT NULL,
    status_code INTEGER,
    response_received INTEGER NOT NULL DEFAULT 0,
    response_gone INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    timeout INTEGER NOT NULL DEFAULT 0,
    length INTEGER,
    elapsed_ms REAL,
    full_request TEXT,
    full_response TEXT,
    FOREIGN KEY (session_id) REFERENCES attack_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_session ON attack_results(session_id);
CREATE INDEX IF NOT EXISTS idx_captured_timestamp ON captured_traffic(timestamp);
"""


class DB:
    """Thin wrapper around a single sqlite3 connection with WAL mode for
    concurrent capture-writer + REPL-reader access.

    A single connection is shared by several threads at once — the REPL, the
    mitmproxy capture addon, and the attack engine's dispatch thread. sqlite3
    permits this with ``check_same_thread=False``, but interleaved implicit
    transactions from different threads can clobber each other's commits (a
    write from one thread committing another's half-finished statement), which
    shows up as *silently dropped captures* under load. We therefore serialize
    every cursor/commit cycle behind a re-entrant lock so each logical
    operation is atomic. WAL mode keeps readers from blocking on the writer."""

    def __init__(self, path: Path = DEFAULT_DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                    timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=30000;")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._lock = threading.RLock()

    @contextmanager
    def cursor(self):
        with self._lock:
            cur = self.conn.cursor()
            try:
                yield cur
                self.conn.commit()
            finally:
                cur.close()

    # ---------------- captured_traffic ----------------

    def insert_captured(self, method, url, headers, body,
                         response_status=None, response_body=None,
                         response_headers=None):
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO captured_traffic
                   (timestamp, method, url, headers, body,
                    response_status, response_body, response_headers)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (time.time(), method, url,
                 json.dumps(headers or {}), body or "",
                 response_status, response_body or "",
                 json.dumps(response_headers or {}))
            )
            return cur.lastrowid

    def list_captured(self, limit=500):
        with self.cursor() as cur:
            cur.execute(
                """SELECT id, timestamp, method, url, response_status,
                          LENGTH(response_body) AS length
                   FROM captured_traffic ORDER BY id DESC LIMIT ?""",
                (limit,)
            )
            return [dict(r) for r in cur.fetchall()]

    def search_captured(self, keyword, limit=500):
        like = f"%{keyword}%"
        with self.cursor() as cur:
            cur.execute(
                """SELECT id, timestamp, method, url, response_status,
                          LENGTH(response_body) AS length
                   FROM captured_traffic
                   WHERE url LIKE ? OR body LIKE ? OR response_body LIKE ?
                   ORDER BY id DESC LIMIT ?""",
                (like, like, like, limit)
            )
            return [dict(r) for r in cur.fetchall()]

    def get_captured(self, capture_id):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM captured_traffic WHERE id = ?", (capture_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    # ---------------- scope_rules ----------------

    def add_scope(self, pattern):
        """Insert a scope pattern; returns True if newly added, False if it
        already existed."""
        pattern = pattern.strip()
        if not pattern:
            return False
        with self.cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO scope_rules (pattern, created_at) VALUES (?, ?)",
                (pattern, time.time())
            )
            return cur.rowcount > 0

    def remove_scope(self, pattern):
        with self.cursor() as cur:
            cur.execute("DELETE FROM scope_rules WHERE pattern = ?", (pattern.strip(),))
            return cur.rowcount > 0

    def list_scope(self):
        with self.cursor() as cur:
            cur.execute("SELECT pattern FROM scope_rules ORDER BY id ASC")
            return [r["pattern"] for r in cur.fetchall()]

    def clear_scope(self):
        with self.cursor() as cur:
            cur.execute("DELETE FROM scope_rules")
            return cur.rowcount

    # ---------------- attack_sessions ----------------

    def create_session(self, base_request: dict, attack_type: str,
                        payload_config: dict, target_summary: str = ""):
        session_id = uuid.uuid4().hex[:12]
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO attack_sessions
                   (session_id, base_request, attack_type, payload_config,
                    status, last_completed_index, created_at, target_summary)
                   VALUES (?, ?, ?, ?, 'running', -1, ?, ?)""",
                (session_id, json.dumps(base_request), attack_type,
                 json.dumps(payload_config), time.time(), target_summary)
            )
        return session_id

    def update_session_status(self, session_id, status):
        with self.cursor() as cur:
            cur.execute(
                "UPDATE attack_sessions SET status = ? WHERE session_id = ?",
                (status, session_id)
            )

    def checkpoint(self, session_id, last_completed_index):
        with self.cursor() as cur:
            cur.execute(
                """UPDATE attack_sessions SET last_completed_index = ?
                   WHERE session_id = ?""",
                (last_completed_index, session_id)
            )

    def get_session(self, session_id):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM attack_sessions WHERE session_id = ?", (session_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_sessions(self):
        with self.cursor() as cur:
            cur.execute(
                """SELECT session_id, attack_type, status, target_summary,
                          created_at, last_completed_index
                   FROM attack_sessions ORDER BY created_at DESC"""
            )
            return [dict(r) for r in cur.fetchall()]

    # ---------------- attack_results ----------------

    def insert_result(self, session_id, request_no, payloads, status_code,
                       response_received, response_gone, error, timeout,
                       length, elapsed_ms, full_request, full_response):
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO attack_results
                   (session_id, request_no, payloads, status_code,
                    response_received, response_gone, error, timeout,
                    length, elapsed_ms, full_request, full_response)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, request_no, json.dumps(payloads), status_code,
                 int(bool(response_received)), int(bool(response_gone)),
                 error, int(bool(timeout)), length, elapsed_ms,
                 full_request, full_response)
            )

    def get_results(self, session_id, order_by="request_no", descending=False):
        allowed_cols = {"request_no", "status_code", "length", "elapsed_ms"}
        col = order_by if order_by in allowed_cols else "request_no"
        direction = "DESC" if descending else "ASC"
        with self.cursor() as cur:
            cur.execute(
                f"""SELECT * FROM attack_results WHERE session_id = ?
                    ORDER BY {col} {direction}""",
                (session_id,)
            )
            return [dict(r) for r in cur.fetchall()]

    def count_results(self, session_id):
        with self.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) as c FROM attack_results WHERE session_id = ?",
                (session_id,)
            )
            return cur.fetchone()["c"]

    def close(self):
        self.conn.close()
