"""Session database — SQLite-backed session, command, and findings storage."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from capo import config

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    UNIQUE NOT NULL,
    target_ip   TEXT    NOT NULL,
    domain      TEXT    NOT NULL DEFAULT '',
    campaign    TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'active'
                CHECK(status IN ('active','paused','completed')),
    notes       TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    tool        TEXT    NOT NULL DEFAULT '',
    command     TEXT    NOT NULL,
    output_file TEXT    NOT NULL DEFAULT '',
    exit_code   INTEGER,
    duration    REAL    NOT NULL DEFAULT 0.0,
    is_key      INTEGER NOT NULL DEFAULT 0,
    source      TEXT    NOT NULL DEFAULT 'auto'
                CHECK(source IN ('auto','manual')),
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command_id  INTEGER REFERENCES commands(id) ON DELETE SET NULL,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    category    TEXT    NOT NULL DEFAULT 'general'
                CHECK(category IN ('general','foothold','privesc','credential',
                                   'misconfiguration','vulnerability')),
    severity    TEXT    NOT NULL DEFAULT 'info'
                CHECK(severity IN ('info','low','medium','high','critical')),
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_key     ON commands(session_id, is_key)
    WHERE is_key = 1;
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row else None


class SessionDB:
    """SQLite-backed session, command, and findings store."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or config.SESSIONS_DB_FILE
        self._conn: sqlite3.Connection | None = None
        self._active_session_id: int | None = None
        self._active_session_name: str | None = None
        self._ensure_db()
        self._auto_load()

    # ── setup ──────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _ensure_db(self):
        conn = self._get_conn()
        conn.executescript(_SCHEMA_SQL)
        conn.commit()

    def _auto_load(self):
        """Restore active session from the marker file."""
        marker = self._session_file()
        if marker.exists():
            name = marker.read_text(encoding="utf-8").strip()
            if name:
                row = self._get_conn().execute(
                    "SELECT id, name FROM sessions WHERE name = ?", (name,)
                ).fetchone()
                if row:
                    self._active_session_id = row["id"]
                    self._active_session_name = row["name"]

    def _session_file(self) -> Path:
        return self._db_path.parent / ".current_session"

    # ── session CRUD ───────────────────────────────────────

    def create_session(
        self,
        name: str,
        target_ip: str,
        domain: str = "",
        campaign: str = "",
    ) -> dict:
        """Create a new session. Raises ValueError if name already exists."""
        now = _now()
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO sessions (name, target_ip, domain, campaign, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, target_ip, domain, campaign, now, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"Session '{name}' already exists")
        return self.get_session(name)  # type: ignore[return-value]

    def activate_session(self, name: str) -> dict:
        """Activate a session by name. Returns the session dict."""
        session = self.get_session(name)
        if not session:
            raise ValueError(f"Session '{name}' not found")
        self._active_session_id = session["id"]
        self._active_session_name = session["name"]
        marker = self._session_file()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(name, encoding="utf-8")
        return session

    def deactivate_session(self):
        """Clear the active session."""
        self._active_session_id = None
        self._active_session_name = None
        marker = self._session_file()
        if marker.exists():
            marker.unlink()

    def get_active_session(self) -> dict | None:
        """Get the currently active session, or None."""
        if self._active_session_name:
            return self.get_session(self._active_session_name)
        return None

    @property
    def active_session_id(self) -> int | None:
        return self._active_session_id

    @property
    def active_session_name(self) -> str | None:
        return self._active_session_name

    def get_session(self, name: str) -> dict | None:
        row = self._get_conn().execute(
            "SELECT * FROM sessions WHERE name = ?", (name,)
        ).fetchone()
        return _row_to_dict(row)

    def list_sessions(self) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_session(self, name: str):
        """Delete a session and all its commands/findings (CASCADE)."""
        conn = self._get_conn()
        session = self.get_session(name)
        if not session:
            raise ValueError(f"Session '{name}' not found")
        conn.execute("DELETE FROM sessions WHERE name = ?", (name,))
        conn.commit()
        # If we just deleted the active session, clear it
        if self._active_session_name == name:
            self.deactivate_session()

    # ── command recording ──────────────────────────────────

    def record_command(
        self,
        tool: str,
        command: str,
        output_file: str = "",
        exit_code: int | None = None,
        duration: float = 0.0,
        source: str = "auto",
    ) -> int:
        """Record a command to the active session. Returns cmd ID, or -1 if no session."""
        if self._active_session_id is None:
            return -1
        now = _now()
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO commands (session_id, tool, command, output_file, exit_code, "
            "duration, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (self._active_session_id, tool, command, output_file, exit_code,
             duration, source, now),
        )
        # Touch session updated_at
        conn.execute(
            "UPDATE sessions SET updated_at = ? WHERE id = ?",
            (now, self._active_session_id),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def list_commands(
        self,
        session_name: str | None = None,
        key_only: bool = False,
        tool: str | None = None,
    ) -> list[dict]:
        """List commands for a session (defaults to active)."""
        sid = self._resolve_session_id(session_name)
        if sid is None:
            return []
        clauses = ["session_id = ?"]
        params: list = [sid]
        if key_only:
            clauses.append("is_key = 1")
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        where = " AND ".join(clauses)
        rows = self._get_conn().execute(
            f"SELECT * FROM commands WHERE {where} ORDER BY id",  # noqa: S608
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def get_command(self, cmd_id: int) -> dict | None:
        row = self._get_conn().execute(
            "SELECT * FROM commands WHERE id = ?", (cmd_id,)
        ).fetchone()
        return _row_to_dict(row)

    def mark_key(self, cmd_id: int, is_key: bool = True):
        """Toggle the is_key flag on a command."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE commands SET is_key = ? WHERE id = ?",
            (1 if is_key else 0, cmd_id),
        )
        conn.commit()

    # ── findings ───────────────────────────────────────────

    def add_finding(
        self,
        title: str,
        description: str = "",
        command_id: int | None = None,
        category: str = "general",
        severity: str = "info",
    ) -> int:
        """Add a finding to the active session. Returns finding ID, or -1 if no session."""
        if self._active_session_id is None:
            return -1
        now = _now()
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO findings (session_id, command_id, title, description, "
            "category, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._active_session_id, command_id, title, description,
             category, severity, now),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def list_findings(self, session_name: str | None = None) -> list[dict]:
        """List findings for a session (defaults to active)."""
        sid = self._resolve_session_id(session_name)
        if sid is None:
            return []
        rows = self._get_conn().execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY id",
            (sid,),
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_finding(self, finding_id: int):
        conn = self._get_conn()
        conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        conn.commit()

    # ── summary ────────────────────────────────────────────

    def session_summary(self, name: str | None = None) -> dict:
        """Return summary stats for a session."""
        sid = self._resolve_session_id(name)
        if sid is None:
            return {}
        conn = self._get_conn()
        session = dict(conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (sid,)
        ).fetchone())

        stats = conn.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN is_key = 1 THEN 1 ELSE 0 END) as key_steps, "
            "MIN(created_at) as first_cmd, "
            "MAX(created_at) as last_cmd "
            "FROM commands WHERE session_id = ?",
            (sid,),
        ).fetchone()

        finding_count = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE session_id = ?", (sid,)
        ).fetchone()[0]

        return {
            **session,
            "total_commands": stats["total"],
            "key_steps": stats["key_steps"] or 0,
            "findings_count": finding_count,
            "first_command_at": stats["first_cmd"],
            "last_command_at": stats["last_cmd"],
        }

    # ── helpers ────────────────────────────────────────────

    def _resolve_session_id(self, name: str | None) -> int | None:
        """Resolve a session name to its ID, defaulting to active session."""
        if name:
            session = self.get_session(name)
            return session["id"] if session else None
        return self._active_session_id


# Global singleton
session_db = SessionDB()
