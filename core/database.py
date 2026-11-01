"""SQLite persistence: scans, targets, findings, checkpoints, audit trail, search & resume."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterable
import uuid

from core.finding import Finding

SCHEMA = """
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    config_json TEXT,
    total_targets INTEGER DEFAULT 0,
    note TEXT,
    tool_versions_json TEXT,
    report_paths_json TEXT
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    request_count INTEGER DEFAULT 0,
    error TEXT,
    score INTEGER,
    UNIQUE(scan_id, url)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    url TEXT,
    endpoint TEXT,
    category TEXT, module TEXT, title TEXT, severity TEXT,
    confidence TEXT, description TEXT, evidence TEXT,
    detection_method TEXT, cwe TEXT, cve TEXT, remediation TEXT,
    verification_status TEXT, parameter TEXT, tags TEXT,
    owasp_reference TEXT, wstg_reference TEXT, impact TEXT,
    false_positive_notes TEXT, test_id TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT, ts TEXT, event TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS checkpoints (
    scan_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(scan_id, target_url);
CREATE INDEX IF NOT EXISTS idx_targets_scan ON targets(scan_id, status);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            try:
                self._conn.execute("PRAGMA journal_mode=WAL;")
            except sqlite3.OperationalError:
                self._conn.execute("PRAGMA journal_mode=DELETE;")
            self._conn.executescript(SCHEMA)
            self._ensure_columns()
            self._conn.commit()

    def _ensure_columns(self) -> None:
        scan_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(scans)").fetchall()}
        for col in ("tool_versions_json", "report_paths_json"):
            if col not in scan_cols:
                self._conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")

        finding_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(findings)").fetchall()}
        for col in ("endpoint", "owasp_reference", "wstg_reference", "impact", "false_positive_notes", "test_id"):
            if col not in finding_cols:
                self._conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")

    # ---- lifecycle --------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except sqlite3.Error:
                pass

    def create_scan(self, config_json: dict, total: int, note: str = "",
                    tool_versions: dict | None = None) -> str:
        scan_id = uuid.uuid4().hex[:12]
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO scans (id, started_at, status, config_json, total_targets, note, tool_versions_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (scan_id, _now(), "running", json.dumps(config_json), total, note,
                 json.dumps(tool_versions or {})),
            )
        return scan_id

    def reopen_scan(self, scan_id: str) -> None:
        """Mark an interrupted scan as running again for in-place resumption."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status='running', finished_at=NULL WHERE id=?",
                (scan_id,),
            )
            self._conn.execute(
                "UPDATE targets SET status='pending' WHERE scan_id=? AND status='running'",
                (scan_id,),
            )

    def unfinished_target_urls(self, scan_id: str) -> list[str]:
        """Return target URLs that have not yet completed ('pending' or 'running')."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT url FROM targets WHERE scan_id=? AND status IN ('pending','running') ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [r["url"] for r in rows]

    def finish_scan(self, scan_id: str, status: str = "complete") -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE scans SET status=?, finished_at=? WHERE id=?",
                               (status, _now(), scan_id))

    def save_report_paths(self, scan_id: str, paths: dict[str, Any]) -> None:
        clean = {k: str(v) for k, v in (paths or {}).items() if v is not None}
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET report_paths_json=? WHERE id=?",
                (json.dumps(clean), scan_id),
            )

    def add_targets(self, scan_id: str, urls: Iterable[str]) -> int:
        n = 0
        with self._lock, self._conn:
            for u in urls:
                try:
                    self._conn.execute(
                        "INSERT INTO targets (scan_id, url) VALUES (?,?)", (scan_id, u))
                    n += 1
                except sqlite3.IntegrityError:
                    pass
        return n

    def set_target_status(self, scan_id: str, url: str, status: str,
                          error: str | None = None, score: int | None = None,
                          requests: int | None = None) -> None:
        field_sql, params = ["status=?"], [status]
        if status == "running":
            field_sql.append("started_at=?")
            params.append(_now())
        if status in ("done", "failed", "skipped"):
            field_sql.append("finished_at=?")
            params.append(_now())
        if error is not None:
            field_sql.append("error=?")
            params.append(error[:800])
        if score is not None:
            field_sql.append("score=?")
            params.append(score)
        if requests is not None:
            field_sql.append("request_count=?")
            params.append(requests)
        params += [scan_id, url]
        with self._lock, self._conn:
            self._conn.execute(f"UPDATE targets SET {', '.join(field_sql)}"
                               " WHERE scan_id=? AND url=?", params)

    def add_findings(self, scan_id: str, findings: list[Finding]) -> None:
        if not findings:
            return
        rows = [
            (
                f.finding_id, scan_id, f.target, f.url, f.endpoint, f.category,
                f.module, f.title, f.severity, f.confidence, f.description,
                f.evidence, f.detection_method, f.cwe, f.cve, f.remediation,
                f.verification_status, f.parameter, json.dumps(f.tags),
                f.owasp_reference, f.wstg_reference, f.impact,
                f.false_positive_notes, f.test_id, f.timestamp,
            )
            for f in findings
        ]
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO findings (finding_id, scan_id, target_url, url, endpoint,"
                " category, module, title, severity, confidence, description, evidence,"
                " detection_method, cwe, cve, remediation, verification_status, parameter,"
                " tags, owasp_reference, wstg_reference, impact, false_positive_notes,"
                " test_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )

    def audit(self, scan_id: str | None, event: str, detail: str = "") -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO audit_log (scan_id, ts, event, detail) VALUES (?,?,?,?)",
                               (scan_id, _now(), event, detail[:2000]))

    # ---- checkpoints ------------------------------------------------------
    def save_checkpoint(self, scan_id: str, payload: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO checkpoints (scan_id, payload, updated_at) VALUES (?,?,?)"
                " ON CONFLICT(scan_id) DO UPDATE SET payload=excluded.payload,"
                " updated_at=excluded.updated_at",
                (scan_id, json.dumps(payload), _now()))

    def load_checkpoint(self, scan_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT payload FROM checkpoints WHERE scan_id=?",
                                     (scan_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    # ---- queries ----------------------------------------------------------
    def targets(self, scan_id: str, status: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM targets WHERE scan_id=?"
        p: list[Any] = [scan_id]
        if status:
            q += " AND status=?"
            p.append(status)
        q += " ORDER BY id"
        with self._lock:
            return self._conn.execute(q, p).fetchall()

    def findings(self, scan_id: str, target: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM findings WHERE scan_id=?"
        p: list[Any] = [scan_id]
        if target:
            q += " AND target_url=?"
            p.append(target)
        q += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1" \
             " WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, id"
        with self._lock:
            return self._conn.execute(q, p).fetchall()

    def search_findings(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        verification_status: str | None = None,
        category: str | None = None,
        query: str | None = None,
        limit: int = 200,
    ) -> list[sqlite3.Row]:
        clauses = ["1=1"]
        params: list[Any] = []
        if scan_id:
            clauses.append("scan_id=?")
            params.append(scan_id)
        if severity:
            clauses.append("severity=?")
            params.append(severity.upper())
        if verification_status:
            clauses.append("verification_status=?")
            params.append(verification_status.upper())
        if category:
            clauses.append("category=?")
            params.append(category)
        if query:
            clauses.append("(title LIKE ? OR description LIKE ? OR target_url LIKE ?)")
            like = f"%{query}%"
            params.extend([like, like, like])
        params.append(limit)
        sql = (
            f"SELECT * FROM findings WHERE {' AND '.join(clauses)} "
            "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
            "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, id DESC LIMIT ?"
        )
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def recent_scans(self, limit: int = 20) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()

    def scan(self, scan_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    def resumable_scans(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM scans WHERE status IN ('running','interrupted')"
                " ORDER BY started_at DESC").fetchall()

    def counts(self, scan_id: str) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) c FROM targets WHERE scan_id=? GROUP BY status",
                (scan_id,)).fetchall()
        return {r["status"]: r["c"] for r in rows}
