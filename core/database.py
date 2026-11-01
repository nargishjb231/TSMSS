"""SQLite persistence: scans, targets, findings, checkpoints, audit trail."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.finding import Finding

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    config_json TEXT,
    total_targets INTEGER DEFAULT 0,
    note TEXT
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
    category TEXT, module TEXT, title TEXT, severity TEXT,
    confidence TEXT, description TEXT, evidence TEXT,
    detection_method TEXT, cwe TEXT, cve TEXT, remediation TEXT,
    verification_status TEXT, parameter TEXT, tags TEXT, created_at TEXT
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
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ---- lifecycle --------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except sqlite3.Error:
                pass

    def create_scan(self, config_json: dict, total: int, note: str = "") -> str:
        scan_id = uuid.uuid4().hex[:12]
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO scans (id, started_at, status, config_json, total_targets, note)"
                " VALUES (?,?,?,?,?,?)",
                (scan_id, _now(), "running", json.dumps(config_json), total, note))
        return scan_id

    def finish_scan(self, scan_id: str, status: str = "complete") -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE scans SET status=?, finished_at=? WHERE id=?",
                               (status, _now(), scan_id))

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
        rows = [(f.finding_id, scan_id, f.target, f.url, f.category, f.module, f.title,
                 f.severity, f.confidence, f.description, f.evidence, f.detection_method,
                 f.cwe, f.cve, f.remediation, f.verification_status, f.parameter,
                 json.dumps(f.tags), f.timestamp) for f in findings]
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO findings (finding_id, scan_id, target_url, url, category,"
                " module, title, severity, confidence, description, evidence,"
                " detection_method, cwe, cve, remediation, verification_status, parameter,"
                " tags, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

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