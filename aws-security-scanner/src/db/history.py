"""
Scan History Storage
====================
Persists scan results to a local SQLite database so the web dashboard
can display historical compliance trends and detect regressions.

For cloud deployments, the DynamoDB backend can be swapped in by setting
SCANNER_DB_BACKEND=dynamodb in the environment.
"""
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.environ.get("SCANNER_DB_PATH", os.path.expanduser("~/.aws-security-scanner/history.db"))


def _ensure_dir():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


class ScanHistoryDB:
    """SQLite-backed scan history store."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or DB_PATH
        _ensure_dir()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id     TEXT PRIMARY KEY,
                    timestamp   TEXT NOT NULL,
                    account_id  TEXT,
                    region      TEXT,
                    duration_s  REAL,
                    total_findings INTEGER,
                    critical    INTEGER,
                    high        INTEGER,
                    medium      INTEGER,
                    low         INTEGER,
                    cis_score   REAL,
                    nist_score  REAL,
                    pci_score   REAL,
                    findings_json    TEXT,
                    attack_paths_json TEXT,
                    graph_data_json  TEXT
                )
            """)
            conn.commit()

    def save_scan(self, report_data: Dict[str, Any]) -> str:
        """Persist a complete scan result. Returns the scan_id."""
        scan_id = str(uuid.uuid4())[:8]
        meta = report_data.get("scan_metadata", {})
        stats = report_data.get("statistics", {})
        comp = report_data.get("compliance", {})
        frameworks = comp.get("frameworks", {})

        by_sev = stats.get("by_severity", {})

        timestamp = meta.get("scan_time") or datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO scans VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
            """, (
                scan_id,
                timestamp,
                meta.get("account_id", "unknown"),
                meta.get("region", "us-east-1"),
                meta.get("scan_duration_seconds"),
                stats.get("total_findings", 0),
                by_sev.get("CRITICAL", 0),
                by_sev.get("HIGH", 0),
                by_sev.get("MEDIUM", 0),
                by_sev.get("LOW", 0),
                frameworks.get("cis", {}).get("score"),
                frameworks.get("nist", {}).get("score"),
                frameworks.get("pci", {}).get("score"),
                json.dumps(report_data.get("findings", []), default=str),
                json.dumps(report_data.get("attack_paths", []), default=str),
                json.dumps(report_data.get("graph_data", {}), default=str),
            ))
            conn.commit()

        return scan_id

    def get_recent_scans(self, days: int = 90, account_id: str = None) -> List[Dict]:
        """Return summary rows for trend charts (no full findings blob)."""
        query = """
            SELECT scan_id, timestamp, account_id, region, total_findings,
                   critical, high, medium, low, cis_score, nist_score, pci_score, duration_s
            FROM scans
            WHERE timestamp >= datetime('now', ?)
        """
        params: list = [f"-{days} days"]
        if account_id:
            query += " AND account_id = ?"
            params.append(account_id)
        query += " ORDER BY timestamp DESC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_latest_scan(self, account_id: str = None) -> Optional[Dict]:
        """Return the most recent full scan record including findings."""
        query = "SELECT * FROM scans"
        params = []
        if account_id:
            query += " WHERE account_id = ?"
            params.append(account_id)
        query += " ORDER BY timestamp DESC LIMIT 1"

        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()

        if not row:
            return None

        result = dict(row)
        for json_col in ("findings_json", "attack_paths_json", "graph_data_json"):
            key = json_col.replace("_json", "")
            try:
                result[key] = json.loads(result.pop(json_col) or "[]")
            except (json.JSONDecodeError, TypeError):
                result[key] = []
        return result

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        for json_col in ("findings_json", "attack_paths_json", "graph_data_json"):
            key = json_col.replace("_json", "")
            try:
                result[key] = json.loads(result.pop(json_col) or "[]")
            except (json.JSONDecodeError, TypeError):
                result[key] = []
        return result

    def list_scans(self, limit: int = 50) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id, timestamp, account_id, total_findings, cis_score FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
