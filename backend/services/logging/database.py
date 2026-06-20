"""Milli Kiber-DNT — Database Layer (SQLite + Filterable Log Storage)"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path


class KiberDatabase:
    def __init__(self, db_path: str = "data/kiber_dnt.db"):
        self.db_path = db_path
        Path(os.path.dirname(db_path)).mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE,
                cve TEXT,
                name TEXT,
                cvss REAL,
                epss REAL,
                ai_decision TEXT,
                confidence REAL,
                status TEXT DEFAULT 'open',
                started_at TEXT,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                ip TEXT,
                hostname TEXT,
                ports TEXT,
                banner TEXT,
                vendor TEXT,
                discovered_at TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                timestamp TEXT,
                phase TEXT,
                event_type TEXT,
                source TEXT,
                message TEXT,
                data_json TEXT,
                severity TEXT DEFAULT 'info',
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );

            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                rule_type TEXT,
                rule_content TEXT,
                sid INTEGER UNIQUE,
                deployed_at TEXT,
                status TEXT DEFAULT 'active',
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );

            CREATE TABLE IF NOT EXISTS bas_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                target_ip TEXT,
                status_code INTEGER,
                result TEXT,
                latency_ms REAL,
                tested_at TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE,
                summary TEXT,
                report_markdown TEXT,
                generated_at TEXT,
                model_used TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
            );

            CREATE INDEX IF NOT EXISTS idx_logs_incident ON logs(incident_id);
            CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(event_type);
            CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
            CREATE INDEX IF NOT EXISTS idx_incidents_cve ON incidents(cve);
        """)
        self.conn.commit()

    def create_incident(self, incident_id: str, cve: str, name: str, cvss: float = 0.0, epss: float = 0.0):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            "INSERT OR IGNORE INTO incidents (incident_id, cve, name, cvss, epss, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, cve, name, cvss, epss, now)
        )
        self.conn.commit()

    def update_incident(self, incident_id: str, **kwargs):
        fields = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [incident_id]
        self.conn.execute(f"UPDATE incidents SET {fields} WHERE incident_id = ?", vals)
        self.conn.commit()

    def add_asset(self, incident_id: str, ip: str, hostname: str, ports: str, banner: str, vendor: str = ""):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            "INSERT INTO assets (incident_id, ip, hostname, ports, banner, vendor, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (incident_id, ip, hostname, ports, banner, vendor, now)
        )
        self.conn.commit()

    def add_log(self, incident_id: str, phase: str, event_type: str, message: str,
                source: str = "system", data_json: str = "", severity: str = "info"):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            "INSERT INTO logs (incident_id, timestamp, phase, event_type, source, message, data_json, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (incident_id, now, phase, event_type, source, message, data_json, severity)
        )
        self.conn.commit()

    def add_rule(self, incident_id: str, rule_type: str, rule_content: str, sid: int):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO rules (incident_id, rule_type, rule_content, sid, deployed_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, rule_type, rule_content, sid, now)
        )
        self.conn.commit()

    def add_bas_result(self, incident_id: str, target_ip: str, status_code: int, result: str, latency_ms: float):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            "INSERT INTO bas_results (incident_id, target_ip, status_code, result, latency_ms, tested_at) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, target_ip, status_code, result, latency_ms, now)
        )
        self.conn.commit()

    def save_report(self, incident_id: str, summary: str, markdown: str, model_used: str = ""):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO reports (incident_id, summary, report_markdown, generated_at, model_used) VALUES (?, ?, ?, ?, ?)",
            (incident_id, summary, markdown, now, model_used)
        )
        self.conn.commit()

    # ---- Query / Filter Methods ----

    def query_logs(self, incident_id: str = None, event_type: str = None,
                   phase: str = None, severity: str = None, source: str = None,
                   search: str = None, limit: int = 500, offset: int = 0):
        q = "SELECT * FROM logs WHERE 1=1"
        params = []
        if incident_id:
            q += " AND incident_id = ?"; params.append(incident_id)
        if event_type:
            q += " AND event_type = ?"; params.append(event_type)
        if phase:
            q += " AND phase = ?"; params.append(phase)
        if severity:
            q += " AND severity = ?"; params.append(severity)
        if source:
            q += " AND source = ?"; params.append(source)
        if search:
            q += " AND (message LIKE ? OR data_json LIKE ?)"; params.append(f"%{search}%"); params.append(f"%{search}%")
        q += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self.conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def query_assets(self, ips: str = None, ports: str = None, vendor: str = None,
                     search: str = None, incident_id: str = None):
        q = "SELECT * FROM assets WHERE 1=1"
        params = []
        if ips:
            q += " AND ip LIKE ?"; params.append(f"%{ips}%")
        if ports:
            q += " AND ports LIKE ?"; params.append(f"%{ports}%")
        if vendor:
            q += " AND vendor LIKE ?"; params.append(f"%{vendor}%")
        if search:
            q += " AND (ip LIKE ? OR hostname LIKE ? OR banner LIKE ?)"
            params.extend([f"%{search}%"] * 3)
        if incident_id:
            q += " AND incident_id = ?"; params.append(incident_id)
        q += " ORDER BY discovered_at DESC"
        rows = self.conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def query_rules(self, sid: int = None, rule_type: str = None, status: str = None):
        q = "SELECT * FROM rules WHERE 1=1"
        params = []
        if sid:
            q += " AND sid = ?"; params.append(sid)
        if rule_type:
            q += " AND rule_type = ?"; params.append(rule_type)
        if status:
            q += " AND status = ?"; params.append(status)
        q += " ORDER BY deployed_at DESC"
        rows = self.conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def query_bas_results(self, incident_id: str = None, result: str = None):
        q = "SELECT * FROM bas_results WHERE 1=1"
        params = []
        if incident_id:
            q += " AND incident_id = ?"; params.append(incident_id)
        if result:
            q += " AND result = ?"; params.append(result)
        q += " ORDER BY tested_at DESC"
        rows = self.conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get_incident(self, incident_id: str):
        row = self.conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return dict(row) if row else None

    def get_recent_incidents(self, limit: int = 10):
        rows = self.conn.execute("SELECT * FROM incidents ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self):
        stats = {}
        stats["total_incidents"] = self.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        stats["total_assets"] = self.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        stats["total_logs"] = self.conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        stats["total_rules"] = self.conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        stats["total_bas"] = self.conn.execute("SELECT COUNT(*) FROM bas_results").fetchone()[0]
        stats["blocked_count"] = self.conn.execute(
            "SELECT COUNT(*) FROM bas_results WHERE result LIKE '%BLOCKED%' OR result LIKE '%SUCCESS%'"
        ).fetchone()[0]
        return stats

    def close(self):
        self.conn.close()
