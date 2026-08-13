"""SQLite-backed store for scan run history, keyed by scope target name.

Enables diffing (src/diff_engine.py) between the current run and the most
recent prior run for the same target, which is what makes scheduled
scanning (cron/systemd, see scripts/run-scheduled-scan.sh) useful --
without this, every run is independent and there's no way to ask
"what changed since last time."
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "history.db"


class HistoryStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    findings_json TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target_name, timestamp)"
            )

    def save_run(self, target_name: str, timestamp: str, findings: list[dict[str, Any]]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO runs (target_name, timestamp, findings_json) VALUES (?, ?, ?)",
                (target_name, timestamp, json.dumps(findings, default=str)),
            )
            return cur.lastrowid

    def get_previous_run(self, target_name: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT timestamp, findings_json FROM runs "
                "WHERE target_name = ? ORDER BY id DESC LIMIT 1",
                (target_name,),
            ).fetchone()
        if row is None:
            return None
        return {"timestamp": row["timestamp"], "findings": json.loads(row["findings_json"])}

    def get_run_history(self, target_name: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT timestamp, findings_json FROM runs "
                "WHERE target_name = ? ORDER BY id DESC LIMIT ?",
                (target_name, limit),
            ).fetchall()
        return [
            {"timestamp": r["timestamp"], "findings": json.loads(r["findings_json"])}
            for r in rows
        ]
