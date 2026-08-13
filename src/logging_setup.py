"""Structured JSON logging for agent runs.

Every tool invocation and finding gets written as one JSON object per line
to logs/agent-activity.jsonl, so the Evidence Collector / Report Generator
(and a human auditing the run afterwards) have a full record of what ran
against what.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"


class JsonlHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            entry.update(extra)
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = JsonlHandler(LOG_DIR / "agent-activity.jsonl")
        logger.addHandler(handler)
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(stream)
        logger.propagate = False
    return logger


def log_with_fields(logger: logging.Logger, level: int, message: str, **fields) -> None:
    logger.log(level, message, extra={"extra_fields": fields})
