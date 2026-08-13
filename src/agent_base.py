"""Base class every security agent must subclass.

Design constraints (see plan doc for rationale):
- Every run() call MUST check the target against ScopeGuard before doing
  anything else.
- Every external command an agent can invoke must appear in that agent's
  `allowed_tools` list. `_run_tool` refuses to execute anything else.
- subprocess is always invoked with a list of args (never shell=True) and
  always with a timeout, to avoid shell injection and hangs.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.logging_setup import get_logger, log_with_fields
from src.scope_guard import ScopeGuard


class DisallowedToolError(Exception):
    """Raised when an agent tries to run a binary outside its allowed_tools."""


@dataclass
class AgentResult:
    agent_name: str
    target: str
    timestamp: str
    status: str  # "ok" | "error" | "skipped"
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_output: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "target": self.target,
            "timestamp": self.timestamp,
            "status": self.status,
            "findings": self.findings,
            "raw_output": self.raw_output,
            "error": self.error,
        }


class BaseAgent(ABC):
    name: str = "base-agent"
    allowed_tools: list[str] = []
    default_timeout_seconds: int = 60

    def __init__(self, scope_guard: ScopeGuard, dry_run: bool = True):
        self.scope_guard = scope_guard
        self.dry_run = dry_run
        self.logger: logging.Logger = get_logger(f"agent.{self.name}")
        self._last_call_ts: float = 0.0

    @abstractmethod
    def run(self, target: str) -> AgentResult:
        """Execute this agent's checks against `target`. Must call
        self.scope_guard.authorize(target) before any tool invocation."""
        raise NotImplementedError

    def _run_tool(self, cmd: list[str]) -> subprocess.CompletedProcess:
        binary = cmd[0]
        if binary not in self.allowed_tools:
            raise DisallowedToolError(
                f"{self.name} is not permitted to run '{binary}'. "
                f"Allowed tools: {self.allowed_tools}"
            )
        if shutil.which(binary) is None:
            raise FileNotFoundError(
                f"Required tool '{binary}' is not installed or not on PATH."
            )

        self._respect_rate_limit()
        log_with_fields(self.logger, logging.INFO, "running tool", command=cmd)

        if self.dry_run:
            log_with_fields(self.logger, logging.INFO, "dry-run: not executing", command=cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.default_timeout_seconds,
            shell=False,
        )
        log_with_fields(
            self.logger, logging.INFO, "tool finished",
            command=cmd, returncode=result.returncode,
        )
        return result

    def _respect_rate_limit(self) -> None:
        max_rate = self.scope_guard.scope.max_scan_rate or 5.0
        min_interval = 1.0 / max_rate
        elapsed = time.monotonic() - self._last_call_ts
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_call_ts = time.monotonic()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()
