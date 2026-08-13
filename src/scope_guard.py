"""Scope enforcement: the single authority on what agents are allowed to touch.

Every agent must call ScopeGuard.authorize(target) before running any tool
against that target. This is intentionally the *only* path to authorization --
agents and the orchestrator never make their own scope decisions.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class OutOfScopeError(Exception):
    """Raised when a target is not explicitly authorized in scope.yaml."""


class ScopeConfigError(Exception):
    """Raised when scope.yaml is missing or malformed."""


@dataclass
class AuthorizedTarget:
    name: str
    host: str
    notes: str = ""
    web_port: int | None = None
    tls_port: int | None = None


@dataclass
class ExploitTarget:
    """A target where live exploitation (ExploitAgent) is authorized.

    Separate from AuthorizedTarget -- being allowed to recon-scan a host
    does not imply exploitation is authorized against it. `resettable`
    is the load-bearing safety condition: full exploitation (real data
    extraction, real command execution) is only justified because the
    target is disposable and can be torn down and recreated. Enforced at
    load time in ScopeGuard._load, not just documented here.
    """
    name: str
    host: str
    resettable: bool
    known_vulnerabilities: dict = field(default_factory=dict)
    notes: str = ""
    web_port: int | None = None


@dataclass
class Scope:
    authorized_targets: list[AuthorizedTarget] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    max_scan_rate: float = 5.0
    authorized_code_paths: list[str] = field(default_factory=list)
    authorized_exploit_targets: list[ExploitTarget] = field(default_factory=list)


class ScopeGuard:
    def __init__(self, scope_path: str | Path):
        self.scope_path = Path(scope_path)
        self.scope = self._load(self.scope_path)

    @staticmethod
    def _load(scope_path: Path) -> Scope:
        if not scope_path.exists():
            raise ScopeConfigError(
                f"Scope file not found: {scope_path}. "
                "Copy config/scope.example.yaml to config/scope.yaml and fill "
                "in your authorized lab targets before running any agent."
            )
        with scope_path.open() as f:
            raw = yaml.safe_load(f) or {}

        targets_raw = raw.get("authorized_targets") or []
        if not targets_raw:
            raise ScopeConfigError(
                f"{scope_path} has no authorized_targets. Refusing to run "
                "against zero authorized targets."
            )

        targets = [
            AuthorizedTarget(
                name=t["name"], host=t["host"], notes=t.get("notes", ""),
                web_port=t.get("web_port"), tls_port=t.get("tls_port"),
            )
            for t in targets_raw
        ]
        excluded = raw.get("excluded") or []
        max_scan_rate = float(raw.get("max_scan_rate", 5.0))
        authorized_code_paths = raw.get("authorized_code_paths") or []

        exploit_targets_raw = raw.get("authorized_exploit_targets") or []
        exploit_targets = []
        for t in exploit_targets_raw:
            if not t.get("resettable"):
                raise ScopeConfigError(
                    f"authorized_exploit_targets entry '{t.get('name', '?')}' in "
                    f"{scope_path} is missing `resettable: true`. Full exploitation "
                    "(real data extraction, real command execution) is only "
                    "authorized against targets you can tear down and recreate -- "
                    "add `resettable: true` only if that's actually true for this "
                    "target, or remove the entry."
                )
            exploit_targets.append(ExploitTarget(
                name=t["name"], host=t["host"], resettable=True,
                known_vulnerabilities=t.get("known_vulnerabilities") or {},
                notes=t.get("notes", ""), web_port=t.get("web_port"),
            ))

        return Scope(
            authorized_targets=targets, excluded=excluded, max_scan_rate=max_scan_rate,
            authorized_code_paths=authorized_code_paths,
            authorized_exploit_targets=exploit_targets,
        )

    def resolve_target(self, name_or_host: str) -> AuthorizedTarget:
        """Look up a target by the friendly `name` field in scope.yaml."""
        for t in self.scope.authorized_targets:
            if t.name == name_or_host:
                return t
        raise OutOfScopeError(
            f"'{name_or_host}' is not a named target in {self.scope_path}. "
            f"Known targets: {[t.name for t in self.scope.authorized_targets]}"
        )

    def is_authorized(self, host: str) -> bool:
        """Check whether a literal host/IP is covered by scope, honoring exclusions."""
        try:
            resolved_ips = self._resolve_ips(host)
        except socket.gaierror:
            return False

        for excl in self.scope.excluded:
            if self._matches(excl, host, resolved_ips):
                return False

        for target in self.scope.authorized_targets:
            if self._matches(target.host, host, resolved_ips):
                return True
        return False

    def authorize(self, host: str) -> None:
        """Raise OutOfScopeError unless host is explicitly authorized."""
        if not self.is_authorized(host):
            raise OutOfScopeError(
                f"'{host}' is not in the authorized scope defined in "
                f"{self.scope_path}. Add it to authorized_targets before "
                "running any agent against it."
            )

    def resolve_exploit_target(self, name: str) -> ExploitTarget:
        """Look up an exploit target by name. Raises OutOfScopeError if the
        name isn't in authorized_exploit_targets -- being recon-authorized
        (authorized_targets) does not imply exploitation is authorized."""
        for t in self.scope.authorized_exploit_targets:
            if t.name == name:
                return t
        raise OutOfScopeError(
            f"'{name}' is not in authorized_exploit_targets in {self.scope_path}. "
            "Recon/scanning authorization does not imply exploitation is "
            "authorized -- add a separate authorized_exploit_targets entry "
            "(with resettable: true) before running ExploitAgent against it. "
            f"Known exploit targets: {[t.name for t in self.scope.authorized_exploit_targets]}"
        )

    def authorize_exploit(self, host: str) -> None:
        """Raise OutOfScopeError unless host is explicitly authorized for
        exploitation (not just recon)."""
        for t in self.scope.authorized_exploit_targets:
            if self._matches(t.host, host, self._safe_resolve_ips(host)):
                return
        raise OutOfScopeError(
            f"'{host}' is not in authorized_exploit_targets in {self.scope_path}."
        )

    def _safe_resolve_ips(self, host: str) -> set[str]:
        try:
            return self._resolve_ips(host)
        except socket.gaierror:
            return set()

    def is_path_authorized(self, path: str | Path) -> bool:
        """Check whether a local filesystem path is under an authorized
        code path (config's `authorized_code_paths`). Independent of the
        network `authorized_targets` list -- static analysis of local
        source is a different kind of scope than a network target."""
        try:
            resolved = Path(path).resolve(strict=True)
        except OSError:
            return False
        for allowed in self.scope.authorized_code_paths:
            allowed_resolved = Path(allowed).resolve()
            if resolved == allowed_resolved or allowed_resolved in resolved.parents:
                return True
        return False

    def authorize_path(self, path: str | Path) -> None:
        """Raise OutOfScopeError unless path is under an authorized code path."""
        if not self.is_path_authorized(path):
            raise OutOfScopeError(
                f"'{path}' is not under any authorized_code_paths entry in "
                f"{self.scope_path}. Add its directory before running "
                "CodeAnalyzer against it."
            )

    @staticmethod
    def _resolve_ips(host: str) -> set[str]:
        try:
            ipaddress.ip_address(host)
            return {host}
        except ValueError:
            pass
        infos = socket.getaddrinfo(host, None)
        return {info[4][0] for info in infos}

    @staticmethod
    def _matches(scope_entry: str, host: str, resolved_ips: set[str]) -> bool:
        if scope_entry == host:
            return True
        try:
            network = ipaddress.ip_network(scope_entry, strict=False)
            for ip in resolved_ips:
                if ipaddress.ip_address(ip) in network:
                    return True
        except ValueError:
            pass
        return False
