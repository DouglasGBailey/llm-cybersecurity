"""Recon Agent: passive-first target enumeration.

Scope: DNS resolution, WHOIS lookup, and a capped nmap service/version scan.
No exploitation, no brute force, no aggressive scripts -- this agent only
answers "what's here and what's it running", nothing more.
"""
from __future__ import annotations

import logging
import re

from src.agent_base import AgentResult, BaseAgent
from src.logging_setup import log_with_fields


class ReconAgent(BaseAgent):
    name = "recon-agent"
    allowed_tools = ["nmap", "dig", "whois"]

    # Deliberately capped: default NSE scripts + version detection only,
    # top 100 ports, no aggressive timing, no exploitation scripts.
    NMAP_ARGS = ["-sV", "--script=default", "--top-ports", "100", "-T3"]

    def run(self, target: str) -> AgentResult:
        self.scope_guard.authorize(target)
        result = AgentResult(
            agent_name=self.name, target=target, timestamp=self._now(), status="ok"
        )

        for step in (self._dig, self._whois, self._nmap):
            try:
                step(target, result)
            except FileNotFoundError as e:
                log_with_fields(self.logger, logging.WARNING, str(e), target=target)
                result.findings.append({"type": "tool-unavailable", "detail": str(e)})
            except Exception as e:  # noqa: BLE001 - surface any tool failure as a finding
                log_with_fields(self.logger, logging.ERROR, str(e), target=target)
                result.findings.append({"type": "error", "step": step.__name__, "detail": str(e)})

        return result

    def _dig(self, target: str, result: AgentResult) -> None:
        proc = self._run_tool(["dig", "+short", target])
        result.raw_output.append(f"dig: {proc.stdout.strip()}")
        ips = [line for line in proc.stdout.splitlines() if line.strip()]
        if ips:
            result.findings.append({"type": "dns-resolution", "records": ips})

    def _whois(self, target: str, result: AgentResult) -> None:
        proc = self._run_tool(["whois", target])
        result.raw_output.append(f"whois: {proc.stdout[:2000]}")
        registrar = re.search(r"Registrar:\s*(.+)", proc.stdout)
        if registrar:
            result.findings.append({"type": "whois-registrar", "value": registrar.group(1).strip()})

    def _nmap(self, target: str, result: AgentResult) -> None:
        proc = self._run_tool(["nmap", *self.NMAP_ARGS, target])
        result.raw_output.append(f"nmap: {proc.stdout[:4000]}")
        open_ports = re.findall(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", proc.stdout, re.MULTILINE)
        for port, proto, service in open_ports:
            result.findings.append({
                "type": "open-port",
                "port": int(port),
                "protocol": proto,
                "service": service,
            })
