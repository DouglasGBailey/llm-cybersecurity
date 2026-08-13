"""Kubernetes Analyzer: read-only hygiene checks against an authorized
cluster context.

Scope: `kubectl get` only (list/read operations) via the ambient
kubeconfig -- never `apply`/`create`/`delete`/`exec`/`patch`. Connects by
kubeconfig context name (`target` here), never a network host, so this
agent never calls `scope_guard.authorize()`; it uses the matching
`authorize_k8s_context()` instead (see src/scope_guard.py). No cluster
credentials are ever read from scope.yaml -- the ambient kubeconfig
(KUBECONFIG env var or ~/.kube/config) is the sole credential source, the
same "config references, never stores, credentials" pattern alerting.py
uses for SMTP.

Checks work correctly against a single-node cluster (kind/minikube/k3s,
the expected lab target) -- nothing here assumes multi-node topology, all
checks are namespace/resource scoped, not node-topology dependent.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from src.agent_base import AgentResult, BaseAgent
from src.logging_setup import log_with_fields

# Namespaces excluded from the "missing NetworkPolicy" / "default SA
# automounts token" checks -- these are cluster-managed control-plane
# namespaces, not application workloads an operator configures themselves.
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}

# Built-in ClusterRoles that are *expected* to carry broad/wildcard
# permissions by design -- flagging them would be noise, not signal. Only
# custom cluster roles reaching for wildcard access are worth flagging.
BUILTIN_CLUSTERROLE_NAMES = {"cluster-admin", "admin", "edit", "view"}

# The default control-plane binding of cluster-admin to Group
# system:masters is expected. Only User/ServiceAccount subjects bound to
# cluster-admin represent an operator-introduced risk.
RISKY_SUBJECT_KINDS = {"User", "ServiceAccount"}


class KubernetesAnalyzer(BaseAgent):
    name = "k8s-analyzer"
    allowed_tools = ["kubectl"]
    default_timeout_seconds = 60

    def run(self, target: str) -> AgentResult:
        self.scope_guard.authorize_k8s_context(target)
        result = AgentResult(
            agent_name=self.name, target=target, timestamp=self._now(), status="ok"
        )

        for step in (
            self._check_pod_security,
            self._check_rbac,
            self._check_service_exposure,
            self._check_network_policies,
            self._check_default_serviceaccounts,
            self._check_nodes,
        ):
            try:
                step(target, result)
            except FileNotFoundError as e:
                log_with_fields(self.logger, logging.WARNING, str(e), target=target)
                result.findings.append({"type": "tool-unavailable", "detail": str(e)})
            except Exception as e:  # noqa: BLE001 - surface any tool/cluster failure as a finding
                log_with_fields(self.logger, logging.ERROR, str(e), target=target, step=step.__name__)
                result.findings.append({"type": "error", "step": step.__name__, "detail": str(e)})

        return result

    def _kubectl_json(self, context: str, args: list[str]) -> dict[str, Any] | None:
        proc = self._run_tool(["kubectl", "--context", context, *args, "-o", "json"])
        stdout = proc.stdout.strip()
        if not stdout:
            return None
        return json.loads(stdout)

    def _check_pod_security(self, context: str, result: AgentResult) -> None:
        data = self._kubectl_json(context, ["get", "pods", "-A"])
        if data is None:
            return

        missing_limits_by_ns: dict[str, int] = {}
        for pod in data.get("items", []):
            namespace = pod.get("metadata", {}).get("namespace", "?")
            pod_name = pod.get("metadata", {}).get("name", "?")
            spec = pod.get("spec", {})

            if spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC"):
                result.findings.append({
                    "type": "k8s-host-namespace-shared",
                    "namespace": namespace, "pod": pod_name,
                    "hostNetwork": bool(spec.get("hostNetwork")),
                    "hostPID": bool(spec.get("hostPID")),
                    "hostIPC": bool(spec.get("hostIPC")),
                })

            for container in spec.get("containers", []):
                sc = container.get("securityContext") or {}
                container_name = container.get("name", "?")

                if sc.get("privileged"):
                    result.findings.append({
                        "type": "k8s-privileged-container",
                        "namespace": namespace, "pod": pod_name, "container": container_name,
                    })
                if sc.get("runAsUser") == 0:
                    result.findings.append({
                        "type": "k8s-container-runs-as-root",
                        "namespace": namespace, "pod": pod_name, "container": container_name,
                    })

                resources = container.get("resources") or {}
                limits = resources.get("limits") or {}
                if "cpu" not in limits or "memory" not in limits:
                    missing_limits_by_ns[namespace] = missing_limits_by_ns.get(namespace, 0) + 1

        for namespace, count in missing_limits_by_ns.items():
            result.findings.append({
                "type": "k8s-missing-resource-limits",
                "namespace": namespace, "container_count": count,
            })

    def _check_rbac(self, context: str, result: AgentResult) -> None:
        bindings = self._kubectl_json(context, ["get", "clusterrolebindings"])
        if bindings is not None:
            for binding in bindings.get("items", []):
                role_ref = binding.get("roleRef", {})
                if role_ref.get("name") != "cluster-admin":
                    continue
                for subject in binding.get("subjects") or []:
                    if subject.get("kind") in RISKY_SUBJECT_KINDS:
                        result.findings.append({
                            "type": "k8s-overly-permissive-clusterrolebinding",
                            "binding": binding.get("metadata", {}).get("name", "?"),
                            "subject_kind": subject.get("kind"),
                            "subject_name": subject.get("name"),
                            "subject_namespace": subject.get("namespace"),
                        })

        roles = self._kubectl_json(context, ["get", "clusterroles"])
        if roles is not None:
            for role in roles.get("items", []):
                role_name = role.get("metadata", {}).get("name", "?")
                if role_name in BUILTIN_CLUSTERROLE_NAMES or role_name.startswith("system:"):
                    continue
                for rule in role.get("rules") or []:
                    if "*" in (rule.get("resources") or []) and "*" in (rule.get("verbs") or []):
                        result.findings.append({
                            "type": "k8s-wildcard-clusterrole",
                            "role": role_name,
                        })
                        break

    def _check_service_exposure(self, context: str, result: AgentResult) -> None:
        data = self._kubectl_json(context, ["get", "services", "-A"])
        if data is None:
            return
        for svc in data.get("items", []):
            svc_type = svc.get("spec", {}).get("type")
            if svc_type in ("NodePort", "LoadBalancer"):
                result.findings.append({
                    "type": "k8s-service-publicly-exposed",
                    "namespace": svc.get("metadata", {}).get("namespace", "?"),
                    "service": svc.get("metadata", {}).get("name", "?"),
                    "service_type": svc_type,
                })

    def _check_network_policies(self, context: str, result: AgentResult) -> None:
        namespaces_data = self._kubectl_json(context, ["get", "namespaces"])
        if namespaces_data is None:
            return
        all_namespaces = {
            ns.get("metadata", {}).get("name")
            for ns in namespaces_data.get("items", [])
        } - SYSTEM_NAMESPACES

        policies_data = self._kubectl_json(context, ["get", "networkpolicies", "-A"])
        covered_namespaces = {
            np.get("metadata", {}).get("namespace")
            for np in (policies_data.get("items", []) if policies_data else [])
        }

        for namespace in sorted(all_namespaces - covered_namespaces):
            result.findings.append({
                "type": "k8s-namespace-missing-network-policy",
                "namespace": namespace,
            })

    def _check_default_serviceaccounts(self, context: str, result: AgentResult) -> None:
        data = self._kubectl_json(context, ["get", "serviceaccounts", "-A"])
        if data is None:
            return
        for sa in data.get("items", []):
            namespace = sa.get("metadata", {}).get("namespace", "?")
            if sa.get("metadata", {}).get("name") != "default" or namespace in SYSTEM_NAMESPACES:
                continue
            if sa.get("automountServiceAccountToken") is not False:
                result.findings.append({
                    "type": "k8s-default-serviceaccount-automounts-token",
                    "namespace": namespace,
                })

    def _check_nodes(self, context: str, result: AgentResult) -> None:
        data = self._kubectl_json(context, ["get", "nodes"])
        if data is None:
            return
        nodes = data.get("items", [])
        node_info = [
            {
                "name": node.get("metadata", {}).get("name", "?"),
                "kubelet_version": node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion"),
            }
            for node in nodes
        ]
        result.raw_output.append(f"nodes: {len(nodes)}")
        result.findings.append({
            "type": "k8s-node-info",
            "node_count": len(nodes),
            "nodes": node_info,
        })
