import json
import subprocess
import textwrap
from unittest.mock import patch

import pytest

from src.agents.k8s_analyzer import KubernetesAnalyzer
from src.scope_guard import OutOfScopeError, ScopeGuard

CONTEXT = "kind-lab"


@pytest.fixture
def guard(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(f"""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
        max_scan_rate: 1000
        authorized_k8s_clusters:
          - name: local-k8s-lab
            context: {CONTEXT}
    """))
    return ScopeGuard(p)


def resource_of(cmd: list[str]) -> str:
    return cmd[cmd.index("get") + 1]


def empty_list() -> dict:
    return {"items": []}


def make_fake_kubectl(resources: dict[str, dict]):
    """resources maps resource-type ('pods', 'nodes', ...) to the JSON
    body kubectl would return for `get <resource> [-A] -o json`. Any
    resource type not present in the map returns an empty list."""
    def fake_run(cmd, **kwargs):
        body = resources.get(resource_of(cmd), empty_list())
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(body), stderr="")
    return fake_run


def run_agent(guard, resources: dict[str, dict], dry_run: bool = False):
    agent = KubernetesAnalyzer(guard, dry_run=dry_run)
    with patch("shutil.which", return_value="/usr/bin/fake"), \
         patch("subprocess.run", side_effect=make_fake_kubectl(resources)):
        return agent.run(CONTEXT)


def test_out_of_scope_context_rejected(guard):
    agent = KubernetesAnalyzer(guard, dry_run=False)
    with patch("subprocess.run") as mock_run:
        with pytest.raises(OutOfScopeError):
            agent.run("not-an-authorized-context")
        mock_run.assert_not_called()


def test_dry_run_makes_no_real_kubectl_calls(guard):
    agent = KubernetesAnalyzer(guard, dry_run=True)
    with patch("subprocess.run") as mock_run, patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(CONTEXT)
        mock_run.assert_not_called()
    assert result.status == "ok"
    assert result.findings == []


def test_tool_unavailable_recorded_not_crashed(guard):
    agent = KubernetesAnalyzer(guard, dry_run=False)
    with patch("shutil.which", return_value=None):
        result = agent.run(CONTEXT)
    assert result.status == "ok"
    assert all(f["type"] == "tool-unavailable" for f in result.findings)
    assert result.findings


def test_privileged_container_detected(guard):
    pods = {"items": [{
        "metadata": {"namespace": "default", "name": "evil-pod"},
        "spec": {"containers": [
            {"name": "c1", "securityContext": {"privileged": True}, "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}},
        ]},
    }]}
    result = run_agent(guard, {"pods": pods})
    findings = [f for f in result.findings if f["type"] == "k8s-privileged-container"]
    assert len(findings) == 1
    assert findings[0]["pod"] == "evil-pod"
    assert findings[0]["container"] == "c1"


def test_container_runs_as_root_detected(guard):
    pods = {"items": [{
        "metadata": {"namespace": "default", "name": "root-pod"},
        "spec": {"containers": [
            {"name": "c1", "securityContext": {"runAsUser": 0}, "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}},
        ]},
    }]}
    result = run_agent(guard, {"pods": pods})
    findings = [f for f in result.findings if f["type"] == "k8s-container-runs-as-root"]
    assert len(findings) == 1
    assert findings[0]["pod"] == "root-pod"


def test_non_privileged_non_root_container_not_flagged(guard):
    pods = {"items": [{
        "metadata": {"namespace": "default", "name": "safe-pod"},
        "spec": {"containers": [
            {"name": "c1", "securityContext": {"runAsUser": 1000, "privileged": False},
             "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}},
        ]},
    }]}
    result = run_agent(guard, {"pods": pods})
    assert not [f for f in result.findings if f["type"] in ("k8s-privileged-container", "k8s-container-runs-as-root")]


def test_host_namespace_shared_detected(guard):
    pods = {"items": [{
        "metadata": {"namespace": "default", "name": "host-pod"},
        "spec": {"hostNetwork": True, "hostPID": True, "containers": []},
    }]}
    result = run_agent(guard, {"pods": pods})
    findings = [f for f in result.findings if f["type"] == "k8s-host-namespace-shared"]
    assert len(findings) == 1
    assert findings[0]["hostNetwork"] is True
    assert findings[0]["hostPID"] is True
    assert findings[0]["hostIPC"] is False


def test_missing_resource_limits_aggregated_by_namespace(guard):
    pods = {"items": [
        {
            "metadata": {"namespace": "default", "name": "p1"},
            "spec": {"containers": [{"name": "c1", "resources": {}}, {"name": "c2", "resources": {"limits": {"cpu": "1"}}}]},
        },
        {
            "metadata": {"namespace": "default", "name": "p2"},
            "spec": {"containers": [{"name": "c3"}]},
        },
    ]}
    result = run_agent(guard, {"pods": pods})
    findings = [f for f in result.findings if f["type"] == "k8s-missing-resource-limits"]
    assert len(findings) == 1
    assert findings[0]["namespace"] == "default"
    # c1 (no limits at all), c2 (limits present but missing 'memory'), c3 (no resources block) = 3
    assert findings[0]["container_count"] == 3


def test_clusterrolebinding_serviceaccount_to_cluster_admin_flagged(guard):
    bindings = {"items": [{
        "metadata": {"name": "risky-binding"},
        "roleRef": {"name": "cluster-admin"},
        "subjects": [{"kind": "ServiceAccount", "name": "ci-bot", "namespace": "default"}],
    }]}
    result = run_agent(guard, {"clusterrolebindings": bindings})
    findings = [f for f in result.findings if f["type"] == "k8s-overly-permissive-clusterrolebinding"]
    assert len(findings) == 1
    assert findings[0]["subject_name"] == "ci-bot"


def test_default_cluster_admin_group_binding_not_flagged(guard):
    """The built-in cluster-admin -> Group:system:masters binding is
    expected control-plane wiring, not an operator-introduced risk."""
    bindings = {"items": [{
        "metadata": {"name": "cluster-admin"},
        "roleRef": {"name": "cluster-admin"},
        "subjects": [{"kind": "Group", "name": "system:masters"}],
    }]}
    result = run_agent(guard, {"clusterrolebindings": bindings})
    assert not [f for f in result.findings if f["type"] == "k8s-overly-permissive-clusterrolebinding"]


def test_wildcard_clusterrole_detected(guard):
    roles = {"items": [{
        "metadata": {"name": "super-role"},
        "rules": [{"resources": ["*"], "verbs": ["*"], "apiGroups": ["*"]}],
    }]}
    result = run_agent(guard, {"clusterroles": roles})
    findings = [f for f in result.findings if f["type"] == "k8s-wildcard-clusterrole"]
    assert len(findings) == 1
    assert findings[0]["role"] == "super-role"


def test_builtin_clusterroles_not_flagged_for_wildcard(guard):
    roles = {"items": [
        {"metadata": {"name": "cluster-admin"}, "rules": [{"resources": ["*"], "verbs": ["*"]}]},
        {"metadata": {"name": "system:node"}, "rules": [{"resources": ["*"], "verbs": ["*"]}]},
    ]}
    result = run_agent(guard, {"clusterroles": roles})
    assert not [f for f in result.findings if f["type"] == "k8s-wildcard-clusterrole"]


def test_nodeport_and_loadbalancer_services_flagged(guard):
    services = {"items": [
        {"metadata": {"namespace": "default", "name": "svc-np"}, "spec": {"type": "NodePort"}},
        {"metadata": {"namespace": "default", "name": "svc-lb"}, "spec": {"type": "LoadBalancer"}},
        {"metadata": {"namespace": "default", "name": "svc-ci"}, "spec": {"type": "ClusterIP"}},
    ]}
    result = run_agent(guard, {"services": services})
    findings = [f for f in result.findings if f["type"] == "k8s-service-publicly-exposed"]
    assert {f["service"] for f in findings} == {"svc-np", "svc-lb"}


def test_namespace_missing_network_policy_detected(guard):
    namespaces = {"items": [
        {"metadata": {"name": "default"}},
        {"metadata": {"name": "kube-system"}},
        {"metadata": {"name": "app-ns"}},
    ]}
    policies = {"items": [{"metadata": {"namespace": "app-ns", "name": "allow-x"}}]}
    result = run_agent(guard, {"namespaces": namespaces, "networkpolicies": policies})
    findings = {f["namespace"] for f in result.findings if f["type"] == "k8s-namespace-missing-network-policy"}
    assert findings == {"default"}  # app-ns covered, kube-system excluded as a system namespace


def test_default_serviceaccount_automounts_token_flagged(guard):
    sas = {"items": [
        {"metadata": {"namespace": "default", "name": "default"}},
        {"metadata": {"namespace": "app-ns", "name": "default"}, "automountServiceAccountToken": False},
        {"metadata": {"namespace": "kube-system", "name": "default"}},
        {"metadata": {"namespace": "default", "name": "custom-sa"}},
    ]}
    result = run_agent(guard, {"serviceaccounts": sas})
    findings = {f["namespace"] for f in result.findings if f["type"] == "k8s-default-serviceaccount-automounts-token"}
    assert findings == {"default"}


def test_node_info_reported_for_single_node_cluster(guard):
    nodes = {"items": [{
        "metadata": {"name": "kind-lab-control-plane"},
        "status": {"nodeInfo": {"kubeletVersion": "v1.29.0"}},
    }]}
    result = run_agent(guard, {"nodes": nodes})
    findings = [f for f in result.findings if f["type"] == "k8s-node-info"]
    assert len(findings) == 1
    assert findings[0]["node_count"] == 1
    assert findings[0]["nodes"][0]["name"] == "kind-lab-control-plane"
    assert findings[0]["nodes"][0]["kubelet_version"] == "v1.29.0"


def test_kubectl_failure_recorded_not_crashed(guard):
    agent = KubernetesAnalyzer(guard, dry_run=False)

    def failing_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 60)

    with patch("shutil.which", return_value="/usr/bin/fake"), patch("subprocess.run", side_effect=failing_run):
        result = agent.run(CONTEXT)

    assert result.status == "ok"
    assert [f for f in result.findings if f["type"] == "error"]
