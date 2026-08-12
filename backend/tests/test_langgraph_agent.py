from pathlib import Path

from backend.agentic.graph import graph, route_after_diagnosis


def test_langgraph_graph_contains_controlled_investigation_nodes():
    nodes = set(graph.get_graph().nodes)
    assert {"collect_operational", "collect_security", "diagnose", "expand_evidence"}.issubset(nodes)


def test_validation_failure_can_trigger_one_expansion_pass():
    assert route_after_diagnosis({"synthesis": {"status": "NEED_MORE_EVIDENCE"}, "expansion_passes": 0}) == "expand_evidence"
    assert route_after_diagnosis({"synthesis": {"status": "NEED_MORE_EVIDENCE"}, "expansion_passes": 1}) == "finish"
    assert route_after_diagnosis({"synthesis": {"status": "DIAGNOSED"}, "expansion_passes": 0}) == "finish"


def test_kubernetes_backend_does_not_shell_out_to_kubectl():
    root = Path(__file__).resolve().parents[1] / "kubernetes"
    forbidden = ("subprocess.", "os.system(", "os.popen(", "commands.getoutput(")
    kubectl_command_patterns = ("kubectl get ", "kubectl describe ", "kubectl apply ", "kubectl patch ", "kubectl delete ", "kubectl rollout ")

    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not any(token in text for token in forbidden), f"Shell execution found in {path}"
        assert not any(token in text for token in kubectl_command_patterns), f"kubectl command found in {path}"


def test_toolkit_uses_kubernetes_python_client():
    toolkit = (root / "toolkit.py").read_text(encoding="utf-8")
    assert "from kubernetes import client, config" in toolkit
    assert "config.new_client_from_config" in toolkit
    assert "CoreV1Api" in toolkit
    assert "AppsV1Api" in toolkit
