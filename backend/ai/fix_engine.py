from backend.core.logging import logger


def _fallback_fix(root_cause: str) -> dict:
    """Provide beginner-friendly fallback fixes when the LLM response is incomplete."""
    lower = root_cause.lower()

    if "environment variable" in lower:
        return {
            "fix": "Add or correct the missing environment variable in the deployment.",
            "kubectl_command": "kubectl edit deployment <deployment-name> -n <namespace>",
            "prevention": "Use ConfigMaps or Secrets and validate env vars in CI.",
        }
    if "image" in lower:
        return {
            "fix": "Verify the image tag exists and that the registry is accessible.",
            "kubectl_command": "kubectl describe pod <pod-name> -n <namespace>",
            "prevention": "Pin image tags and test image pull in a staging cluster.",
        }
    if "crash" in lower:
        return {
            "fix": "Inspect pod logs and events to find the startup failure reason.",
            "kubectl_command": "kubectl logs <pod-name> -n <namespace> --previous",
            "prevention": "Add readiness/liveness probes and health checks.",
        }
    if "memory" in lower or "oom" in lower:
        return {
            "fix": "Increase memory limits or optimize the application memory usage.",
            "kubectl_command": "kubectl edit deployment <deployment-name> -n <namespace>",
            "prevention": "Set resource requests/limits and monitor memory trends.",
        }
    if "schedule" in lower:
        return {
            "fix": "Check node resources, taints, tolerations, and affinity rules.",
            "kubectl_command": "kubectl describe pod <pod-name> -n <namespace>",
            "prevention": "Right-size nodes and review scheduling constraints.",
        }
    if "endpoint" in lower or "service" in lower:
        return {
            "fix": "Verify the service selector matches pod labels and pods are running.",
            "kubectl_command": "kubectl get endpoints -n <namespace>",
            "prevention": "Keep labels and selectors in sync in deployment manifests.",
        }

    return {
        "fix": "Review the investigation evidence and apply a targeted fix.",
        "kubectl_command": "kubectl get all -n <namespace>",
        "prevention": "Add monitoring and alerts for cluster health.",
    }


def extract_fix(llm_output: dict, root_cause: str = "") -> dict:
    """Extract fix, kubectl command, and prevention from LLM output."""
    fix = llm_output.get("fix")
    kubectl_command = llm_output.get("kubectl_command")
    prevention = llm_output.get("prevention")

    if fix and kubectl_command and prevention:
        return {
            "fix": fix,
            "kubectl_command": kubectl_command,
            "prevention": prevention,
        }

    logger.warning("LLM did not return complete fix details, using fallback")
    return _fallback_fix(root_cause)
