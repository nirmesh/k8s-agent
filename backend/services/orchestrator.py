from backend.ai import reasoning
from backend.kubernetes import inspector


def run_investigation() -> dict:
    inspector.inspect_pods()
    reasoning.build_prompt()
    return {"status": "pending"}
