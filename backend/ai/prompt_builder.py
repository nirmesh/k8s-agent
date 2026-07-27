import json


def build_prompt(investigation: dict) -> str:
    """Build a structured Senior Kubernetes SRE prompt for the LLM."""
    return (
        "You are a Senior Kubernetes Site Reliability Engineer. "
        "Analyze the following cluster investigation evidence and identify the root cause. "
        "Be specific, avoid vague language, and base your reasoning on the evidence.\n\n"
        "Return ONLY a valid JSON object with exactly these keys:\n"
        '- "root_cause": a concise root cause summary\n'
        '- "explanation": 1-3 sentences explaining the failure\n'
        '- "fix": a practical step-by-step fix\n'
        '- "kubectl_command": a kubectl command the user can run\n'
        '- "prevention": how to prevent this in the future\n'
        '- "confidence": an integer confidence score from 0 to 100\n\n'
        "Investigation evidence:\n"
        f"{json.dumps(investigation, indent=2)}"
    )
