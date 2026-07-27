import json

from backend.ai.confidence_engine import compute_confidence
from backend.ai.fix_engine import extract_fix
from backend.ai.llm_client import generate
from backend.ai.prompt_builder import build_prompt
from backend.ai.root_cause_analyzer import extract_root_cause


def analyze(investigation: dict) -> dict:
    """Analyze investigation evidence and return a structured diagnosis."""
    prompt = build_prompt(investigation)
    raw_response = generate(prompt)

    try:
        llm_output = json.loads(raw_response)
    except json.JSONDecodeError:
        llm_output = {}

    root_cause = extract_root_cause(llm_output, investigation)
    fix_details = extract_fix(llm_output, root_cause)
    confidence = compute_confidence(investigation, llm_output)

    def _str(value) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2)
        return str(value)

    def _int(value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    return {
        "root_cause": _str(root_cause),
        "explanation": _str(llm_output.get("explanation", "No explanation provided.")),
        "fix": _str(fix_details["fix"]),
        "kubectl_command": _str(fix_details["kubectl_command"]),
        "prevention": _str(fix_details["prevention"]),
        "confidence": _int(confidence),
    }
