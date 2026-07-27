import json
import subprocess
import threading
from typing import Any

from backend.core.logging import logger

_context = threading.local()


def set_context(context: str | None):
    """Set the active kubectl context for the current thread."""
    _context.name = context


def get_context() -> str | None:
    return getattr(_context, "name", None)


def run_kubectl(args: list[str], timeout: int = 30) -> dict[str, Any]:
    """Safely execute a kubectl command and return a structured result."""
    command = ["kubectl"]
    context = get_context()
    if context:
        command += ["--context", context]
    command += args
    try:
        logger.info(f"Running kubectl: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "command": " ".join(command),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
        }
    except FileNotFoundError:
        logger.error("kubectl binary not found in PATH")
        return {
            "command": " ".join(command),
            "returncode": -1,
            "stdout": "",
            "stderr": "kubectl binary not found",
            "success": False,
        }
    except subprocess.TimeoutExpired:
        logger.error(f"kubectl command timed out: {' '.join(command)}")
        return {
            "command": " ".join(command),
            "returncode": -1,
            "stdout": "",
            "stderr": "kubectl command timed out",
            "success": False,
        }
    except Exception as exc:
        logger.error(f"Unexpected error running kubectl: {exc}")
        return {
            "command": " ".join(command),
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "success": False,
        }


def run_kubectl_json(args: list[str], timeout: int = 30) -> dict[str, Any] | None:
    """Run kubectl and parse JSON output. Returns None on failure."""
    result = run_kubectl(args + ["-o", "json"], timeout=timeout)
    if not result["success"]:
        return None
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        logger.error(f"Failed to parse kubectl JSON output: {exc}")
        return None
