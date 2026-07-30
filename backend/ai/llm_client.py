import json

import httpx

from backend.core.config import settings
from backend.core.logging import logger


def generate(prompt: str, system: str | None = None, retries: int = 2) -> str:
    """Call the Ollama generate endpoint and return the LLM response text."""
    url = f"{settings.ollama_host}/api/generate"
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
    }
    if settings.ollama_json_format:
        payload["format"] = "json"
    if system is not None:
        payload["system"] = system

    for attempt in range(retries + 1):
        try:
            logger.info(f"Calling Ollama at {url} (attempt {attempt + 1})")
            with httpx.Client(timeout=settings.ollama_timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("response", "")
        except httpx.TimeoutException:
            logger.error(f"Ollama request timed out (attempt {attempt + 1})")
        except httpx.HTTPError as exc:
            logger.error(f"Ollama HTTP error (attempt {attempt + 1}): {exc}")
        except Exception as exc:
            logger.error(f"Ollama call failed (attempt {attempt + 1}): {exc}")

    return json.dumps({
        "root_cause": "LLM unavailable",
        "explanation": "The AI reasoning service could not be reached.",
        "fix": "Verify Ollama is running and OLLAMA_HOST/OLLAMA_MODEL are configured.",
        "kubectl_command": "",
        "prevention": "",
        "confidence": 0,
    })


def chat(messages: list[dict], tools: list[dict] | None = None, retries: int = 2) -> dict:
    """Call Ollama /api/chat and return the assistant message, including native tool_calls."""
    url = f"{settings.ollama_host}/api/chat"
    payload = {
        "model": settings.ollama_model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.1},
    }
    if tools:
        payload["tools"] = tools

    for attempt in range(retries + 1):
        try:
            logger.info(f"Calling Ollama chat at {url} (attempt {attempt + 1})")
            with httpx.Client(timeout=settings.ollama_timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("message") or {"role": "assistant", "content": ""}
        except httpx.TimeoutException:
            logger.error(f"Ollama chat request timed out (attempt {attempt + 1})")
        except httpx.HTTPError as exc:
            logger.error(f"Ollama chat HTTP error (attempt {attempt + 1}): {exc}")
        except Exception as exc:
            logger.error(f"Ollama chat call failed (attempt {attempt + 1}): {exc}")

    return {"role": "assistant", "content": ""}
