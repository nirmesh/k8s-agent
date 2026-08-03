import json

import httpx

from backend.core.config import settings
from backend.core.logging import logger


def generate(prompt: str, system: str | None = None, retries: int = 2) -> str:
    """Return LLM response text. Implemented via the chat endpoint for consistency."""
    messages = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    message = chat(messages, tools=None, retries=retries)
    return message.get("content", "")


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
