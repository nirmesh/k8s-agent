from __future__ import annotations

import re
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from bson.objectid import ObjectId

from backend.core.database import get_db


class IncidentMemory:
    """Persistent storage and similarity search for past incidents.

    Stores symptoms, evidence, diagnosis, remediation, verification, confidence
    and duration. Search uses simple token overlap (no embeddings required) so it
    is deterministic and offline-capable.
    """

    _COLLECTION_NAME = "incident_memory"

    def __init__(self, db: Any | None = None):
        self._collection = (db or get_db())[self._COLLECTION_NAME]

    def store(
        self,
        symptoms: str | list[str],
        evidence: list[dict[str, Any]],
        diagnosis: dict[str, Any],
        remediation: dict[str, Any],
        verification: dict[str, Any],
        confidence: float,
        duration: float | None = None,
        incident_id: str | None = None,
    ) -> str:
        """Persist an incident and return its memory id."""
        if isinstance(symptoms, str):
            symptoms = [symptoms]
        doc = {
            "symptoms": symptoms,
            "evidence": evidence,
            "diagnosis": diagnosis,
            "remediation": remediation,
            "verification": verification,
            "confidence": confidence,
            "duration": duration,
            "incident_id": incident_id,
            "created_at": datetime.now(timezone.utc),
            "tokens": list(
                set(_tokenize(" ".join(symptoms)))
                | set(_tokenize(_flatten(diagnosis)))
            ),
        }
        result = self._collection.insert_one(doc)
        return str(result.inserted_id)

    def search_similar_incidents(
        self, symptoms: str | list[str], top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Return the top-k past incidents ranked by token overlap with the query."""
        query_text = symptoms if isinstance(symptoms, str) else " ".join(symptoms)
        query_tokens = set(_tokenize(query_text))
        if not query_tokens:
            return []

        scored: list[tuple[float, dict[str, Any]]] = []
        for doc in self._collection.find():
            stored_tokens = set(doc.get("tokens") or [])
            if not stored_tokens:
                continue
            intersection = query_tokens & stored_tokens
            union = query_tokens | stored_tokens
            score = len(intersection) / len(union) if union else 0.0
            if score > 0:
                serializable = _serialize_doc(doc)
                serializable["similarity_score"] = round(score, 3)
                scored.append((score, serializable))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

    def get(self, memory_id: str) -> dict[str, Any] | None:
        doc = self._collection.find_one({"_id": ObjectId(memory_id)})
        return _serialize_doc(doc) if doc else None


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in re.findall(r"[a-zA-Z0-9]+(?:[-_][a-zA-Z0-9]+)*", text)]


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def _serialize_doc(doc: dict[str, Any]) -> dict[str, Any]:
    copy = dict(doc)
    copy["id"] = str(copy.pop("_id"))
    for key in ("created_at",):
        if isinstance(copy.get(key), datetime):
            copy[key] = copy[key].isoformat()
    return copy
