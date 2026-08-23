from typing import Any


MAX_PERSISTED_SECURITY_EVIDENCE = 100


def persist_security_evidence(db: Any, investigation_id: str, evidence: list[Any]) -> int:
    """Persist a bounded evidence sample; aggregate security counts stay in the summary."""
    collection = db.investigation_security_evidence
    collection.delete_many({"investigation_id": investigation_id})
    if not evidence:
        return 0

    documents = []
    for item in evidence[:MAX_PERSISTED_SECURITY_EVIDENCE]:
        if hasattr(item, "model_dump"):
            item = item.model_dump(mode="json")
        elif hasattr(item, "dict"):
            item = item.dict()
        elif not isinstance(item, dict):
            item = {"value": str(item)}
        item["investigation_id"] = investigation_id
        documents.append(item)

    collection.insert_many(documents, ordered=False)
    return len(documents)
