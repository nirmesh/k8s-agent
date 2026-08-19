from typing import Any


def persist_security_evidence(db: Any, investigation_id: str, evidence: list[Any]) -> int:
    """Persist large security evidence sets outside the parent investigation document."""
    if not evidence:
        return 0
    collection = db.investigation_security_evidence
    collection.delete_many({"investigation_id": investigation_id})
    documents = []
    for item in evidence:
        if hasattr(item, "model_dump"):
            item = item.model_dump(mode="json")
        elif hasattr(item, "dict"):
            item = item.dict()
        elif not isinstance(item, dict):
            item = {"value": str(item)}
        item["investigation_id"] = investigation_id
        documents.append(item)
    if documents:
        collection.insert_many(documents, ordered=False)
    return len(documents)
