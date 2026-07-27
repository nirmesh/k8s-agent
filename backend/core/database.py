from pymongo import MongoClient

from backend.core.config import settings

_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(settings.mongodb_url)
    return _client


def get_db():
    return get_client()[settings.mongodb_database]
