import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from bson.objectid import ObjectId

from backend.core.database import get_db


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def create_user(email: str, password: str) -> dict:
    db = get_db()
    if db.users.find_one({"email": email}):
        return {"error": "User already exists"}

    salt = secrets.token_hex(16)
    user = {
        "email": email,
        "salt": salt,
        "password_hash": _hash_password(password, salt),
        "created_at": datetime.now(timezone.utc),
    }
    result = db.users.insert_one(user)
    return {"id": str(result.inserted_id), "email": email}


def authenticate_user(email: str, password: str) -> dict | None:
    db = get_db()
    user = db.users.find_one({"email": email})
    if not user:
        return None

    hashed = _hash_password(password, user["salt"])
    if not hmac.compare_digest(hashed, user["password_hash"]):
        return None
    return user


def create_session(user_id: str) -> dict:
    db = get_db()
    token = _generate_token()
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    session = {
        "token": token,
        "user_id": user_id,
        "expires_at": expires,
        "created_at": datetime.now(timezone.utc),
    }
    db.sessions.insert_one(session)
    return {"token": token, "expires_at": expires}


def get_user_by_token(token: str) -> dict | None:
    db = get_db()
    session = db.sessions.find_one({
        "token": token,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if not session:
        return None
    return db.users.find_one({"_id": ObjectId(session["user_id"])})
