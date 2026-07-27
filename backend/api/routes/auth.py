from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.services.auth_service import authenticate_user, create_session, create_user

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=4)


@router.post("/register")
def register(request: AuthRequest):
    result = create_user(request.email, request.password)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/login")
def login(request: AuthRequest):
    user = authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session = create_session(str(user["_id"]))
    return {"token": session["token"]}
