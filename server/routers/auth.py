"""
JWT authentication for the operator UI.
POST   /auth/login          → access_token
GET    /auth/me             → {username, role}
GET    /auth/users          → list (admin only)
POST   /auth/users          → create user (admin only)
DELETE /auth/users/{uname}  → delete user (admin only)
"""
import os
from datetime import datetime, timedelta

import jwt
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session

import database
from models.user import User

router  = APIRouter(prefix="/auth", tags=["auth"])
bearer  = HTTPBearer()

_SECRET: str = ""
_ALGO        = "HS256"
_TOKEN_TTL_H = 12


def _get_secret() -> str:
    global _SECRET
    if not _SECRET:
        _SECRET = os.environ.get("KHAOS_JWT_SECRET",
                  os.environ.get("LEGITC2_JWT_SECRET", "change-me-in-production"))
    return _SECRET


# ---- Pydantic models ----

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role:     str = "operator"


# ---- Token helpers ----

def create_token(username: str, role: str = "operator") -> str:
    payload = {
        "sub":  username,
        "role": role,
        "iat":  datetime.utcnow(),
        "exp":  datetime.utcnow() + timedelta(hours=_TOKEN_TTL_H),
    }
    return jwt.encode(payload, _get_secret(), algorithm=_ALGO)


def _decode(raw: str) -> dict:
    try:
        return jwt.decode(raw, _get_secret(), algorithms=[_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    """Returns username. Used by existing agent/task routers unchanged."""
    return _decode(credentials.credentials)["sub"]


def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    """Returns username, 403 if role != admin."""
    payload = _decode(credentials.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload["sub"]


def verify_token_str(token: str) -> str:
    """JWT validation for WebSocket connections (token passed as query param)."""
    try:
        payload = jwt.decode(token, _get_secret(), algorithms=[_ALGO])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.PyJWTError:
        raise ValueError("Invalid token")


# ---- Routes ----

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: Session = Depends(database.get_db)):
    user = db.get(User, body.username)
    if user and user.is_active and User.verify_password(body.password, user.password_hash):
        return TokenResponse(access_token=create_token(user.username, user.role))

    # Fallback to env-var credentials (only if no users exist in DB)
    if db.query(User).count() == 0:
        env_user = os.environ.get("LEGITC2_OPERATOR_USER", "operator")
        env_pass = os.environ.get("LEGITC2_OPERATOR_PASS", "changeme")
        if body.username == env_user and body.password == env_pass:
            return TokenResponse(access_token=create_token(env_user, "admin"))

    raise HTTPException(status_code=401, detail="Invalid credentials")


@router.get("/me")
async def me(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    payload = _decode(credentials.credentials)
    return {"username": payload["sub"], "role": payload.get("role", "operator")}


@router.get("/users")
async def list_users(
    _admin: str = Depends(verify_admin),
    db: Session = Depends(database.get_db),
):
    return [
        {"username": u.username, "role": u.role, "is_active": u.is_active}
        for u in db.query(User).order_by(User.username).all()
    ]


@router.post("/users", status_code=201)
async def create_user(
    body: CreateUserRequest,
    _admin: str = Depends(verify_admin),
    db: Session = Depends(database.get_db),
):
    if body.role not in ("admin", "operator"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'operator'")
    if db.get(User, body.username):
        raise HTTPException(status_code=409, detail="User already exists")
    user = User(
        username=body.username,
        password_hash=User.hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    return {"username": user.username, "role": user.role}


@router.delete("/users/{username}", status_code=204)
async def delete_user(
    username: str,
    admin: str = Depends(verify_admin),
    db: Session = Depends(database.get_db),
):
    if username == admin:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    user = db.get(User, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
