"""
POST   /api/creds           — save a credential
GET    /api/creds           — list creds (optional ?agent_id=)
DELETE /api/creds/{id}      — delete a credential
"""
from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from routers.auth import verify_token
from models.cred import Cred
from database import get_db

router = APIRouter(tags=["creds"])


class CredRequest(BaseModel):
    agent_id:  str = ""
    cred_type: str = "cleartext"   # cleartext | hash | token | kerberos
    username:  str
    secret:    str = ""
    host:      str = ""
    note:      str = ""


@router.post("/creds")
async def create_cred(
    body: CredRequest,
    db:   Session = Depends(get_db),
    _:    str     = Depends(verify_token),
):
    cred = Cred(
        cred_id     = str(uuid.uuid4()),
        agent_id    = body.agent_id,
        cred_type   = body.cred_type,
        username    = body.username,
        secret      = body.secret,
        host        = body.host,
        note        = body.note,
        captured_at = datetime.utcnow(),
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred.to_dict()


@router.get("/creds")
async def list_creds(
    agent_id: Optional[str] = None,
    db:       Session       = Depends(get_db),
    _:        str           = Depends(verify_token),
):
    q = db.query(Cred).order_by(Cred.captured_at.desc())
    if agent_id:
        q = q.filter(Cred.agent_id == agent_id)
    return [c.to_dict() for c in q.all()]


@router.delete("/creds/{cred_id}")
async def delete_cred(
    cred_id: str,
    db:      Session = Depends(get_db),
    _:       str     = Depends(verify_token),
):
    cred = db.get(Cred, cred_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    db.delete(cred)
    db.commit()
    return {"status": "deleted", "cred_id": cred_id}
