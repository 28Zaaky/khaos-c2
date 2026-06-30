"""
GET  /agents           — list all agents
GET  /agents/{id}      — single agent details
PATCH /agents/{id}     — update mutable fields (tags)
DELETE /agents/{id}    — mark agent inactive (does not kill it)
POST /agents/killall   — queue kill task for all active agents (admin)
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from routers.auth import verify_token, verify_admin
from models.agent import Agent
from database import get_db

router = APIRouter(prefix="/agents", tags=["agents"])


class PatchAgentRequest(BaseModel):
    tags: Optional[str] = None


@router.get("")
async def list_agents(
    db:   Session = Depends(get_db),
    _user: str    = Depends(verify_token),
):
    agents = db.query(Agent).order_by(Agent.last_seen.desc()).all()
    return [a.to_dict() for a in agents]


@router.get("/graph")
async def get_graph(
    db:    Session = Depends(get_db),
    _user: str     = Depends(verify_token),
):
    agents = db.query(Agent).all()
    return {
        "nodes": [a.to_dict() for a in agents],
        "edges": [{"source": a.agent_id, "target": a.parent_id}
                  for a in agents if a.parent_id],
    }


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    db:       Session = Depends(get_db),
    _user:    str     = Depends(verify_token),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent.to_dict()


@router.patch("/{agent_id}")
async def patch_agent(
    agent_id: str,
    body:     PatchAgentRequest,
    db:       Session = Depends(get_db),
    _user:    str     = Depends(verify_token),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if body.tags is not None:
        agent.tags = body.tags
    db.commit()
    db.refresh(agent)
    return agent.to_dict()


@router.post("/killall")
async def kill_all_agents(
    db:     Session = Depends(get_db),
    _admin: str     = Depends(verify_admin),
):
    """Queue a self-kill task for every active agent with a completed handshake."""
    import uuid as _uuid
    from models.task import Task

    active = db.query(Agent).filter(
        Agent.is_active == True, Agent.handshake_done == True  # noqa: E712
    ).all()

    count = 0
    for a in active:
        task = Task(
            task_id  = str(_uuid.uuid4()),
            agent_id = a.agent_id,
            cmd      = "kill",
            args     = "self",
            status   = "pending",
        )
        a.is_active = False
        db.add(task)
        count += 1

    db.commit()
    return {"killed": count}


@router.delete("/{agent_id}")
async def remove_agent(
    agent_id: str,
    db:       Session = Depends(get_db),
    _user:    str     = Depends(verify_token),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.is_active = False
    db.commit()
    return {"status": "deactivated", "agent_id": agent_id}
