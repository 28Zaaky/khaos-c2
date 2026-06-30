from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import mapped_column, Mapped
from models.agent import Base


class Task(Base):
    __tablename__ = "tasks"

    task_id:    Mapped[str]      = mapped_column(String(64), primary_key=True)
    agent_id:   Mapped[str]      = mapped_column(String(16), index=True)
    cmd:        Mapped[str]      = mapped_column(String(32),  default="")
    args:       Mapped[str]      = mapped_column(Text,        default="")
    data_b64:   Mapped[str]      = mapped_column(Text,        default="")  # for upload
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    sent_at:    Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    acked_at:   Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # "pending" | "sent" | "acked" | "error"
    status:     Mapped[str]      = mapped_column(String(16), default="pending")
    output:     Mapped[str]      = mapped_column(Text,        default="")

    def to_dict(self) -> dict:
        return {
            "task_id":    self.task_id,
            "agent_id":   self.agent_id,
            "cmd":        self.cmd,
            "args":       self.args,
            "status":     self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "acked_at":   self.acked_at.isoformat()   if self.acked_at   else None,
            "output":     self.output,
        }

    def to_wire(self) -> dict:
        """JSON payload sent to the agent (before encryption)."""
        d = {
            "t":   "t",
            "tid": self.task_id,
            "c":   self.cmd,
            "a":   self.args,
        }
        if self.data_b64:
            d["d"] = self.data_b64
        return d
