from __future__ import annotations
from datetime import datetime
from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import mapped_column, Mapped
from models.agent import Base


class Cred(Base):
    __tablename__ = "creds"

    cred_id:     Mapped[str]      = mapped_column(String(64),  primary_key=True)
    agent_id:    Mapped[str]      = mapped_column(String(16),  index=True, default="")
    cred_type:   Mapped[str]      = mapped_column(String(32),  default="cleartext")
    # cred_type values: cleartext | hash | token | kerberos
    username:    Mapped[str]      = mapped_column(String(256), default="")
    secret:      Mapped[str]      = mapped_column(Text,        default="")
    host:        Mapped[str]      = mapped_column(String(256), default="")
    note:        Mapped[str]      = mapped_column(Text,        default="")
    captured_at: Mapped[datetime] = mapped_column(DateTime,    default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "cred_id":     self.cred_id,
            "agent_id":    self.agent_id,
            "cred_type":   self.cred_type,
            "username":    self.username,
            "secret":      self.secret,
            "host":        self.host,
            "note":        self.note,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
        }
