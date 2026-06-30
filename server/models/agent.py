from datetime import datetime
from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"

    agent_id:        Mapped[str]      = mapped_column(String(16), primary_key=True)
    hostname:        Mapped[str]      = mapped_column(String(256), default="")
    username:        Mapped[str]      = mapped_column(String(128), default="")
    os_info:         Mapped[str]      = mapped_column(String(128), default="")
    privileges:      Mapped[str]      = mapped_column(String(32),  default="")
    first_seen:      Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen:       Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Crypto: session key + server keypair (hex-encoded)
    session_key:     Mapped[str]      = mapped_column(String(64),  default="")
    server_pubkey:   Mapped[str]      = mapped_column(String(64),  default="")
    server_privkey:  Mapped[str]      = mapped_column(String(64),  default="")
    handshake_done:  Mapped[bool]     = mapped_column(default=False)

    # Status
    is_active:       Mapped[bool]     = mapped_column(default=True)
    pending_task_id: Mapped[str]      = mapped_column(String(64),  default="")
    tags:            Mapped[str]      = mapped_column(Text,         default="")
    parent_id:       Mapped[str]      = mapped_column(String(16),  default="", nullable=True)
    ip:              Mapped[str]      = mapped_column(String(64),   default="", nullable=True)
    auto_enum_done:  Mapped[bool]     = mapped_column(default=False)

    def to_dict(self) -> dict:
        return {
            "agent_id":    self.agent_id,
            "hostname":    self.hostname,
            "username":    self.username,
            "os_info":     self.os_info,
            "privileges":  self.privileges,
            "first_seen":  self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":   self.last_seen.isoformat()  if self.last_seen  else None,
            "is_active":   self.is_active,
            "handshake":   self.handshake_done,
            "tags":        self.tags or "",
            "parent_id":   self.parent_id or "",
            "ip":          self.ip or "",
        }
