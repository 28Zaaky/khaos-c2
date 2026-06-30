from datetime import datetime
from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import mapped_column, Mapped
from models.agent import Base


class Log(Base):
    __tablename__ = "logs"

    id:         Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    agent_id:   Mapped[str]      = mapped_column(String(16), index=True)
    level:      Mapped[str]      = mapped_column(String(16), default="info")  # info|warn|error
    event:      Mapped[str]      = mapped_column(String(64), default="")
    detail:     Mapped[str]      = mapped_column(Text,       default="")
    created_at: Mapped[datetime] = mapped_column(DateTime,   default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "agent_id":   self.agent_id,
            "level":      self.level,
            "event":      self.event,
            "detail":     self.detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
