import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.agent import Base


class License(Base):
    __tablename__ = "licenses"

    key:             Mapped[str]            = mapped_column(String(64),  primary_key=True)
    label:           Mapped[str]            = mapped_column(String(256), default="")
    is_active:       Mapped[bool]           = mapped_column(Boolean,     default=True)
    created_at:      Mapped[datetime]       = mapped_column(DateTime,    default=datetime.utcnow)
    expires_at:      Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, default=None)
    build_count:     Mapped[int]            = mapped_column(Integer,     default=0)
    max_builds:      Mapped[Optional[int]]  = mapped_column(Integer,     nullable=True, default=None)
    # per-license mTLS client cert (PFX, base64) — unique per tenant, signed by operator CA
    cert_pfx_b64:   Mapped[Optional[str]]  = mapped_column(Text,         nullable=True, default=None)
    # audit trail
    last_build_uuid: Mapped[Optional[str]]  = mapped_column(String(36),  nullable=True, default=None)
    last_build_at:   Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, default=None)
    last_feat_flags: Mapped[Optional[str]]  = mapped_column(Text,         nullable=True, default=None)
    last_built_by:   Mapped[Optional[str]]  = mapped_column(String(64),   nullable=True, default=None)

    @staticmethod
    def generate() -> str:
        raw = secrets.token_hex(8).upper()
        return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"

    def is_valid(self) -> tuple[bool, str]:
        if not self.is_active:
            return False, "license revoked"
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False, "license expired"
        if self.max_builds is not None and self.build_count >= self.max_builds:
            return False, "build limit reached"
        return True, ""
