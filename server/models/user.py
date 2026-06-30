import hashlib, secrets
from sqlalchemy import String, Boolean
from sqlalchemy.orm import mapped_column, Mapped
from models.agent import Base


class User(Base):
    __tablename__ = "users"

    username:      Mapped[str]  = mapped_column(String(64),  primary_key=True)
    password_hash: Mapped[str]  = mapped_column(String(256), default="")
    role:          Mapped[str]  = mapped_column(String(16),  default="operator")
    is_active:     Mapped[bool] = mapped_column(Boolean,     default=True)

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return f"{salt}:{dk.hex()}"

    @staticmethod
    def verify_password(password: str, stored: str) -> bool:
        try:
            salt, dk_hex = stored.split(":", 1)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
            return secrets.compare_digest(dk.hex(), dk_hex)
        except Exception:
            return False
