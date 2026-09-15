from sqlalchemy import Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from models.agent import Base


class OperatorCA(Base):
    __tablename__ = "operator_ca"

    id:           Mapped[int] = mapped_column(Integer, primary_key=True)  # singleton, always 1
    ca_cert_pem:  Mapped[str] = mapped_column(Text)
    ca_key_pem:   Mapped[str] = mapped_column(Text)
    srv_cert_pem: Mapped[str] = mapped_column(Text)
    srv_key_pem:  Mapped[str] = mapped_column(Text)
