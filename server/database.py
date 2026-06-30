"""
Database session helpers — populated by main.py at startup.
Routers import get_db from here so they stay decoupled from engine setup.
"""
from typing import Generator
from sqlalchemy.orm import Session


# Set by main.py after engine creation
SessionLocal = None


def get_db() -> Generator[Session, None, None]:
    if SessionLocal is None:
        raise RuntimeError("get_db not initialized — is main.py loaded?")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
