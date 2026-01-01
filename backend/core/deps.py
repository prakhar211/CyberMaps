from typing import Generator
from fastapi import Depends
from sqlalchemy.orm import Session
from database import SessionLocal
from core.repository import AlertRepository, SqliteAlertRepository, InMemoryAlertRepository
import os

# Global instance for InMemory implementation to persist data across requests (but not restarts)
# This is shared among ALL users in the playground (demo limitation accepted for now)
_in_memory_repo = InMemoryAlertRepository()

def get_db() -> Generator:
    # If in playground mode, we might not need DB, but existing dependencies might expect it.
    # We yield a dummy or still yield session if we want mixed usage.
    # For now, keep as is.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_repository(db: Session = Depends(get_db)) -> AlertRepository:
    mode = os.getenv("CYBERMAPS_MODE", "local")
    if mode.lower() == "playground":
        return _in_memory_repo
    return SqliteAlertRepository(db)
