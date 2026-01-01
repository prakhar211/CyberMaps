from fastapi import Depends, Header
from sqlalchemy.orm import Session
from database import SessionLocal
from core.repository import AlertRepository, SqliteAlertRepository, InMemoryAlertRepository
import os

def get_db() -> Generator:
    # If in playground mode, we might not need DB, but existing dependencies might expect it.
    # We yield a dummy or still yield session if we want mixed usage.
    # For now, keep as is.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_repository(
    db: Session = Depends(get_db),
    x_session_id: str = Header(default="default", alias="X-Session-ID")
) -> AlertRepository:
    mode = os.getenv("CYBERMAPS_MODE", "local")
    if mode.lower() == "playground":
        # Return a repository scoped to this session ID
        return InMemoryAlertRepository(session_id=x_session_id)
    return SqliteAlertRepository(db)
