from typing import Generator, Optional
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
    x_session_id: str = Header(default=None, alias="X-Session-ID"),
    session_id: Optional[str] = None # Support for query param fallback
) -> AlertRepository:
    mode = os.getenv("CYBERMAPS_MODE", "local")
    
    # Priority: Header > Query Param > "default"
    effective_session_id = x_session_id or session_id or "default"
    
    print(f"DEBUG: deps.py - Mode: {mode}, Session ID: {effective_session_id}")
    if mode.lower() == "playground":
        # Return a repository scoped to this session ID
        return InMemoryAlertRepository(session_id=effective_session_id)
    return SqliteAlertRepository(db)
