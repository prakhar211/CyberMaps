from typing import Generator, Optional
from fastapi import Depends, Header
from sqlalchemy.orm import Session
from database import SessionLocal
from core.repository import AlertRepository, SqliteAlertRepository, InMemoryAlertRepository, RedisAlertRepository
import os

# Redis client singleton (lazy initialized)
_redis_client = None

def get_redis_client():
    """Get or create Redis client singleton."""
    global _redis_client
    redis_url = os.getenv("REDIS_URL")
    
    if not redis_url:
        return None
    
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(redis_url, decode_responses=True)
            # Test connection
            _redis_client.ping()
            print(f"DEBUG: Redis connected successfully")
        except Exception as e:
            print(f"DEBUG: Redis connection failed: {e}")
            return None
    
    return _redis_client

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
        # Try Redis first (for production multi-worker environments)
        redis_client = get_redis_client()
        if redis_client:
            print(f"DEBUG: Using RedisAlertRepository")
            return RedisAlertRepository(redis_client, session_id=effective_session_id)
        
        # Fall back to InMemory (works for single-worker or local dev)
        print(f"DEBUG: Using InMemoryAlertRepository (no Redis)")
        return InMemoryAlertRepository(session_id=effective_session_id)
    
    return SqliteAlertRepository(db)
