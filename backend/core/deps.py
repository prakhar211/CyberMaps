import os
import uuid
from typing import Generator, Optional
from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session
from database import SessionLocal
from core.repository import AlertRepository, SqliteAlertRepository, InMemoryAlertRepository, RedisAlertRepository

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
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_repository(
    request: Request,
    db: Session = Depends(get_db),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    session_id: Optional[str] = None # Support for query param fallback
) -> AlertRepository:
    mode = os.getenv("CYBERMAPS_MODE", "local")
    
    # Debug: Log header keys to see what the proxy is doing
    header_keys = [k.lower() for k in request.headers.keys()]
    
    # Determine the effective session ID
    # 1. Check query parameter first (most reliable as it's never stripped by proxies)
    # 2. Check X-Session-ID header (FastAPI auto-extraction)
    # 3. Check raw headers (manual case-insensitive search)
    # 4. Fallback to "default"
    
    effective_session_id = session_id
    
    if not effective_session_id:
        effective_session_id = x_session_id
        
    if not effective_session_id:
        # Manual search in headers
        effective_session_id = request.headers.get("x-session-id") or \
                               request.headers.get("X-Session-ID") or \
                               request.headers.get("X-Session-Id")
                               
    if not effective_session_id:
        effective_session_id = "default"
    
    # Extra logging to catch the "default" case
    if effective_session_id == "default" and mode.lower() == "playground":
        print(f"DEBUG: Session ID is 'default'. Available header keys: {header_keys}")
    else:
        print(f"DEBUG: deps.py - Mode: {mode}, Session ID: {effective_session_id}")
    
    if mode.lower() == "playground":
        redis_client = get_redis_client()
        if redis_client:
            return RedisAlertRepository(redis_client, session_id=effective_session_id)
        return InMemoryAlertRepository(session_id=effective_session_id)
    
    return SqliteAlertRepository(db)
