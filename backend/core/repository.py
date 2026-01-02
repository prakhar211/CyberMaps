from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
import uuid
from datetime import datetime

# Import models from parent (assuming we are running from backend package context or imports work)
# If this fails, we might need to adjust imports.
import models


# Since schemas were defined in main.py, we should ideally move them.
# But for now, let's define abstract types as simple Pydantic models or Dicts to avoid circular imports 
# if we haven't moved schemas yet.
# We will use the existing SQLAlchemy models for SqliteRepository.

class AlertRepository(ABC):
    @abstractmethod
    def create_alert(self, alert_data: Dict[str, Any]) -> Any:
        pass

    @abstractmethod
    def get_alerts(self, time_filter: Optional[str] = None) -> List[Any]:
        pass

    @abstractmethod
    def get_alert_by_id(self, alert_id: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    def get_alerts_by_ids(self, alert_ids: List[str]) -> List[Any]:
        pass

    # Investigation methods
    @abstractmethod
    def create_investigation(self, data: Dict[str, Any]) -> Any:
        pass
    
    @abstractmethod
    def get_investigations(self) -> List[Any]:
        pass
    
    @abstractmethod
    def get_investigation_by_id(self, inv_id: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    def delete_investigation(self, inv_id: str) -> None:
        pass
        
    @abstractmethod
    def update_investigation(self, inv_id: str, alert_ids: Optional[List[str]] = None, graph: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        pass

class SqliteAlertRepository(AlertRepository):
    def __init__(self, db: Session):
        self.db = db

    def create_alert(self, alert_data: Dict[str, Any]) -> Any:
        db_alert = models.AlertModel(
            id=alert_data.get("id") or str(uuid.uuid4()),
            name=alert_data["name"],
            severity=alert_data["severity"],
            tactic=alert_data["tactic"],
            technique=alert_data.get("technique"),
            description=alert_data.get("description"),
            raw_data=alert_data.get("raw_data"),
            created_at=datetime.utcnow() # Always set creation time
        )
        self.db.add(db_alert)
        self.db.commit()
        self.db.refresh(db_alert)
        return db_alert

    def get_alerts(self, time_filter: Optional[str] = None) -> List[Any]:
        from datetime import timedelta
        query = self.db.query(models.AlertModel)
        
        if time_filter and time_filter != "all":
            now = datetime.utcnow()
            time_delta_map = {
                "30m": timedelta(minutes=30),
                "1h": timedelta(hours=1),
                "24h": timedelta(hours=24),
                "7d": timedelta(days=7),
            }
            if time_filter in time_delta_map:
                cutoff_time = now - time_delta_map[time_filter]
                query = query.filter(models.AlertModel.created_at >= cutoff_time)
        
        return query.order_by(models.AlertModel.created_at.desc()).all()

    def get_alert_by_id(self, alert_id: str) -> Optional[Any]:
        return self.db.query(models.AlertModel).filter(models.AlertModel.id == alert_id).first()
        
    def get_alerts_by_ids(self, alert_ids: List[str]) -> List[Any]:
        return self.db.query(models.AlertModel).filter(models.AlertModel.id.in_(alert_ids)).all()

    def create_investigation(self, data: Dict[str, Any]) -> Any:
        new_inv = models.InvestigationModel(
            id=data.get("id") or str(uuid.uuid4()),
            name=data["name"],
            created_at=datetime.utcnow(),
            alert_ids=data["alert_ids"],
            graph=data["graph"]
        )
        self.db.add(new_inv)
        self.db.commit()
        self.db.refresh(new_inv)
        return new_inv

    def get_investigations(self) -> List[Any]:
        return self.db.query(models.InvestigationModel).all()

    def get_investigation_by_id(self, inv_id: str) -> Optional[Any]:
        return self.db.query(models.InvestigationModel).filter(models.InvestigationModel.id == inv_id).first()

    def delete_investigation(self, inv_id: str) -> None:
        inv = self.get_investigation_by_id(inv_id)
        if inv:
            self.db.delete(inv)
            self.db.commit()

    def update_investigation(self, inv_id: str, alert_ids: Optional[List[str]] = None, graph: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        inv = self.get_investigation_by_id(inv_id)
        if inv:
            if alert_ids is not None:
                inv.alert_ids = alert_ids
            if graph is not None:
                inv.graph = graph
            self.db.commit()
            self.db.refresh(inv)
        return inv

# Global store for in-memory data, keyed by session_id
# Structure: { session_id: { "alerts": [], "investigations": [] } }
GLOBAL_STORE = {}

class InMemoryAlertRepository(AlertRepository):
    def __init__(self, session_id: str = "default"):
        self.session_id = session_id
        if self.session_id not in GLOBAL_STORE:
            GLOBAL_STORE[self.session_id] = {"alerts": [], "investigations": []}
            
    @property
    def alerts(self):
        return GLOBAL_STORE[self.session_id]["alerts"]
        
    @property
    def investigations(self):
        return GLOBAL_STORE[self.session_id]["investigations"]

    def create_alert(self, alert_data: Dict[str, Any]) -> Any:
        # Simulate an object with attribute access to mimic ORM model
        class MockAlert:
            def __init__(self, **entries):
                self.__dict__.update(entries)
                
        alert_obj = MockAlert(
            id=alert_data.get("id") or str(uuid.uuid4()),
            name=alert_data["name"],
            severity=alert_data["severity"],
            tactic=alert_data["tactic"],
            technique=alert_data.get("technique"),
            description=alert_data.get("description"),
            raw_data=alert_data.get("raw_data"),
            created_at=datetime.utcnow()
        )
        self.alerts.append(alert_obj)
        return alert_obj

    def get_alerts(self, time_filter: Optional[str] = None) -> List[Any]:
        # Simple implementation ignoring efficient time filtering for now
        # Just return sorted list
        return sorted(self.alerts, key=lambda x: x.created_at, reverse=True)

    def get_alert_by_id(self, alert_id: str) -> Optional[Any]:
        for a in self.alerts:
            if a.id == alert_id:
                return a
        return None
        
    def get_alerts_by_ids(self, alert_ids: List[str]) -> List[Any]:
        return [a for a in self.alerts if a.id in alert_ids]

    def create_investigation(self, data: Dict[str, Any]) -> Any:
        class MockInvestigation:
            def __init__(self, **entries):
                self.__dict__.update(entries)
        
        new_inv = MockInvestigation(
            id=data.get("id") or str(uuid.uuid4()),
            name=data["name"],
            created_at=datetime.utcnow(),
            alert_ids=data["alert_ids"],
            graph=data["graph"]
        )
        self.investigations.append(new_inv)
        return new_inv

    def get_investigations(self) -> List[Any]:
        return self.investigations

    def get_investigation_by_id(self, inv_id: str) -> Optional[Any]:
        for inv in self.investigations:
            if inv.id == inv_id:
                return inv
        return None

    def delete_investigation(self, inv_id: str) -> None:
        # Filter existing list in-place assignment logic effectively
        current_invs = self.investigations
        updated_invs = [i for i in current_invs if i.id != inv_id]
        GLOBAL_STORE[self.session_id]["investigations"] = updated_invs

    def update_investigation(self, inv_id: str, alert_ids: Optional[List[str]] = None, graph: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        inv = self.get_investigation_by_id(inv_id)
        if inv:
            if alert_ids is not None:
                inv.alert_ids = alert_ids
            if graph is not None:
                inv.graph = graph
        return inv


# --- Redis-backed Repository for Production Playground ---

class RedisAlertRepository(AlertRepository):
    """
    Redis-backed repository for session-scoped storage.
    Solves multi-worker isolation by using shared Redis instance.
    """
    
    def __init__(self, redis_client, session_id: str = "default"):
        self.redis = redis_client
        self.session_id = session_id
        self.alerts_key = f"cybermaps:{session_id}:alerts"
        self.investigations_key = f"cybermaps:{session_id}:investigations"
        # Set TTL for session data (24 hours)
        self.ttl = 86400
    
    def _serialize(self, obj: Any) -> str:
        """Serialize object to JSON string."""
        import json
        if hasattr(obj, '__dict__'):
            data = {k: v for k, v in obj.__dict__.items() if not k.startswith('_')}
            # Handle datetime
            if 'created_at' in data and hasattr(data['created_at'], 'isoformat'):
                data['created_at'] = data['created_at'].isoformat()
            return json.dumps(data)
        return json.dumps(obj)
    
    def _deserialize_alert(self, json_str: str) -> Any:
        """Deserialize JSON to alert-like object."""
        import json
        from datetime import datetime as dt
        
        class RedisAlert:
            def __init__(self, **entries):
                self.__dict__.update(entries)
        
        data = json.loads(json_str)
        # Parse datetime
        if 'created_at' in data and data['created_at']:
            try:
                data['created_at'] = dt.fromisoformat(data['created_at'])
            except:
                data['created_at'] = dt.utcnow()
        return RedisAlert(**data)
    
    def _deserialize_investigation(self, json_str: str) -> Any:
        """Deserialize JSON to investigation-like object."""
        import json
        from datetime import datetime as dt
        
        class RedisInvestigation:
            def __init__(self, **entries):
                self.__dict__.update(entries)
        
        data = json.loads(json_str)
        if 'created_at' in data and data['created_at']:
            try:
                data['created_at'] = dt.fromisoformat(data['created_at'])
            except:
                data['created_at'] = dt.utcnow()
        return RedisInvestigation(**data)

    def create_alert(self, alert_data: Dict[str, Any]) -> Any:
        alert_id = alert_data.get("id") or str(uuid.uuid4())
        
        class RedisAlert:
            def __init__(self, **entries):
                self.__dict__.update(entries)
        
        alert_obj = RedisAlert(
            id=alert_id,
            name=alert_data["name"],
            severity=alert_data["severity"],
            tactic=alert_data["tactic"],
            technique=alert_data.get("technique"),
            description=alert_data.get("description"),
            raw_data=alert_data.get("raw_data"),
            created_at=datetime.utcnow()
        )
        
        # Store in Redis hash
        self.redis.hset(self.alerts_key, alert_id, self._serialize(alert_obj))
        self.redis.expire(self.alerts_key, self.ttl)
        return alert_obj

    def get_alerts(self, time_filter: Optional[str] = None) -> List[Any]:
        all_alerts_raw = self.redis.hvals(self.alerts_key)
        alerts = [self._deserialize_alert(a) for a in all_alerts_raw]
        # Sort by created_at descending
        return sorted(alerts, key=lambda x: x.created_at if x.created_at else datetime.min, reverse=True)

    def get_alert_by_id(self, alert_id: str) -> Optional[Any]:
        raw = self.redis.hget(self.alerts_key, alert_id)
        if raw:
            return self._deserialize_alert(raw)
        return None
        
    def get_alerts_by_ids(self, alert_ids: List[str]) -> List[Any]:
        results = []
        for aid in alert_ids:
            raw = self.redis.hget(self.alerts_key, aid)
            if raw:
                results.append(self._deserialize_alert(raw))
        return results

    def create_investigation(self, data: Dict[str, Any]) -> Any:
        inv_id = data.get("id") or str(uuid.uuid4())
        
        class RedisInvestigation:
            def __init__(self, **entries):
                self.__dict__.update(entries)
        
        new_inv = RedisInvestigation(
            id=inv_id,
            name=data["name"],
            created_at=datetime.utcnow(),
            alert_ids=data["alert_ids"],
            graph=data["graph"]
        )
        
        self.redis.hset(self.investigations_key, inv_id, self._serialize(new_inv))
        self.redis.expire(self.investigations_key, self.ttl)
        return new_inv

    def get_investigations(self) -> List[Any]:
        all_inv_raw = self.redis.hvals(self.investigations_key)
        return [self._deserialize_investigation(i) for i in all_inv_raw]

    def get_investigation_by_id(self, inv_id: str) -> Optional[Any]:
        raw = self.redis.hget(self.investigations_key, inv_id)
        if raw:
            return self._deserialize_investigation(raw)
        return None

    def delete_investigation(self, inv_id: str) -> None:
        self.redis.hdel(self.investigations_key, inv_id)

    def update_investigation(self, inv_id: str, alert_ids: Optional[List[str]] = None, graph: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        inv = self.get_investigation_by_id(inv_id)
        if inv:
            if alert_ids is not None:
                inv.alert_ids = alert_ids
            if graph is not None:
                inv.graph = graph
            # Re-save
            self.redis.hset(self.investigations_key, inv_id, self._serialize(inv))
            self.redis.expire(self.investigations_key, self.ttl)
        return inv
