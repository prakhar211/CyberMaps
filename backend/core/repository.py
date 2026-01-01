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

class InMemoryAlertRepository(AlertRepository):
    def __init__(self):
        # In a real per-request scenario, this might need to be context-var based or session-based.
        # For now, it's a global in-memory store for the application instance (shared by all users if singleton).
        # CAUTION: This means shared state for the 'Playground' if valid for all users.
        # To make it truly per-session, we'd need dependency injection with session handling.
        # For the prototype roadmap, we proceed with simple list, but note the limitation.
        self._alerts = []
        self._investigations = []

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
        self._alerts.append(alert_obj)
        return alert_obj

    def get_alerts(self, time_filter: Optional[str] = None) -> List[Any]:
        # Simple implementation ignoring efficient time filtering for now
        # Just return sorted list
        return sorted(self._alerts, key=lambda x: x.created_at, reverse=True)

    def get_alert_by_id(self, alert_id: str) -> Optional[Any]:
        for a in self._alerts:
            if a.id == alert_id:
                return a
        return None
        
    def get_alerts_by_ids(self, alert_ids: List[str]) -> List[Any]:
        return [a for a in self._alerts if a.id in alert_ids]

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
        self._investigations.append(new_inv)
        return new_inv

    def get_investigations(self) -> List[Any]:
        return self._investigations

    def get_investigation_by_id(self, inv_id: str) -> Optional[Any]:
        for inv in self._investigations:
            if inv.id == inv_id:
                return inv
        return None

    def delete_investigation(self, inv_id: str) -> None:
        self._investigations = [i for i in self._investigations if i.id != inv_id]

    def update_investigation(self, inv_id: str, alert_ids: Optional[List[str]] = None, graph: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        inv = self.get_investigation_by_id(inv_id)
        if inv:
            if alert_ids is not None:
                inv.alert_ids = alert_ids
            if graph is not None:
                inv.graph = graph
        return inv
