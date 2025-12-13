from sqlalchemy import Column, String, DateTime, JSON
from database import Base
from datetime import datetime

class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    name = Column(String)
    severity = Column(String)
    tactic = Column(String)
    technique = Column(String, nullable=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)  # Add timestamp
    raw_data = Column(JSON, nullable=True)  # Store complete CloudTrail event/raw log

class InvestigationModel(Base):
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, index=True)
    name = Column(String)
    created_at = Column(DateTime)
    alert_ids = Column(JSON) # Storing list of IDs as JSON
    graph = Column(JSON)     # Storing the graph dict as JSON
