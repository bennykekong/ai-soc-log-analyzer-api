from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

EventType = Literal["failed_login", "network_connection", "firewall_drop", "other"]


class SecurityEvent(BaseModel):
    timestamp: datetime
    event_type: EventType
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = None
    action: Optional[str] = None
    raw: Optional[str] = None


class LogBatch(BaseModel):
    events: list[SecurityEvent]


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    description: str
    evidence: dict


class AnalysisResult(BaseModel):
    total_events: int
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["Low", "Medium", "High", "Critical"]
    findings: list[Finding]
    incident_summary: str
    recommended_actions: list[str]
