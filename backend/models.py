"""Milli Kiber-DNT — Pydantic Models"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class ScanRequest(BaseModel):
    subnet: str = "10.10.40.0/24"
    arguments: Optional[str] = "-p 80,443,554 -sV --script=banner --host-timeout 30s"
    incident_id: Optional[str] = None


class EPSSRequest(BaseModel):
    cve_id: str


class BASRequest(BaseModel):
    target_ip: str
    ports: Optional[List[int]] = None
    incident_id: Optional[str] = None


class SimulateRequest(BaseModel):
    scenario: str = "hikvision"
    speed: str = "normal"


class LogQuery(BaseModel):
    incident_id: Optional[str] = None
    event_type: Optional[str] = None
    phase: Optional[str] = None
    severity: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0


class AssetQuery(BaseModel):
    ip: Optional[str] = None
    port: Optional[str] = None
    vendor: Optional[str] = None
    search: Optional[str] = None


class RuleQuery(BaseModel):
    sid: Optional[int] = None
    rule_type: Optional[str] = None
    status: Optional[str] = None
