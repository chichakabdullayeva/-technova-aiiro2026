"""Jurnal API — Logging & SIEM Routes"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from fastapi import APIRouter, Query
from services.logging.database import KiberDatabase

router = APIRouter(prefix="/api", tags=["logs"])
db = KiberDatabase()

@router.get("/logs")
async def get_logs(event_type: str = None, phase: str = None, severity: str = None, search: str = None, limit: int = Query(100), offset: int = Query(0)):
    logs = db.query_logs(event_type=event_type, phase=phase, severity=severity, search=search, limit=limit, offset=offset)
    return {"logs": logs, "count": len(logs)}

@router.get("/logs/stats")
async def log_stats():
    return db.get_stats()
