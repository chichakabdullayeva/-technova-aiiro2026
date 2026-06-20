"""Kəşfiyyat API — Network Discovery Routes"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from fastapi import APIRouter, Query, BackgroundTasks
from services.discovery.scanner import NetworkScanner
from services.logging.database import KiberDatabase

router = APIRouter(prefix="/api", tags=["discovery"])
db = KiberDatabase()

@router.get("/assets")
async def get_assets(ip: str = None, port: int = None, vendor: str = None):
    scanner = NetworkScanner(db=db)
    if ip:
        return db.query_assets(ips=ip, ports=port, vendor=vendor)
    return db.query_assets()

@router.post("/scan/start")
async def start_scan(subnet: str = Query("10.10.40.0/24")):
    scanner = NetworkScanner(db=db)
    if scanner.available:
        result = scanner.scan_subnet(subnet)
        return {"status": "completed", "data": result, "mode": "real"}
    return {"status": "fallback", "data": scanner._generate_fallback_assets(subnet), "mode": "simulated"}

@router.get("/scan/status")
async def scan_status():
    return {"status": "idle", "message": "Scanner hazırdır"}
