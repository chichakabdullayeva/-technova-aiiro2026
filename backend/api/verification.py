"""Doğrulama API — BAS & Verification Routes"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from fastapi import APIRouter, Query
from services.verification.bas_engine import BASEngine

router = APIRouter(prefix="/api", tags=["verification"])

@router.post("/bas/simulate")
async def simulate_bas(target_ip: str = Query("10.10.40.12"), target_port: int = Query(80), cve: str = "CVE-2021-36260"):
    bas = BASEngine()
    result = bas.verify_patch_http(target_ip, target_port)
    return {"target": f"{target_ip}:{target_port}", "cve": cve, "result": result}
