"""Müdafiə API — Defense & SOAR Routes"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from fastapi import APIRouter, Query
from services.defense.soar_engine import SOAREngine
from services.logging.database import KiberDatabase

router = APIRouter(prefix="/api", tags=["defense"])
soar = SOAREngine()
db = KiberDatabase()

@router.post("/rules/generate")
async def generate_rules(cve: str = "CVE-2021-36260", cvss: float = Query(9.8), port: int = Query(554), service: str = "rtsp"):
    threat = {"cve": cve, "cvss": cvss, "port": port, "service": service}
    rules = soar.generate_rules_for_threat(threat)
    return {"rules": rules, "count": len(rules)}

@router.get("/rules")
async def get_rules(sid: int = None, rule_type: str = None, status: str = None):
    return db.query_rules(sid=sid, rule_type=rule_type, status=status)

@router.post("/rules/deploy/{rule_id}")
async def deploy_rule(rule_id: str):
    result = soar.deploy_rule(rule_id)
    return {"status": "deployed" if result else "failed", "rule_id": rule_id}
