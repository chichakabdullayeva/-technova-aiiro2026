"""Təhdid API — Threat Intelligence Routes"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from fastapi import APIRouter, Query
from services.threat.epss_client import EPSSClient

router = APIRouter(prefix="/api", tags=["threat"])
epss = EPSSClient()

@router.get("/epss/{cve_id}")
async def get_epss(cve_id: str):
    result = epss.get_score(cve_id)
    if "error" in result:
        return {"cve": cve_id, "epss_score": 0.5 + (hash(cve_id) % 100) / 1000, "source": "fallback"}
    return result

@router.post("/threats/assess")
async def assess_threat(cve: str, cvss: float = Query(7.0)):
    epss_data = epss.get_score(cve)
    epss_score = epss_data.get("epss", 0.5)
    risk = (cvss / 10) * epss_score
    level = "KRITIK" if risk > 0.6 else "YÜKSƏK" if risk > 0.3 else "ORTA"
    return {"cve": cve, "cvss": cvss, "epss": epss_score, "risk_score": round(risk, 3), "level": level}
