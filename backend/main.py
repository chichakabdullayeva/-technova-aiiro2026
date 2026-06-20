"""Milli Kiber-DNT — Main FastAPI Application

Real backend with WebSocket-based real-time communication.
Connects the frontend to real scanning, EPSS API, SOAR, BAS, and LLM.
"""

import asyncio
import json
import uuid
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from config import TARGET_SUBNET, LOG_LEVEL, AUTH_USERNAME, AUTH_PASSWORD, AUTH_SECRET_TOKEN, AUTH_ENABLED
from database import KiberDatabase
from scanner import NetworkScanner
from epss_client import EPSSClient
from soar_engine import SOAREngine
from bas_engine import BASEngine
from llm_reporter import LLMReporter
from websocket_manager import ConnectionManager
from models import (
    ScanRequest, EPSSRequest, BASRequest, SimulateRequest,
    LogQuery, AssetQuery, RuleQuery
)

# ---- Globals ----
db = KiberDatabase()
ws_manager = ConnectionManager()
scanner = NetworkScanner(db=db)
epss_client = EPSSClient(db=db)
soar = SOAREngine(db=db)
bas = BASEngine(db=db)
llm = LLMReporter(db=db)

# ---- Authentication ----
security = HTTPBasic()

def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if not AUTH_ENABLED:
        return {"username": "demo", "role": "viewer"}
    correct_username = secrets.compare_digest(credentials.username, AUTH_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, AUTH_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Yanlış istifadəçi adı və ya şifrə",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"username": credentials.username, "role": "admin"}

def verify_token(authorization: str = Header(default=None)):
    if not AUTH_ENABLED:
        return True
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    # Support both "Bearer <token>" and plain token
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    if not secrets.compare_digest(token, AUTH_SECRET_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid token")
    return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"[Kiber-DNT] Backend started. Nmap: {'✓' if scanner.available else '✗ (fallback)'}")
    print(f"[Kiber-DNT] Ollama LLM: {'✓' if llm.available else '✗ (template mode)'}")
    print(f"[Kiber-DNT] Database: {db.db_path}")
    print(f"[Kiber-DNT] Target subnet: {TARGET_SUBNET}")
    yield
    # Shutdown
    db.close()
    print("[Kiber-DNT] Backend shut down.")


app = FastAPI(
    title="Milli Kiber-DNT Backend API",
    version="1.0.0",
    description="Closed-Loop Cyber Defense Platform — Backend Engine",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===== Auth Endpoints =====

@app.post("/api/auth/login")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    if AUTH_ENABLED:
        verify_auth(credentials)
    return {
        "status": "success",
        "username": credentials.username if AUTH_ENABLED else "demo",
        "token": AUTH_SECRET_TOKEN,
        "message": f"Xoş gəldiniz, {credentials.username if AUTH_ENABLED else 'demo'}!"
    }

@app.get("/api/auth/check")
async def check_auth(user: dict = Depends(verify_auth)):
    return {"status": "authenticated", "user": user}


# ===== REST Endpoints =====

@app.get("/api/status")
async def get_status():
    return {
        "service": "Milli Kiber-DNT",
        "version": "1.0.0",
        "status": "running",
        "nmap_available": scanner.available,
        "llm_available": llm.available,
        "active_websockets": ws_manager.active_connections,
        "db_stats": db.get_stats(),
        "uptime": datetime.utcnow().isoformat()
    }


@app.post("/api/scan")
async def run_scan(req: ScanRequest):
    """Run a real Nmap scan on the target subnet."""
    incident_id = req.incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"

    # Notify frontend
    await ws_manager.broadcast_log(incident_id, "KƏŞF", "SCAN_START",
                                   f"Scanning subnet: {req.subnet} with args: {req.arguments}",
                                   severity="info")

    # Run the scan
    assets = await scanner.scan_async(
        subnet=req.subnet,
        arguments=req.arguments,
        incident_id=incident_id,
        callback=lambda a: asyncio.create_task(ws_manager.broadcast_scan_result(a, incident_id))
    )

    await ws_manager.broadcast_log(incident_id, "KƏŞF", "SCAN_COMPLETE",
                                   f"Scan complete: {len(assets)} assets discovered",
                                   data={"count": len(assets)},
                                   severity="success")

    return {
        "incident_id": incident_id,
        "subnet": req.subnet,
        "assets_found": len(assets),
        "assets": assets,
        "nmap_available": scanner.available
    }


@app.post("/api/epss")
async def get_epss(req: EPSSRequest):
    """Get real EPSS score from FIRST.org API."""
    data = epss_client.get_score(req.cve_id)
    await ws_manager.broadcast_epss(data)
    return data


@app.post("/api/assess")
async def assess_threat(cve_id: str = Query(...), cvss: float = Query(default=0.0)):
    """Full threat assessment combining CVSS + real EPSS."""
    assessment = epss_client.assess_threat_level(cve_id, cvss)
    await ws_manager.broadcast({
        "type": "assessment",
        "event": "THREAT_ASSESSMENT",
        "data": assessment,
        "timestamp": datetime.utcnow().isoformat()
    })
    return assessment


@app.post("/api/soar/generate-rules")
async def generate_rules(
    cve_id: str = Query(...),
    target_subnet: str = Query(default="10.10.40.0/24"),
    port: int = Query(default=554),
    incident_id: str = Query(default=None)
):
    """Generate WAF/IPS rules (autopilot)."""
    inc_id = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"
    rules = soar.generate_autopilot_rules(cve_id, target_subnet, port, inc_id)

    # Broadcast each rule
    for r in rules:
        await ws_manager.broadcast_rule(r)

    return {
        "incident_id": inc_id,
        "rules_generated": len(rules),
        "rules": rules
    }


@app.post("/api/soar/deploy-rule")
async def deploy_rule(sid: int = Query(...)):
    """Deploy a generated rule to the local WAF/IPS."""
    rules = soar.get_all_rules()
    target = next((r for r in rules if r.get("sid") == sid), None)
    if not target:
        raise HTTPException(404, f"Rule sid={sid} not found")
    result = soar.deploy_rule(target)
    await ws_manager.broadcast({
        "type": "rule",
        "event": "RULE_DEPLOYED",
        "data": result
    })
    return result


@app.post("/api/bas/verify")
async def verify_bas(req: BASRequest):
    """Run BAS verification against target."""
    inc_id = req.incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"

    await ws_manager.broadcast_log(inc_id, "BAS", "VERIFICATION_START",
                                   f"BAS verification started against {req.target_ip}",
                                   severity="info")

    result = bas.run_full_bas(req.target_ip, req.ports, inc_id)

    await ws_manager.broadcast_bas(result)
    await ws_manager.broadcast_log(inc_id, "BAS", "VERIFICATION_COMPLETE",
                                   f"BAS complete: {result['overall']}",
                                   data=result, severity="success")

    return result


@app.post("/api/report/generate")
async def generate_report(data: dict):
    """Generate post-mortem report from incident data."""
    report = llm.generate_report(data)
    await ws_manager.broadcast_report(report)
    return report


@app.post("/api/simulate")
async def run_simulation(req: SimulateRequest):
    """Run a full closed-loop simulation against a scenario.
    
    This orchestrates: scan → EPSS → SOAR → BAS → LLM report
    in sequence, broadcasting each phase via WebSocket.
    """
    incident_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    speed_delays = {"slow": 2.0, "normal": 1.0, "fast": 0.3}

    # Load scenario definition
    scenario = _get_scenario(req.scenario)
    if not scenario:
        raise HTTPException(400, f"Unknown scenario: {req.scenario}")

    db.create_incident(incident_id, scenario["cve"], scenario["name"],
                       scenario.get("cvss", 0), scenario.get("epss", 0))

    # Phase 1: Kəşfiyyat
    await ws_manager.broadcast_phase_update(1, "started", incident_id)
    assets = await scanner.scan_async(
        subnet=TARGET_SUBNET,
        incident_id=incident_id
    )
    for a in assets:
        await ws_manager.broadcast_scan_result([a], incident_id)
    await asyncio.sleep(speed_delays[req.speed])
    await ws_manager.broadcast_phase_update(1, "completed", incident_id)

    # Phase 2: AI Qərar
    await ws_manager.broadcast_phase_update(2, "started", incident_id)
    epss_data = epss_client.assess_threat_level(scenario["cve"], scenario.get("cvss", 0))
    await ws_manager.broadcast_epss(epss_data)
    await asyncio.sleep(speed_delays[req.speed])
    await ws_manager.broadcast_phase_update(2, "completed", incident_id)

    # Phase 3: SOAR
    await ws_manager.broadcast_phase_update(3, "started", incident_id)
    rules = soar.generate_autopilot_rules(
        scenario["cve"], TARGET_SUBNET,
        scenario.get("port", 554), incident_id
    )
    for r in rules:
        await ws_manager.broadcast_rule(r)
    await asyncio.sleep(speed_delays[req.speed])
    await ws_manager.broadcast_phase_update(3, "completed", incident_id)

    # Phase 4: BAS
    await ws_manager.broadcast_phase_update(4, "started", incident_id)
    target_ip = assets[0]["ip"] if assets else "10.10.40.12"
    bas_result = bas.run_full_bas(target_ip, [80, 554], incident_id)
    await ws_manager.broadcast_bas(bas_result)
    await asyncio.sleep(speed_delays[req.speed])
    await ws_manager.broadcast_phase_update(4, "completed", incident_id)

    # Phase 5: Report
    await ws_manager.broadcast_phase_update(5, "started", incident_id)
    report_data = {
        "incident_id": incident_id,
        "name": scenario["name"],
        "cve": scenario["cve"],
        "cvss": scenario.get("cvss", 0),
        "epss": epss_data.get("epss", 0),
        "ai_decision": epss_data.get("recommendation", "MONITOR"),
        "confidence": (1 - epss_data.get("epss", 0)) * 100,
        "assets": [a["ip"] for a in assets],
        "rules_count": len(rules),
        "bas_result": bas_result.get("overall", "N/A"),
        "bas_latency": bas_result.get("details", {}).get("80", {}).get("latency_ms", "N/A")
    }
    report = llm.generate_report(report_data)

    if llm.available:
        async for chunk in llm.stream_report_async(report_data):
            await ws_manager.broadcast_report({"chunk": chunk, "incident_id": incident_id})
    else:
        await ws_manager.broadcast_report(report)

    await asyncio.sleep(speed_delays[req.speed])
    await ws_manager.broadcast_phase_update(5, "completed", incident_id)

    db.update_incident(incident_id, status="completed",
                       completed_at=datetime.utcnow().isoformat(),
                       cvss=scenario.get("cvss", 0),
                       epss=epss_data.get("epss", 0),
                       ai_decision=epss_data.get("recommendation", "MONITOR"),
                       confidence=(1 - epss_data.get("epss", 0)) * 100)

    return {
        "incident_id": incident_id,
        "status": "completed",
        "scenario": req.scenario,
        "assets_discovered": len(assets),
        "rules_generated": len(rules),
        "bas_result": bas_result["overall"],
        "report_generated": True
    }


# ===== WebSocket Endpoint =====

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time frontend communication."""
    client_id = await ws_manager.connect(websocket)
    try:
        while True:
            try:
                data = await websocket.receive_text()
                msg = json.loads(data)
                msg_type = msg.get("type", "")

                if msg_type == "ping":
                    await ws_manager.send_to(websocket, {
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })

                elif msg_type == "auth":
                    token = msg.get("token", "")
                    if verify_token(authorization=token):
                        await ws_manager.send_to(websocket, {
                            "type": "auth_ok",
                            "message": "Authenticated"
                        })
                    else:
                        await ws_manager.send_to(websocket, {
                            "type": "auth_error",
                            "message": "Invalid authentication token"
                        })

                elif msg_type == "scan":
                    assets = await scanner.scan_async(
                        subnet=msg.get("subnet", TARGET_SUBNET),
                        incident_id=msg.get("incident_id")
                    )
                    await ws_manager.send_to(websocket, {
                        "type": "scan_result",
                        "assets": assets,
                        "count": len(assets)
                    })

                elif msg_type == "epss":
                    result = epss_client.get_score(msg.get("cve", ""))
                    await ws_manager.send_to(websocket, {
                        "type": "epss_result",
                        "data": result
                    })

                elif msg_type == "query_logs":
                    logs = db.query_logs(
                        incident_id=msg.get("incident_id"),
                        event_type=msg.get("event_type"),
                        phase=msg.get("phase"),
                        severity=msg.get("severity"),
                        search=msg.get("search"),
                        limit=msg.get("limit", 100),
                        offset=msg.get("offset", 0)
                    )
                    await ws_manager.send_to(websocket, {
                        "type": "log_results",
                        "logs": logs,
                        "count": len(logs)
                    })

                elif msg_type == "query_assets":
                    assets = db.query_assets(
                        ips=msg.get("ip"),
                        ports=msg.get("port"),
                        vendor=msg.get("vendor"),
                        search=msg.get("search")
                    )
                    await ws_manager.send_to(websocket, {
                        "type": "asset_results",
                        "assets": assets,
                        "count": len(assets)
                    })

                elif msg_type == "query_rules":
                    rules = db.query_rules(
                        sid=msg.get("sid"),
                        rule_type=msg.get("rule_type"),
                        status=msg.get("status")
                    )
                    await ws_manager.send_to(websocket, {
                        "type": "rule_results",
                        "rules": rules,
                        "count": len(rules)
                    })

                elif msg_type == "get_stats":
                    stats = db.get_stats()
                    await ws_manager.send_to(websocket, {
                        "type": "stats",
                        "data": stats
                    })

            except json.JSONDecodeError:
                await ws_manager.send_to(websocket, {
                    "type": "error",
                    "message": "Invalid JSON"
                })

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS Error] {e}")
        await ws_manager.disconnect(websocket)


# ===== Static Files =====

from pathlib import Path
frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")


# ===== Scenario Definitions =====

def _get_scenario(name: str) -> dict:
    scenarios = {
        "hikvision": {
            "id": "ZDI-25-084",
            "name": "Hikvision Ağıllı Şəhər Kamerası Zero-Day RCE",
            "cve": "CVE-2021-36260",
            "cvss": 9.8,
            "epss": 0.97,
            "port": 554,
            "description": "Hikvision IP kameralarda RTSP buffer overflow zəifliyi."
        },
        "absheron": {
            "id": "ZDI-25-112",
            "name": "Abşeron Su Təmizləmə Stansiyası PLC Zəifliyi",
            "cve": "CVE-2025-3119",
            "cvss": 8.6,
            "epss": 0.45,
            "port": 2268,
            "description": "Siemens S7-1200 PLC PROFINET heap overflow."
        },
        "k8s": {
            "id": "ZDI-25-156",
            "name": "Milli Data Mərkəzi Kubernetes Misconfig",
            "cve": "CVE-2025-4291",
            "cvss": 7.2,
            "epss": 0.62,
            "port": 6443,
            "description": "Kubernetes RBAC bypass zəifliyi."
        },
        "random": {
            "id": "ZDI-25-201",
            "name": "Təsadüfi Kiber Təhdid",
            "cve": "CVE-2025-5133",
            "cvss": 9.0,
            "epss": 0.71,
            "port": 502,
            "description": "Təsadüfi ssenari."
        }
    }
    return scenarios.get(name)


# ===== Entry Point =====

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=LOG_LEVEL.lower()
    )
