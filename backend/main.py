"""Milli Kiber-DNT v3 — FastAPI Application"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import asyncio, json, uuid
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from config.settings import LOG_LEVEL
from services.logging.database import KiberDatabase
from websocket.live import ConnectionManager
from services.discovery.scanner import NetworkScanner
from services.threat.epss_client import EPSSClient
from services.defense.soar_engine import SOAREngine
from services.verification.bas_engine import BASEngine
from services.logging.llm_reporter import LLMReporter
from api.discovery import router as discovery_router
from api.threat import router as threat_router
from api.defense import router as defense_router
from api.verification import router as verification_router
from api.logs import router as logs_router

db = KiberDatabase()
ws_manager = ConnectionManager()
scanner = NetworkScanner(db=db)
epss = EPSSClient(db=db)
soar = SOAREngine(db=db)
bas = BASEngine(db=db)
llm = LLMReporter(db=db)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[Kiber-DNT] v3 başladı | Nmap: {'✓' if scanner.available else '✗'} | LLM: {'✓' if llm.available else '✗'}")
    print(f"[Kiber-DNT] DB: {db.db_path} | WebSocket: /ws")
    yield
    db.close()

app = FastAPI(title="Milli Kiber-DNT v3", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

app.include_router(discovery_router)
app.include_router(threat_router)
app.include_router(defense_router)
app.include_router(verification_router)
app.include_router(logs_router)

@app.get("/api/status")
async def get_status():
    return {"service": "Milli Kiber-DNT v3", "version": "3.0.0", "status": "running", "nmap": scanner.available, "llm": llm.available, "ws": ws_manager.active_connections}

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global scanner, epss, soar, bas, llm
    client_id = await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            msg_type = msg.get("type", "")

            if msg_type == "ping":
                await ws_manager.send_to(websocket, {"type": "pong", "timestamp": datetime.utcnow().isoformat()})

            elif msg_type == "auth":
                await ws_manager.send_to(websocket, {"type": "auth_ok", "message": "Authenticated"})

            elif msg_type == "scan":
                assets = await scanner.scan_async(subnet=msg.get("subnet", "10.10.40.0/24"))
                await ws_manager.send_to(websocket, {"type": "scan_result", "assets": assets, "count": len(assets)})

            elif msg_type == "epss":
                cve = msg.get("cve", "")
                result = epss.get_score(cve)
                await ws_manager.send_to(websocket, {"type": "epss_result", "data": result})

            elif msg_type == "rules":
                threat = msg.get("threat", {"cve": "CVE-2021-36260", "cvss": 9.8, "port": 554, "service": "rtsp"})
                rules = soar.generate_rules_for_threat(threat)
                await ws_manager.send_to(websocket, {"type": "rules_result", "rules": rules})

            elif msg_type == "bas":
                ip = msg.get("target_ip", "10.10.40.12")
                port = msg.get("target_port", 80)
                result = bas.verify_patch_http(ip, port)
                await ws_manager.send_to(websocket, {"type": "bas_result", "data": result})

            elif msg_type == "query_logs":
                logs = db.query_logs(event_type=msg.get("event_type"), phase=msg.get("phase"), severity=msg.get("severity"), search=msg.get("search"), limit=msg.get("limit", 100))
                await ws_manager.send_to(websocket, {"type": "log_results", "logs": logs, "count": len(logs)})

            elif msg_type == "query_assets":
                assets = db.query_assets(ips=msg.get("ip"), ports=msg.get("port"), vendor=msg.get("vendor"))
                await ws_manager.send_to(websocket, {"type": "asset_results", "assets": assets, "count": len(assets)})

            elif msg_type == "get_stats":
                await ws_manager.send_to(websocket, {"type": "stats", "data": db.get_stats()})

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)

frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level=LOG_LEVEL.lower())
