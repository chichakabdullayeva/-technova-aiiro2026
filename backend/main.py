"""Milli Kiber-DNT — Closed-Loop Backend API (minimal, real)"""
import sys, os, json, asyncio, uuid
from datetime import datetime
from contextlib import asynccontextmanager
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import aiohttp
import re

# ===== EPSS Proxy =====
EPSS_URL = "https://api.first.org/data/v1/epss"

async def fetch_epss(cve: str) -> dict:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(EPSS_URL, params={"cve": cve}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data") and len(data["data"]):
                        e = data["data"][0]
                        return {
                            "cve": cve,
                            "epss": float(e["epss"]),
                            "percentile": float(e["percentile"]),
                            "date": e["date"],
                            "source": "first.org (live)"
                        }
                return {"cve": cve, "error": f"EPSS API: HTTP {resp.status}"}
    except Exception as ex:
        return {"cve": cve, "error": str(ex)}

# ===== Rule Generation =====
def gen_snort_rule(cve: str, service: str, port: int, epss: float, sid: int) -> str:
    prio = 1 if epss > 0.6 else 2 if epss > 0.3 else 3
    if port == 554 or service == "rtsp":
        return f'alert tcp any any -> $HOME_NET {port} (msg:"Kiber-DNT: {cve} RCE Attempt"; content:"GET"; http_method; content:"/SDK/webLanguage"; http_uri; sid:{sid}; rev:1; classtype:attempted-admin; priority:{prio};)'
    elif port == 502 or service == "modbus":
        return f'alert tcp any any -> $HOME_NET {port} (msg:"Kiber-DNT: {cve} PLC Attack"; content:"|00 00 00 00 00 00|"; depth:6; sid:{sid}; rev:1; classtype:attempted-admin; priority:{prio};)'
    elif port == 443 or service == "https":
        return f'alert tls any any -> $HOME_NET {port} (msg:"Kiber-DNT: {cve} TLS Exploit"; flow:established,to_server; content:"{cve}"; sid:{sid}; rev:1; classtype:attempted-admin; priority:{prio};)'
    else:
        return f'alert http any any -> $HOME_NET {port} (msg:"Kiber-DNT: {cve} Web Attack"; flow:established,to_server; content:"{cve}"; sid:{sid}; rev:1; classtype:attempted-admin; priority:{prio};)'

def gen_suricata_rule(cve: str, service: str, port: int, epss: float, sid: int) -> str:
    return gen_snort_rule(cve, service, port, epss, sid).replace("alert tcp", "alert http")

def gen_modsec_rule(cve: str, service: str, port: int, epss: float, sid: int) -> str:
    return f'SecRule REQUEST_URI "@contains /{cve.split("-")[0]}" "id:{sid},phase:1,deny,status:403,msg:\'Kiber-DNT: {cve} Blocked\',severity:\'{"CRITICAL" if epss>0.6 else "WARNING"}\'"'

# ===== App =====
@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[Kiber-DNT] Backend hazır | :8000")
    yield

app = FastAPI(title="Milli Kiber-DNT API", version="3.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# EPSS proxy
@app.get("/api/epss/{cve}")
async def epss_proxy(cve: str):
    cve = cve.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d+$', cve):
        return {"error": "Yanlış CVE formatı"}
    return await fetch_epss(cve)

# Rule generation
@app.post("/api/rules/generate")
async def generate_rules(data: dict):
    threats = data.get("threats", [])
    rules = []
    for i, t in enumerate(threats):
        sid = 20260000 + i + 1
        epss = t.get("epss", 0.5)
        rules.append({
            "sid": sid,
            "type": "snort",
            "target": f"{t.get('ip','?')}:{t.get('port',80)}",
            "cve": t.get("cve", "CVE-UNKNOWN"),
            "rule": gen_snort_rule(t.get("cve","CVE-UNKNOWN"), t.get("service","http"), int(t.get("port",80)), epss, sid)
        })
        rules.append({
            "sid": sid + 10000,
            "type": "modsecurity",
            "target": f"{t.get('ip','?')}:{t.get('port',80)}",
            "cve": t.get("cve", "CVE-UNKNOWN"),
            "rule": gen_modsec_rule(t.get("cve","CVE-UNKNOWN"), t.get("service","http"), int(t.get("port",80)), epss, sid + 10000)
        })
    return {"rules": rules, "count": len(rules)}

# Health
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Milli Kiber-DNT", "version": "3.0", "timestamp": datetime.utcnow().isoformat()}

# Serve frontend
frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
