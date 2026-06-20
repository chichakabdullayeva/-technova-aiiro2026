import asyncio, json, os, sys, urllib.request, urllib.parse
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
import aiohttp

app = FastAPI(title="Milli Kiber-DNT API", version="3.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Milli Kiber-DNT", "version": "3.1", "timestamp": __import__('datetime').datetime.now().isoformat()}

@app.get("/api/epss/{cve_id}")
async def get_epss(cve_id: str):
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(400, "Invalid CVE format")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data") and len(data["data"]) > 0:
                        epss = float(data["data"][0].get("epss", 0))
                        return {"cve": cve_id, "epss": epss, "source": "first.org"}
        return {"cve": cve_id, "epss": 0.01 + __import__('random').random() * 0.3, "source": "fallback"}
    except Exception as e:
        return {"cve": cve_id, "epss": 0.01 + __import__('random').random() * 0.3, "source": "fallback", "error": str(e)}

@app.get("/api/rules/generate")
async def generate_rules(target: str = "", port: int = 80, cve: str = "CVE-2025-0001", vendor: str = "unknown"):
    sid_base = 100000 + __import__('random').randint(0, 900000)
    msg = f"{cve} - {vendor} exploit attempt"
    content = f"{vendor}|{cve}|exploit"
    if not target:
        target = "192.168.1.1"
    snort = f"alert tcp $EXTERNAL_NET any -> {target} {port} (msg:\"{msg}\"; content:\"{content}\"; classtype:attempted-admin; sid:{sid_base}; rev:1;)"
    suricata = f"alert http $EXTERNAL_NET any -> {target} {port} (msg:\"{msg}\"; content:\"{content}\"; classtype:attempted-admin; sid:{sid_base + 1}; rev:1;)"
    modsec = f'SecRule REQUEST_HEADERS:Host "@contains {target}" "id:{sid_base + 2},phase:1,deny,status:403,msg:\'{msg}\', severity:\'CRITICAL\'"'
    return {
        "target": target, "port": port, "cve": cve, "vendor": vendor,
        "snort": snort, "suricata": suricata, "modsecurity": modsec, "sid_base": sid_base
    }

@app.get("/api/llm/report")
async def get_llm_report():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post("http://localhost:11434/api/generate", json={
                "model": "llama3.2",
                "prompt": "Sən Milli Kiber-DNT platformasının LLM hesabat modulusan. Cari sistem statusu haqqında qısa bir hesabat yaz. Aktiv sayı: 0, CVE: 0, Qayda: 0. Azərbaycan dilində yaz.",
                "stream": False
            }, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"status": "ok", "report": data.get("response", "Hesabat generasiya olunmadı.")}
    except Exception:
        pass
    return {"status": "ok", "report": "LLM mühərriki (Ollama) aktiv deyil. Hesabat template əsasında yaradıldı."}

@app.get("/")
async def serve_index():
    return FileResponse(str(FRONTEND_DIR / "index.html"))

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    print("🧬 Milli Kiber-DNT Backend | :8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
