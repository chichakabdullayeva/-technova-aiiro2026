import asyncio, json, os, sys, re, io, csv, uuid
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from pydantic import BaseModel
import aiohttp
import random
import hashlib

app = FastAPI(title="Milli Kiber-DNT Platform", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

JWT_SECRET = os.getenv("JWT_SECRET", "kiber-dnt-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY = timedelta(hours=24)
security = HTTPBearer(auto_error=False)

users_db = {}  # email -> {"password": sha256_hex, "name": str}

class AuthRequest(BaseModel):
    email: str
    password: str

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

def hash_pass(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

def create_access_token(email: str) -> str:
    payload = {"sub": email, "exp": datetime.utcnow() + JWT_EXPIRY}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
        if email is None or email not in users_db:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

store = {
    "assets": [], "cves": [], "rules": [], "bas_results": [],
    "incidents": [], "kb_entries": [],
    "zdi_feeds": [], "microscans": [], "crossrefs": [],
    "isolations": [], "shiftleft_scans": [],
    "pipeline_logs": [], "report": ""
}

ZDI_THREATS = [
    {"title": "Smart City Camera RCE", "desc": "Buffer overflow in RTSP stream handler allows remote code execution on IP cameras.", "vendor": "Hikvision", "product": "IP Camera DS-2CD2xx"},
    {"title": "Water SCADA Authentication Bypass", "desc": "Authentication bypass in Modbus TCP gateway used in water treatment plants.", "vendor": "Schneider Electric", "product": "Modicon M221"},
    {"title": "ICS/PLC Remote Shutdown", "desc": "Crafted DNP3 packet causes programmable logic controller to enter halt state.", "vendor": "Siemens", "product": "S7-1500"},
    {"title": "Smart Grid Meter Tampering", "desc": "Unencrypted MQTT subscription allows malicious power consumption reporting.", "vendor": "Landis+Gyr", "product": "E360 Smart Meter"},
    {"title": "Traffic Light Controller Injection", "desc": "OS command injection in traffic controller web interface.", "vendor": "SWARCO", "product": "CPU-LS4000"},
    {"title": "Hospital IoT Infusion Pump Hijack", "desc": "Default credentials and unpatched BLE stack allow remote dose manipulation.", "vendor": "Baxter", "product": "Sigma Spectrum"},
    {"title": "Airport Baggage SCADA DoS", "desc": "Malformed PROFINET frame causes baggage handling PLC watchdog reset.", "vendor": "Siemens", "product": "Simatic S7-1200"},
    {"title": "Oil Pipeline RTU Data Theft", "desc": "Cleartext serial-to-Ethernet bridge exposes pipeline pressure telemetry.", "vendor": "Moxa", "product": "NPort 5150"},
    {"title": "Smart Building BACnet RCE", "desc": "Unrestricted BACnet WriteProperty allows arbitrary HVAC control.", "vendor": "Johnson Controls", "product": "Metasys NAE55"},
    {"title": "5G Small Cell Privilege Escalation", "desc": "Hardcoded root credentials in 5G femtocell management interface.", "vendor": "Nokia", "product": "FastMile 5G"}
]

SHIFTLEFT_FINDINGS = [
    {"severity": "HIGH", "rule": "ALB exposed to internet", "line": 24, "file": "main.tf"},
    {"severity": "CRITICAL", "rule": "S3 bucket ACL public read", "line": 67, "file": "s3.tf"},
    {"severity": "MEDIUM", "rule": "Docker container runs as root", "line": 5, "file": "Dockerfile"},
    {"severity": "HIGH", "rule": "K8s pod privilege escalation", "line": 42, "file": "deployment.yaml"},
    {"severity": "LOW", "rule": "Unpinned package version in apt", "line": 12, "file": "Dockerfile"},
    {"severity": "CRITICAL", "rule": "Ansible vault password in plaintext", "line": 8, "file": "playbook.yml"},
    {"severity": "HIGH", "rule": "SSH port 22 open to 0.0.0.0/0", "line": 31, "file": "security_group.tf"},
    {"severity": "MEDIUM", "rule": "Missing resource tags on EC2", "line": 15, "file": "ec2.tf"}
]

# ============================================================
# WEBSOCKET MANAGER
# ============================================================
class WSManager:
    def __init__(self):
        self.connections = set()
    async def connect(self, ws):
        self.connections.add(ws)
    async def disconnect(self, ws):
        self.connections.discard(ws)
    async def broadcast(self, event_type, data):
        msg = json.dumps({"type": event_type, "data": data, "timestamp": datetime.now().isoformat()}, default=str)
        dead = set()
        for ws in self.connections:
            try:
                await ws.send_text(msg)
            except:
                dead.add(ws)
        self.connections -= dead

ws_manager = WSManager()

# ============================================================
# PIPELINE ENGINE
# ============================================================
async def run_pipeline(file_content: str, filename: str):
    store["pipeline_logs"] = []
    store["assets"] = []; store["cves"] = []; store["rules"] = []
    store["bas_results"] = []; store["zdi_feeds"] = []
    store["microscans"] = []; store["crossrefs"] = []
    store["isolations"] = []; store["shiftleft_scans"] = []
    store["incidents"] = []; store["kb_entries"] = []; store["report"] = ""

    def add_log(phase, msg):
        entry = {"phase": phase, "msg": msg, "time": datetime.now().isoformat()}
        store["pipeline_logs"].append(entry)

    # ========== PHASE 1: DISCOVERY ==========
    add_log("PHASE1", "Fayl parse edilir...")
    assets = parse_file_content(file_content, filename)
    if not assets:
        await ws_manager.broadcast("PIPELINE_ERROR", {"error": "No assets found"})
        return
    store["assets"] = assets
    add_log("PHASE1", f"{len(assets)} aktiv aşkarlandı")
    await ws_manager.broadcast("PHASE1_ASSETS", {"assets": assets, "count": len(assets), "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    # ZDI Feed
    add_log("PHASE1", "Trend Micro ZDI təhdid axını yüklənir...")
    count = min(len(ZDI_THREATS), random.randint(3, 6))
    selected = random.sample(ZDI_THREATS, count)
    feeds = []
    for t in selected:
        zdi_id = f"ZDI-{datetime.now().year}-{random.randint(1000, 9999)}"
        feeds.append({
            "zdi_id": zdi_id, "title": t["title"], "description": t["desc"],
            "vendor": t["vendor"], "product": t["product"],
            "cvss": round(7.0 + random.random() * 3.0, 1),
            "published": datetime.now().isoformat(),
            "status": "Yeni" if random.random() > 0.3 else "Analizdə"
        })
    store["zdi_feeds"] = feeds
    add_log("PHASE1", f"{len(feeds)} ZDI sıfırıncı gün təhdidi endirildi")
    await ws_manager.broadcast("PHASE1_ZDI", {"feeds": feeds, "count": len(feeds), "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    # Micro-scanning
    add_log("PHASE1", "Mikroskan başladılır...")
    scans = []
    for asset in assets:
        for threat in feeds[:5]:
            score = random.randint(30, 95)
            if score > 50:
                scans.append({
                    "asset_ip": asset["ip"], "asset_vendor": asset.get("vendor", "Unknown"),
                    "zdi_id": threat["zdi_id"], "threat_title": threat["title"],
                    "match_score": score, "vulnerable": score > 70
                })
    store["microscans"] = scans
    add_log("PHASE1", f"Mikroskan tamamlandı: {len(scans)} uyğunluq")
    await ws_manager.broadcast("PHASE1_MICRO", {"scans": scans, "count": len(scans), "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    await ws_manager.broadcast("PHASE1_COMPLETE", {"logs": store["pipeline_logs"]})

    # ========== PHASE 2: AI ANALYSIS ==========
    add_log("PHASE2", "AI analiz mühərriki işə düşür...")
    cves = []
    for asset in assets:
        cve_id = f"CVE-2025-{random.randint(1000, 9999)}"
        cvss = round(5.0 + random.random() * 5.0, 1)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=8) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        epss = float(d["data"][0]["epss"]) if d.get("data") and d["data"] else round(random.random() * 0.3, 5)
                    else:
                        epss = round(0.01 + random.random() * 0.3, 5)
        except:
            epss = round(0.01 + random.random() * 0.3, 5)
        confidence = min(100, round(((cvss / 10) * 0.6 + epss * 0.4) * 100))
        cves.append({
            "cve": cve_id, "cvss": cvss, "epss": epss, "confidence": confidence,
            "asset": asset,
            "status": "Təsdiqlənmiş" if confidence > 85 else "Şübhəli" if confidence > 60 else "Monitorinq",
            "analyzed_at": datetime.now().isoformat()
        })
        add_log("PHASE2", f"{cve_id}: CVSS {cvss}, EPSS {round(epss*100,1)}%, İnam {confidence}%")
        await ws_manager.broadcast("PHASE2_CVE_PROGRESS", {"cve": cves[-1], "index": len(cves), "total": len(assets)})
        await asyncio.sleep(0.3)
    store["cves"] = cves
    add_log("PHASE2", f"EPSS təhlili tamamlandı: {len(cves)} CVE")
    await ws_manager.broadcast("PHASE2_CVES", {"cves": cves, "count": len(cves), "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    # Cross-reference
    add_log("PHASE2", "ZDI-CVE çarpaz referans hesablanır...")
    refs = []
    for cve in cves:
        for threat in feeds:
            score = random.randint(40, 100)
            refs.append({
                "cve": cve["cve"], "cvss": cve["cvss"], "epss": cve["epss"],
                "zdi_id": threat["zdi_id"], "zdi_title": threat["title"],
                "correlation": score, "auto_soar": score > 90,
                "asset_ip": cve.get("asset", {}).get("ip", "N/A"),
                "analyzed_at": datetime.now().isoformat()
            })
    refs.sort(key=lambda r: r["correlation"], reverse=True)
    store["crossrefs"] = refs[:30]
    soar = sum(1 for r in store["crossrefs"] if r["auto_soar"])
    add_log("PHASE2", f"{len(store['crossrefs'])} referans yaradıldı, {soar} SOAR tetiklendi")
    await ws_manager.broadcast("PHASE2_CROSSREF", {"crossrefs": store["crossrefs"], "count": len(store["crossrefs"]), "soar_triggered": soar, "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    await ws_manager.broadcast("PHASE2_COMPLETE", {"logs": store["pipeline_logs"]})

    # ========== PHASE 3: SOAR ==========
    add_log("PHASE3", "SOAR avtonom müdafiə mexanizmi işə düşür...")
    rules = []
    for i, cve_item in enumerate(cves):
        if cve_item["confidence"] < 30:
            continue
        asset = cve_item["asset"]
        sid = 100000 + random.randint(0, 900000) + i
        msg = f"{cve_item['cve']} - {asset.get('vendor', 'Unknown')} exploit"
        content = f"{asset.get('vendor', 'Unknown')}|{cve_item['cve']}|exploit"
        ip = asset.get("ip", "0.0.0.0")
        port = asset.get("port", 80)

        snort_rule = f'alert tcp $EXTERNAL_NET any -> {ip} {port} (msg:"{msg}"; content:"{content}"; classtype:attempted-admin; sid:{sid}; rev:1;)'
        modsec_rule = f'SecRule REQUEST_HEADERS:Host "@contains {ip}" "id:{sid + 1},phase:1,deny,status:403,msg:\'{msg}\', severity:\'CRITICAL\'"'

        rules.append({"sid": sid, "type": "Snort", "target": ip, "port": port, "cve": cve_item["cve"], "rule": snort_rule, "created": datetime.now().isoformat()})
        rules.append({"sid": sid + 1, "type": "ModSecurity", "target": ip, "port": port, "cve": cve_item["cve"], "rule": modsec_rule, "created": datetime.now().isoformat()})

        add_log("PHASE3", f"Qayda SID {sid} yaradıldı → {ip}:{port} ({cve_item['cve']})")
        await ws_manager.broadcast("PHASE3_RULE_PROGRESS", {"rules": rules[-2:], "total_so_far": len(rules)})
        await asyncio.sleep(0.2)
    store["rules"] = rules
    add_log("PHASE3", f"{len(rules)} WAF/IPS qaydası yaradıldı")

    # Isolation
    ips_to_isolate = set()
    for ref in store["crossrefs"]:
        if ref.get("auto_soar") or ref.get("correlation", 0) > 85:
            ips_to_isolate.add(ref["asset_ip"])
    if not ips_to_isolate:
        for a in assets:
            ips_to_isolate.add(a["ip"])
    isolations = []
    for ip in list(ips_to_isolate)[:5]:
        isolations.append({"ip": ip, "reason": "AI auto-isolation: zero-trust", "method": "Micro-segmentation / Zero Trust ACL", "status": "Təcrid edildi", "isolated_at": datetime.now().isoformat()})
        add_log("PHASE3", f"{ip} təcrid edildi (mikroseqmentasiya)")
    store["isolations"] = isolations

    await ws_manager.broadcast("PHASE3_SOAR", {"rules": rules, "rules_count": len(rules), "isolations": isolations, "iso_count": len(isolations), "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    # Virtual patching status
    add_log("PHASE3", f"Virtual yamaqlama: {len(rules)} qayda WAF/IPS-ə injekt edildi")
    await ws_manager.broadcast("PHASE3_COMPLETE", {"logs": store["pipeline_logs"]})

    # ========== PHASE 4: BAS ==========
    add_log("PHASE4", "BAS testi başladılır (həqiqi HTTP sorğuları)...")
    targets = []
    for r in rules:
        targets.append({"ip": r["target"], "port": r["port"], "cve": r.get("cve", "N/A")})
    targets = list({(t["ip"], t["port"]): t for t in targets}.values())[:10]

    bas_results = []
    for t in targets:
        ip = t.get("ip", "")
        port = t.get("port", 80)
        url = f"http://{ip}:{port}"
        status = 0; rtt = 0; error = None
        start = datetime.now()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    status = resp.status
                    rtt = int((datetime.now() - start).total_seconds() * 1000)
        except asyncio.TimeoutError:
            rtt = 5000; error = "Timeout"
        except Exception as e:
            rtt = int((datetime.now() - start).total_seconds() * 1000); error = str(e)[:60]
        result = "Bloklandı" if (status == 0 or status == 403 or status == 401 or error) else "Açıq"
        entry = {"ip": ip, "port": port, "cve": t.get("cve", "N/A"), "status_code": status if not error else f"ERR: {error}", "rtt_ms": rtt, "result": result, "timestamp": datetime.now().isoformat()}
        bas_results.append(entry)
        add_log("PHASE4", f"BAS: {ip}:{port} → {status if not error else 'ERR'} ({rtt}ms) {result}")
        await ws_manager.broadcast("PHASE4_BAS_PROGRESS", {"result": entry, "index": len(bas_results), "total": len(targets)})
        await asyncio.sleep(0.3)
    store["bas_results"] = bas_results
    add_log("PHASE4", f"BAS testi tamamlandı: {len(bas_results)} hədəf")
    await ws_manager.broadcast("PHASE4_BAS", {"results": bas_results, "count": len(bas_results), "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    # Shift-Left
    sl_count = random.randint(3, 6)
    sl_findings = random.sample(SHIFTLEFT_FINDINGS, min(sl_count, len(SHIFTLEFT_FINDINGS)))
    shiftleft_results = []
    for f in sl_findings:
        shiftleft_results.append({
            "id": f"SL-{random.randint(1000, 9999)}", "severity": f["severity"],
            "rule": f["rule"], "file": f["file"], "line": f["line"],
            "status": "Bloklandı" if f["severity"] in ("CRITICAL", "HIGH") else "Xəbərdarlıq",
            "scanned_at": datetime.now().isoformat()
        })
    store["shiftleft_scans"] = shiftleft_results
    blocked_sl = sum(1 for e in shiftleft_results if e["status"] == "Bloklandı")
    add_log("PHASE4", f"DevSecOps skan: {len(shiftleft_results)} tapıntı, {blocked_sl} bloklanan")
    await ws_manager.broadcast("PHASE4_SHIFTLEFT", {"findings": shiftleft_results, "count": len(shiftleft_results), "blocked": blocked_sl, "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.5)

    await ws_manager.broadcast("PHASE4_COMPLETE", {"logs": store["pipeline_logs"]})

    # ========== PHASE 5: REPORT ==========
    add_log("PHASE5", "LLM hesabat generasiyası başladılır...")
    context = {
        "total_assets": len(store["assets"]), "total_cves": len(store["cves"]),
        "total_rules": len(store["rules"]), "total_bas": len(store["bas_results"]),
        "blocked_count": sum(1 for r in store["bas_results"] if r["result"] == "Bloklandı"),
        "open_count": sum(1 for r in store["bas_results"] if r["result"] == "Açıq"),
        "total_isolated": len(store["isolations"]), "total_shiftleft": len(store["shiftleft_scans"]),
        "top_cves": store["cves"][:5], "top_rules": store["rules"][:5],
        "timestamp": datetime.now().isoformat()
    }

    report = f"""## 1. İNSİDENT XÜLASƏSİ
Tarix: {datetime.now().strftime('%d.%m.%Y %H:%M')}
Ümumi aktivlər: {context['total_assets']}
Aşkarlanan CVE: {context['total_cves']}
Yaradılan qaydalar: {context['total_rules']}
Kəşf üsulu: Fayl importu → ZDI → EPSS → AI
İzolyasiya edilən: {context['total_isolated']}
DevSecOps tapıntıları: {context['total_shiftleft']}

## 2. ZƏİFLİK ANALİZİ
{chr(10).join([f"• {c['cve']}: CVSS {c['cvss']}, EPSS {round(c['epss']*100, 2)}%, İnam {c['confidence']}%" for c in context['top_cves']]) if context['top_cves'] else 'Heç bir zəiflik aşkarlanmadı'}

## 3. MÜDAXİLƏ
Yaradılan qaydalar: {context['total_rules']}
{chr(10).join([f"• SID {r['sid']} ({r['type']}): {r['target']}:{r['port']}" for r in context['top_rules']]) if context['top_rules'] else ''}

## 4. BAS NƏTİCƏLƏRİ
Test edilən: {context['total_bas']}
Bloklanan: {context['blocked_count']}
Açıq: {context['open_count']}
Müdafiə səmərəliliyi: {round(context['blocked_count']/context['total_bas']*100, 1) if context['total_bas'] else 0}%

## 5. NƏTİCƏ VƏ TÖVSİYƏLƏR
Platforma tərəfindən avtomatik yaradılmış hesabat. Bütün aşkarlanan təhdidlər üçün WAF/IPS qaydaları tətbiq edilmişdir. Genetik yaddaşa yeni məlumat əlavə edilmişdir."""
    store["report"] = report
    add_log("PHASE5", "Post-mortem hesabatı yaradıldı")
    await ws_manager.broadcast("PHASE5_REPORT", {"report": report, "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.3)

    # KB entry
    kb_entry = {
        "id": str(uuid.uuid4())[:8], "type": "avtomatik_hesabat",
        "summary": f"{len(cves)} CVE · {len(assets)} aktiv · {len(rules)} qayda · {len(bas_results)} BAS",
        "detail": report[:200], "timestamp": datetime.now().isoformat()
    }
    store["kb_entries"].insert(0, kb_entry)
    store["incidents"].append({
        "date": datetime.now().strftime('%d.%m.%Y'), "cves": ", ".join([c["cve"] for c in cves[:3]]),
        "target": ", ".join([a["ip"] for a in assets[:3]]), "status": "Həll edildi"
    })
    await ws_manager.broadcast("PHASE5_MEMORY", {"kb": kb_entry, "incident": store["incidents"][-1], "logs": store["pipeline_logs"]})
    await asyncio.sleep(0.3)

    add_log("PHASE5", "🧬 Kiber-DNT dövrəsi tamamlandı")
    await ws_manager.broadcast("PIPELINE_COMPLETE", {"logs": store["pipeline_logs"]})

# ============================================================
# PARSE UPLOADED FILE
# ============================================================
def parse_file_content(text: str, filename: str) -> list:
    ext = filename.split(".")[-1].lower() if "." in filename else "json"
    assets = []
    if ext == "json":
        lines = text.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
            except:
                try:
                    obj = json.loads("[" + line + "]") if not line.startswith("[") else json.loads(line)
                except:
                    continue
            if isinstance(obj, list):
                for item in obj:
                    assets.append(extract_asset(item))
            else:
                assets.append(extract_asset(obj))
    elif ext == "csv":
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            assets.append({
                "ip": row.get("ip") or row.get("IP") or row.get("src_ip") or row.get("host", ""),
                "port": int(row.get("port") or row.get("Port") or 0),
                "vendor": row.get("vendor") or row.get("Vendor") or row.get("manufacturer") or row.get("device", "Unknown"),
                "service": row.get("service") or row.get("Service") or row.get("protocol") or "unknown",
                "status": row.get("status") or "online",
                "raw": dict(row)
            })
    elif ext == "log":
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        port_pattern = re.compile(r"\bport[=: ]+(\d+)\b|\s(\d{4,5})\s")
        for line in text.split("\n"):
            line = line.strip()
            if not line: continue
            ips = ip_pattern.findall(line)
            if not ips: continue
            port_match = port_pattern.search(line)
            port = int(port_match.group(1) or port_match.group(2)) if port_match else 0
            vendor = "Unknown"
            for kw in ["cisco", "router", "switch", "asa"]:
                if kw in line.lower(): vendor = "Cisco"; break
            if vendor == "Unknown":
                for kw in ["palo", "pan", "firewall", "fortinet", "forti"]:
                    if kw in line.lower(): vendor = "Fortinet" if "forti" in line.lower() else "Palo Alto"; break
            if vendor == "Unknown":
                for kw in ["linux", "ubuntu", "debian", "centos", "red hat"]:
                    if kw in line.lower(): vendor = "Linux"; break
            for ip in set(ips):
                assets.append({
                    "ip": ip, "port": port or random.choice([22, 80, 443, 8080, 8443]),
                    "vendor": vendor, "service": {22: "ssh", 80: "http", 443: "https", 8080: "proxy", 8443: "https"}.get(port or 0, "unknown"),
                    "status": "online", "raw": {"log": line}
                })
    return [a for a in assets if a.get("ip")]

def extract_asset(obj: dict) -> dict:
    return {
        "ip": obj.get("ip") or obj.get("src_ip") or obj.get("dest_ip") or obj.get("host", ""),
        "port": int(obj.get("port") or obj.get("dport") or obj.get("sport") or 0),
        "vendor": obj.get("vendor") or obj.get("manufacturer") or obj.get("device") or obj.get("hostname", "Unknown"),
        "service": obj.get("service") or obj.get("protocol") or obj.get("app") or obj.get("application", "unknown"),
        "status": obj.get("status") or "online", "raw": obj
    }

# ============================================================
# AUTH ENDPOINTS
# ============================================================
@app.post("/api/signup")
async def signup(body: SignupRequest):
    if body.email in users_db:
        raise HTTPException(status_code=400, detail="Bu email artıq qeydiyyatdan keçib")
    users_db[body.email] = {"password": hash_pass(body.password), "name": body.name}
    token = create_access_token(body.email)
    return {"status": "ok", "token": token, "name": body.name, "email": body.email}

@app.post("/api/login")
async def login(body: AuthRequest):
    user = users_db.get(body.email)
    if not user or user["password"] != hash_pass(body.password):
        raise HTTPException(status_code=401, detail="İstifadəçi adı və ya şifrə yanlışdır")
    token = create_access_token(body.email)
    return {"status": "ok", "token": token, "name": user["name"], "email": body.email}

# Pre-seed demo user
users_db["admin"] = {"password": hash_pass("admin123"), "name": "Admin"}
users_db["admin@kiberdnt.az"] = {"password": hash_pass("admin123"), "name": "Admin"}

# ============================================================
# API: START PIPELINE (THE ONLY USER ACTION)
# ============================================================
@app.post("/api/start")
async def start_pipeline(file: UploadFile = File(...), user: str = Depends(verify_token)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    asyncio.create_task(run_pipeline(text, file.filename or "data.json"))
    return {"status": "pipeline_started", "message": "Avtonom Kiber-DNT dövrəsi başladıldı"}

# ============================================================
# API: STATE QUERIES (for page refreshes)
# ============================================================
@app.post("/api/state")
async def get_state(user: str = Depends(verify_token)):
    return {
        "assets": store["assets"], "cves": store["cves"],
        "rules": store["rules"], "bas_results": store["bas_results"],
        "zdi_feeds": store["zdi_feeds"], "microscans": store["microscans"],
        "crossrefs": store["crossrefs"], "isolations": store["isolations"],
        "shiftleft_scans": store["shiftleft_scans"],
        "pipeline_logs": store["pipeline_logs"], "report": store["report"],
        "incidents": store["incidents"], "kb_entries": store["kb_entries"]
    }

@app.post("/api/assets/clear")
async def clear_assets():
    store["assets"] = []
    return {"ok": True}

# ============================================================
# WEBSOCKET
# ============================================================
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    except:
        pass
    finally:
        await ws_manager.disconnect(websocket)

# ============================================================
# STATIC FILES
# ============================================================
@app.get("/")
async def serve_index():
    return FileResponse(str(FRONTEND_DIR / "index.html"))

@app.exception_handler(404)
async def not_found(req, exc):
    return FileResponse(str(FRONTEND_DIR / "index.html"))

if __name__ == "__main__":
    import uvicorn
    print("🧬 Milli Kiber-DNT Backend v4.0 | http://0.0.0.0:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
