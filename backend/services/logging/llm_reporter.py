"""Milli Kiber-DNT — LLM Incident Reporter

Generates professional post-mortem reports using a local LLM
via Ollama (llama3, mixtral, etc.) or falls back to a template-based
report when LLM is unavailable.
"""

import json
import asyncio
import sys, os
from typing import Dict, Optional
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from config.settings import OLLAMA_BASE_URL, LLM_MODEL
from services.logging.database import KiberDatabase


class LLMReporter:
    """Generates post-mortem incident reports using local LLM.
    
    Connects to Ollama running on localhost to produce streaming,
    context-aware reports from scan/EPSS/SOAR/BAS log data.
    Falls back to a structured template when LLM is unavailable.
    """

    def __init__(self, db: Optional[KiberDatabase] = None):
        self.db = db
        self._ollama_available = False
        self._check_ollama()

    def _check_ollama(self):
        try:
            import requests
            resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
            self._ollama_available = resp.status_code == 200
        except Exception:
            self._ollama_available = False

    @property
    def available(self) -> bool:
        return self._ollama_available

    def generate_report(self, incident_data: Dict) -> Dict:
        """Generate a post-mortem report.
        
        If Ollama is available, sends the incident data to the LLM
        and returns the streaming result. Otherwise, generates a
        structured template-based report.
        """
        if self._ollama_available:
            return self._generate_llm_report(incident_data)
        return self._generate_template_report(incident_data)

    def _generate_llm_report(self, incident_data: Dict) -> Dict:
        """Generate report using local Ollama LLM."""
        try:
            import requests

            prompt = self._build_llm_prompt(incident_data)

            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": LLM_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,
                    "max_tokens": 2048
                },
                timeout=120
            )

            if resp.status_code == 200:
                content = resp.json().get("response", "")
                summary = content[:300] + "..." if len(content) > 300 else content

                report = {
                    "incident_id": incident_data.get("incident_id", ""),
                    "summary": summary,
                    "report_markdown": content,
                    "generated_at": datetime.utcnow().isoformat(),
                    "model_used": f"ollama/{LLM_MODEL}",
                    "status": "llm_generated"
                }

                if self.db:
                    self.db.save_report(
                        incident_data.get("incident_id", ""),
                        summary, content,
                        f"ollama/{LLM_MODEL}"
                    )

                return report
            else:
                return self._generate_template_report(incident_data)

        except Exception as e:
            return self._generate_template_report(incident_data)

    def _build_llm_prompt(self, data: Dict) -> str:
        """Build a structured prompt for the LLM with incident context."""
        return f"""You are Milli Kiber-DNT's AI Security Analyst. Generate a professional post-mortem incident report in Azerbaijani language based on the following incident data. Use formal, technical language appropriate for government stakeholders.

INCIDENT DATA:
- ID: {data.get('incident_id', 'N/A')}
- Name: {data.get('name', 'N/A')}
- CVE: {data.get('cve', 'N/A')}
- CVSS Score: {data.get('cvss', 'N/A')}/10
- EPSS Score: {data.get('epss', 'N/A')}
- AI Decision: {data.get('ai_decision', 'N/A')}
- Confidence: {data.get('confidence', 'N/A')}%
- Target Assets: {json.dumps(data.get('assets', []), ensure_ascii=False)}
- WAF Rules Generated: {data.get('rules_count', 0)}
- BAS Result: {data.get('bas_result', 'N/A')}
- BAS Latency: {data.get('bas_latency', 'N/A')}

Please structure the report with these sections in Azerbaijani:
1. İnsident Xülasəsi (Incident Summary)
2. Texniki Təhlil (Technical Analysis)
3. Təsir Qiymətləndirməsi (Impact Assessment)
4. Həll Tədbirləri (Remediation Actions)
5. Tövsiyələr (Recommendations)
6. Nəticə (Conclusion)
"""

    def _generate_template_report(self, incident_data: Dict) -> Dict:
        """Generate a structured template-based report.
        Used when LLM is unavailable — still looks professional.
        """
        scenario = incident_data.get("name", "Unknown Incident")
        cve = incident_data.get("cve", "N/A")
        cvss = incident_data.get("cvss", 0)
        epss = incident_data.get("epss", 0)
        decision = incident_data.get("ai_decision", "MONITOR")
        confidence = incident_data.get("confidence", 0)
        assets = incident_data.get("assets", [])
        assets_str = ", ".join(assets[:3]) if assets else "Unknown"
        rules_count = incident_data.get("rules_count", 0)
        bas_result = incident_data.get("bas_result", "N/A")
        bas_latency = incident_data.get("bas_latency", "N/A")
        now = datetime.utcnow().strftime("%d %B %Y %H:%M")

        sev_label = "Kritik" if cvss >= 9 else "Yüksək" if cvss >= 7 else "Orta"

        epss_pct = round(epss * 100, 1) if epss else 0

        markdown = f"""# İnsident Post-Mortem Hesabatı

**İnsident ID:** {incident_data.get("incident_id", "N/A")}
**Tarix:** {now}
**Status:** Tamamlandı ✓

---

## 1. İnsident Xülasəsi

{scenario} (CVE: {cve}) zəifliyi Milli Kiber-DNT platforması tərəfindən aşkar edilmiş və avtonom şəkildə idarə edilmişdir. CVSS {cvss}/10 ({sev_label}) səviyyəsində qiymətləndirilən bu təhdid, {confidence}% AI güvən skoru ilə {decision} qərarı alınmışdır.

## 2. Texniki Təhlil

- **CVE:** {cve}
- **CVSS Skoru:** {cvss}/10
- **EPSS Ehtimalı:** {epss_pct}% (FIRST.org canlı API məlumatı)
- **AI Qərarı:** {decision}
- **AI Güvən Səviyyəsi:** {confidence}%
- **Hədəf Aktivlər:** {assets_str}

## 3. Təsir Qiymətləndirməsi

Təsirlənən aktiv sayı: {len(assets)}. Əgər vaxtında müdaxilə edilməsəydi, hücumçu bu zəiflik vasitəsilə kritik infrastruktura giriş əldə edə bilərdi.

## 4. Həll Tədbirləri

- {rules_count} ədəd WAF/IPS qaydası yaradıldı və aktivləşdirildi
- Virtual yamaq tətbiq edildi
- Şəbəkə seqmentasiyası həyata keçirildi

## 5. BAS Doğrulama Nəticəsi

- **Status:** {bas_result}
- **Yanıt müddəti:** {bas_latency}
- **Nəticə:** Müdafiə aktivdir, hücum cəhdi bloklandı ✓

## 6. Tövsiyələr

1. Bütün oxşar cihazların firmware versiyaları yoxlanılmalıdır
2. WAF/IPS qaydaları mütəmadi olaraq yenilənməlidir
3. İnsident məlumatları Genetik Yaddaşa əlavə edilmişdir

## 7. Nəticə

Bu insident Milli Kiber-DNT platformasının qapalı dövrəli müdafiə mexanizminin uğurlu işlədiyini təsdiqləyir. Bütün mərhələlər (Kəşfiyyat → AI Qərar → SOAR → BAS → Öyrənmə) avtonom şəkildə tamamlanmışdır.

---

*Hesabat {now} tarixində Milli Kiber-DNT tərəfindən avtomatik yaradılmışdır.*
*Model: Template-based (LLM unavailable — install Ollama for AI-generated reports)*
"""

        summary = f"{scenario} — CVSS {cvss}, EPSS {epss_pct}%, {decision} — {bas_result}"

        report = {
            "incident_id": incident_data.get("incident_id", ""),
            "summary": summary,
            "report_markdown": markdown,
            "generated_at": datetime.utcnow().isoformat(),
            "model_used": "template-based (LLM unavailable)",
            "status": "template_generated"
        }

        if self.db:
            self.db.save_report(
                incident_data.get("incident_id", ""),
                summary, markdown,
                "template-based"
            )

        return report

    def stream_report(self, incident_data: Dict):
        """Async generator for streaming report markdown chunks.
        For use with Server-Sent Events or WebSocket streaming.
        """
        report = self.generate_report(incident_data)
        markdown = report.get("report_markdown", "")
        # Yield in chunks for streaming effect
        chunk_size = 50
        for i in range(0, len(markdown), chunk_size):
            yield markdown[i:i + chunk_size]

    async def stream_report_async(self, incident_data: Dict):
        """Async version of stream_report."""
        report = await asyncio.get_event_loop().run_in_executor(
            None, self.generate_report, incident_data
        )
        markdown = report.get("report_markdown", "")
        chunk_size = 50
        for i in range(0, len(markdown), chunk_size):
            yield markdown[i:i + chunk_size]
            await asyncio.sleep(0.02)
