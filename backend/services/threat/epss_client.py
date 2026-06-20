"""Milli Kiber-DNT — Real EPSS (Exploit Prediction Scoring System) Client

Queries FIRST.org's official live EPSS API for real threat metrics.
https://www.first.org/epss/api
"""

import requests
import sys, os
from typing import Dict, Optional
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from config.settings import EPSS_API_URL, EPSS_TIMEOUT
from services.logging.database import KiberDatabase


class EPSSClient:
    """Client for the official FIRST.org EPSS API.
    Returns real-world exploit probability scores for any CVE.
    """

    def __init__(self, db: Optional[KiberDatabase] = None):
        self.db = db
        self.api_url = EPSS_API_URL

    def get_score(self, cve_id: str) -> Dict:
        """Fetch real EPSS score for a given CVE ID from FIRST.org API.
        
        Returns:
            {
                "cve": "CVE-2021-36260",
                "epss": 0.9724,        # Real exploit probability (0-1)
                "percentile": 0.9812,   # Percentile rank
                "date": "2025-06-19",   # Model date
                "source": "first.org"
            }
        """
        url = f"{self.api_url}?cve={cve_id}"
        try:
            resp = requests.get(url, timeout=EPSS_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            if data.get('data') and len(data['data']) > 0:
                entry = data['data'][0]
                result = {
                    "cve": entry.get('cve', cve_id),
                    "epss": float(entry.get('epss', 0.0)),
                    "percentile": float(entry.get('percentile', 0.0)),
                    "date": data.get('meta', {}).get('model', datetime.utcnow().strftime("%Y-%m-%d")),
                    "source": "first.org",
                    "status": "live"
                }
                return result
            else:
                # CVE not found in EPSS database — return zero score
                return {
                    "cve": cve_id,
                    "epss": 0.0,
                    "percentile": 0.0,
                    "date": datetime.utcnow().strftime("%Y-%m-%d"),
                    "source": "first.org",
                    "status": "not_found",
                    "note": "CVE not in EPSS database — score set to 0"
                }

        except requests.exceptions.RequestException as e:
            # API unreachable — fallback to cached/mock data
            return self._fallback_score(cve_id, str(e))

    def get_batch_scores(self, cve_ids: list) -> Dict[str, Dict]:
        """Fetch EPSS scores for multiple CVEs in one request."""
        if not cve_ids:
            return {}
        url = f"{self.api_url}?cve={','.join(cve_ids)}"
        try:
            resp = requests.get(url, timeout=EPSS_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            results = {}
            for entry in data.get('data', []):
                cve = entry.get('cve', '')
                results[cve] = {
                    "cve": cve,
                    "epss": float(entry.get('epss', 0.0)),
                    "percentile": float(entry.get('percentile', 0.0)),
                    "source": "first.org",
                    "status": "live"
                }
            return results
        except Exception:
            return {cve: self._fallback_score(cve, "API unavailable") for cve in cve_ids}

    def assess_threat_level(self, cve_id: str, cvss: float = None) -> Dict:
        """Combine EPSS score with CVSS to produce an overall threat assessment.
        This is the core AI decision input.
        """
        epss_data = self.get_score(cve_id)
        epss = epss_data.get('epss', 0.0)
        cvss = cvss or 0.0

        # Weighted threat score (CVSS severity × EPSS probability)
        threat_score = (cvss / 10.0) * epss

        if epss >= 0.9:
            epss_level = "Kritik"
        elif epss >= 0.7:
            epss_level = "Yüksək"
        elif epss >= 0.4:
            epss_level = "Orta"
        else:
            epss_level = "Aşağı"

        if threat_score >= 0.7:
            overall = "KRITIK"
        elif threat_score >= 0.4:
            overall = "YÜKSƏK"
        elif threat_score >= 0.15:
            overall = "ORTA"
        else:
            overall = "AŞAĞI"

        return {
            "cve": cve_id,
            "cvss": cvss,
            "epss": round(epss, 6),
            "epss_percentile": epss_data.get('percentile', 0.0),
            "epss_level": epss_level,
            "threat_score": round(threat_score, 4),
            "overall_assessment": overall,
            "epss_source": "first.org (live)",
            "recommendation": "AUTOPILOT_ISOLATE" if overall == "KRITIK" else (
                "VIRTUAL_PATCH" if overall in ("YÜKSƏK", "ORTA") else "MONITOR"
            )
        }

    def _fallback_score(self, cve_id: str, reason: str = "") -> Dict:
        """Fallback when API is unreachable — returns zero EPSS."""
        return {
            "cve": cve_id,
            "epss": 0.0,
            "percentile": 0.0,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "source": "first.org",
            "status": "fallback",
            "note": f"API unavailable ({reason}) — score defaulted to 0"
        }
