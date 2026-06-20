"""Milli Kiber-DNT — BAS (Breach & Attack Simulation) Engine

Sends real HTTP exploit payloads to target assets to verify
that WAF/IPS virtual patches are actively blocking attacks.
"""

import time
import requests
import sys, os
from typing import Dict, Optional
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from config.settings import BAS_TIMEOUT
from services.logging.database import KiberDatabase


class BASEngine:
    """Breach & Attack Simulation Engine.
    
    After a virtual patch is deployed, this engine sends real
    exploit payloads to the target to verify the patch is working.
    """

    def __init__(self, db: Optional[KiberDatabase] = None):
        self.db = db
        self._results = []

    def verify_patch_http(self, target_ip: str, port: int = 80,
                          incident_id: str = None) -> Dict:
        """Send a simulated exploit payload via HTTP to verify WAF blocking.
        
        The payload attempts to exploit common vulnerability patterns:
        - Path traversal
        - Command injection
        - Configuration file access
        
        Expected behavior with active WAF: 403 Forbidden or 406 Not Acceptable
        Expected behavior without WAF: 200 OK with sensitive content
        """
        payloads = [
            # Path traversal attempt
            {"url": f"http://{target_ip}:{port}/SDK/webLanguage",
             "data": {"LanguageString": "../../../../etc/passwd"}},
            # Config file access
            {"url": f"http://{target_ip}:{port}/config/getpage",
             "data": {"page": "../../../etc/shadow"}},
            # Command injection attempt
            {"url": f"http://{target_ip}:{port}/cgi-bin/cmd",
             "data": {"cmd": "cat /etc/passwd"}},
        ]

        headers = {
            "User-Agent": "Milli-Kiber-DNT-BAS-Engine/1.0",
            "X-Cyber-Defense": "verification-scan"
        }

        results = []
        all_blocked = True

        for payload in payloads:
            start = time.time()
            try:
                resp = requests.post(
                    payload["url"],
                    json=payload["data"],
                    headers=headers,
                    timeout=BAS_TIMEOUT
                )
                latency_ms = round((time.time() - start) * 1000, 2)

                # WAF active if status is 403, 406, or connection refused
                if resp.status_code in (403, 406):
                    result_text = "BLOCKED"
                    blocked = True
                elif resp.status_code in (200, 301, 302):
                    # WAF bypassed — check if sensitive data returned
                    if "root:" in resp.text or "shadow" in resp.text.lower():
                        result_text = "BYPASSED_SENSITIVE_DATA"
                        blocked = False
                    else:
                        result_text = "BYPASSED"
                        blocked = False
                else:
                    result_text = f"UNKNOWN_STATUS_{resp.status_code}"
                    blocked = False

            except requests.exceptions.ConnectionError:
                latency_ms = round((time.time() - start) * 1000, 2)
                result_text = "BLOCKED (Connection Refused)"
                blocked = True
            except requests.exceptions.Timeout:
                latency_ms = BAS_TIMEOUT * 1000
                result_text = "BLOCKED (Timeout)"
                blocked = True
            except Exception as e:
                latency_ms = round((time.time() - start) * 1000, 2)
                result_text = f"ERROR: {str(e)[:50]}"
                blocked = False

            if not blocked:
                all_blocked = False

            entry = {
                "target_ip": target_ip,
                "port": port,
                "payload_url": payload["url"],
                "status_code": resp.status_code if 'resp' in dir() else 0,
                "result": result_text,
                "latency_ms": latency_ms,
                "tested_at": datetime.utcnow().isoformat()
            }
            results.append(entry)

            if self.db and incident_id:
                self.db.add_bas_result(
                    incident_id=incident_id,
                    target_ip=target_ip,
                    status_code=entry["status_code"],
                    result=result_text,
                    latency_ms=latency_ms
                )
                self.db.add_log(
                    incident_id, "BAS", "VERIFICATION",
                    f"Target {target_ip}:{port} → {result_text} ({latency_ms}ms)",
                    source="bas_engine",
                    data_json=str(entry),
                    severity="success" if blocked else "threat"
                )

        summary = {
            "target": f"{target_ip}:{port}",
            "total_tests": len(payloads),
            "blocked_count": sum(1 for r in results if "BLOCKED" in r["result"]),
            "bypassed_count": sum(1 for r in results if "BYPASS" in r["result"]),
            "all_blocked": all_blocked,
            "overall_result": "PROTECTED" if all_blocked else "COMPROMISED",
            "tests": results,
            "completed_at": datetime.utcnow().isoformat()
        }

        self._results.append(summary)

        if self.db and incident_id:
            sev = "success" if all_blocked else "threat"
            self.db.add_log(
                incident_id, "BAS", "VERIFICATION_COMPLETE",
                f"BAS overall: {summary['overall_result']} — {summary['blocked_count']}/{summary['total_tests']} blocked",
                source="bas_engine", data_json=str(summary), severity=sev
            )

        return summary

    def verify_patch_rtsp(self, target_ip: str, port: int = 554,
                          incident_id: str = None) -> Dict:
        """Verify virtual patch for RTSP protocol (Hikvision cameras).
        Attempts a connection to RTSP port and checks if blocked.
        """
        import socket
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(BAS_TIMEOUT)
            result = sock.connect_ex((target_ip, port))
            sock.close()

            latency_ms = round((time.time() - start) * 1000, 2)

            if result != 0:
                # Port closed / filtered = WAF blocking
                status = "BLOCKED"
                blocked = True
            else:
                status = "OPEN (patch may not be active)"
                blocked = False

        except Exception as e:
            latency_ms = round((time.time() - start) * 1000, 2)
            status = f"BLOCKED (Socket Error)"
            blocked = True

        result = {
            "target": f"{target_ip}:{port}",
            "protocol": "RTSP",
            "result": status,
            "latency_ms": latency_ms,
            "overall_result": "PROTECTED" if blocked else "COMPROMISED"
        }

        self._results.append(result)

        if self.db and incident_id:
            self.db.add_bas_result(incident_id, target_ip, 0, status, latency_ms)

        return result

    def run_full_bas(self, target_ip: str, ports: list = None,
                     incident_id: str = None) -> Dict:
        """Run full BAS verification across all relevant ports."""
        ports = ports or [80, 443, 554, 8080]
        all_results = {}

        for port in ports:
            if port == 554:
                all_results[str(port)] = self.verify_patch_rtsp(
                    target_ip, port, incident_id)
            else:
                all_results[str(port)] = self.verify_patch_http(
                    target_ip, port, incident_id)

        protected = all(
            r.get("overall_result") == "PROTECTED"
            for r in all_results.values()
        )

        return {
            "target": target_ip,
            "ports_tested": ports,
            "all_protected": protected,
            "overall": "PROTECTED ✓" if protected else "ACTION REQUIRED ⚠",
            "details": all_results
        }

    def get_latest_result(self) -> Optional[Dict]:
        return self._results[-1] if self._results else None
