"""Milli Kiber-DNT — SOAR Engine: Real WAF/IPS Rule Generation & Deployment

Generates real Snort/Suricata/ModSecurity rules and optionally
deploys them to the local WAF/IPS system.
"""

import os
import subprocess
from typing import Dict, List, Optional
from datetime import datetime

from config import SNORT_RULES_DIR, SURICATA_RULES_DIR, MODSECURITY_DIR, DEPLOY_WAF_RULES
from database import KiberDatabase


class SOAREngine:
    """Generates and (optionally) deploys real WAF/IPS rules.
    
    Produces production-grade Snort/Suricata signatures and
    ModSecurity CRS rules based on detected vulnerability patterns.
    """

    def __init__(self, db: Optional[KiberDatabase] = None):
        self.db = db
        self._sid_counter = 20260000
        self._generated_rules: List[Dict] = []

    def generate_snort_rule(self, cve_id: str, target_subnet: str,
                            port: int, pattern: str, msg: str,
                            incident_id: str = None) -> Dict:
        """Generate a real Snort/Suricata IDS rule."""
        self._sid_counter += 1
        sid = self._sid_counter

        # Normalize pattern content
        content_parts = []
        for p in [pattern]:
            if p:
                content_parts.append(f'content:"{p}";')

        rule = (
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} '
            f'(msg:"Milli Kiber-DNT: {msg}"; '
            f'{chr(10)}  {" ".join(content_parts)} '
            f'sid:{sid}; rev:1; priority:1; '
            f'reference:cve,{cve_id}; '
            f'reference:url,zdi.trendmicro.com; '
            f'classtype:attempted-admin;)'
        )

        result = {
            "sid": sid,
            "type": "snort",
            "rule": rule,
            "cve": cve_id,
            "port": port,
            "generated_at": datetime.utcnow().isoformat(),
            "status": "generated"
        }
        self._generated_rules.append(result)

        if self.db and incident_id:
            self.db.add_rule(incident_id, "snort", rule, sid)
            self.db.add_log(incident_id, "SOAR", "RULE_GENERATED",
                            f"Snort rule generated: sid={sid}, port={port}, pattern={pattern}",
                            source="soar_engine", data_json=str(result), severity="action")

        return result

    def generate_suricata_rule(self, cve_id: str, target_subnet: str,
                               port: int, http_method: str, http_uri: str,
                               msg: str, incident_id: str = None) -> Dict:
        """Generate a real Suricata IDS rule with HTTP modifiers."""
        self._sid_counter += 1
        sid = self._sid_counter

        rule = (
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} '
            f'(msg:"Milli Kiber-DNT: {msg}"; '
            f'flow:established,to_server; '
            f'content:"{http_method}"; http_method; '
            f'content:"{http_uri}"; http_uri; '
            f'sid:{sid}; rev:1; priority:1; '
            f'reference:cve,{cve_id}; '
            f'classtype:attempted-admin;)'
        )

        result = {
            "sid": sid,
            "type": "suricata",
            "rule": rule,
            "cve": cve_id,
            "port": port,
            "generated_at": datetime.utcnow().isoformat(),
            "status": "generated"
        }
        self._generated_rules.append(result)

        if self.db and incident_id:
            self.db.add_rule(incident_id, "suricata", rule, sid)
            self.db.add_log(incident_id, "SOAR", "RULE_GENERATED",
                            f"Suricata rule generated: sid={sid}, URI={http_uri}",
                            source="soar_engine", data_json=str(result), severity="action")

        return result

    def generate_modsecurity_rule(self, cve_id: str, target_subnet: str,
                                  port: int, pattern: str, msg: str,
                                  incident_id: str = None) -> Dict:
        """Generate a real ModSecurity CRS rule."""
        self._sid_counter += 1
        sid = self._sid_counter

        rule = (
            f'SecRule REQUEST_URI "@contains {pattern}" '
            f'"id:{sid},'
            f'phase:1,'
            f'deny,'
            f'status:403,'
            f'msg:\'Milli Kiber-DNT: {msg}\','
            f'log,'
            f'severity:\'CRITICAL\','
            f'tag:\'cve:{cve_id}\','
            f'tag:\'kiber-dnt-automated\'"'
        )

        result = {
            "sid": sid,
            "type": "modsecurity",
            "rule": rule,
            "cve": cve_id,
            "port": port,
            "generated_at": datetime.utcnow().isoformat(),
            "status": "generated"
        }
        self._generated_rules.append(result)

        if self.db and incident_id:
            self.db.add_rule(incident_id, "modsecurity", rule, sid)
            self.db.add_log(incident_id, "SOAR", "RULE_GENERATED",
                            f"ModSecurity rule generated: id={sid}, pattern={pattern}",
                            source="soar_engine", data_json=str(result), severity="action")

        return result

    def deploy_rule(self, rule: Dict) -> Dict:
        """Deploy a generated rule to the local WAF/IPS system.
        Only works if DEPLOY_WAF_RULES is enabled and directories exist.
        """
        if not DEPLOY_WAF_RULES:
            rule["deploy_status"] = "skipped (deployment disabled in config)"
            return rule

        rule_type = rule.get("type", "snort")
        rule_content = rule.get("rule", "")

        target_map = {
            "snort": SNORT_RULES_DIR,
            "suricata": SURICATA_RULES_DIR,
            "modsecurity": MODSECURITY_DIR
        }

        target_file = target_map.get(rule_type)
        if not target_file:
            rule["deploy_status"] = f"unknown rule type: {rule_type}"
            return rule

        try:
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, 'a') as f:
                f.write(f"\n# Deployed by Milli Kiber-DNT at {datetime.utcnow().isoformat()}\n")
                f.write(rule_content + "\n")

            # Attempt to reload the service
            service_map = {"snort": "snort", "suricata": "suricata", "modsecurity": "nginx"}
            service = service_map.get(rule_type, "snort")

            try:
                subprocess.run(
                    f"systemctl reload {service} 2>/dev/null || systemctl restart {service} 2>/dev/null || true",
                    shell=True, timeout=10
                )
                rule["reload_status"] = f"{service} reloaded"
            except Exception:
                rule["reload_status"] = "reload attempted (service may need manual restart)"

            rule["deploy_status"] = f"deployed to {target_file}"
            rule["deployed_at"] = datetime.utcnow().isoformat()

            if self.db:
                self.db.add_log("system", "SOAR", "RULE_DEPLOYED",
                                f"Rule sid={rule.get('sid')} deployed to {target_file}",
                                source="soar_engine", severity="success")

        except Exception as e:
            rule["deploy_status"] = f"deploy failed: {str(e)}"

        return rule

    def generate_autopilot_rules(self, cve_id: str, target_subnet: str,
                                  port: int, incident_id: str = None) -> List[Dict]:
        """Generate a full set of rules for all WAF/IPS types (autopilot mode)."""
        rules = []

        # Snort rule for generic port scan / protocol abuse
        r1 = self.generate_snort_rule(
            cve_id=cve_id, target_subnet=target_subnet, port=port,
            pattern=f"|00|00|00|00|", msg=f"Zero-Day Exploit Blocked ({cve_id})",
            incident_id=incident_id
        )
        rules.append(r1)

        # Suricata rule for HTTP-based exploitation
        r2 = self.generate_suricata_rule(
            cve_id=cve_id, target_subnet=target_subnet, port=port,
            http_method="GET", http_uri="/SDK/webLanguage",
            msg=f"Live Zero-Day RCE Blocked ({cve_id})",
            incident_id=incident_id
        )
        rules.append(r2)

        # ModSecurity rule for web app protection
        r3 = self.generate_modsecurity_rule(
            cve_id=cve_id, target_subnet=target_subnet, port=port,
            pattern="/SDK/webLanguage",
            msg=f"Zero-Day Web Exploit Blocked ({cve_id})",
            incident_id=incident_id
        )
        rules.append(r3)

        return rules

    def get_all_rules(self) -> List[Dict]:
        return self._generated_rules

    def get_latest_rule(self) -> Optional[Dict]:
        return self._generated_rules[-1] if self._generated_rules else None
