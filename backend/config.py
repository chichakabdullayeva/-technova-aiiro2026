"""Milli Kiber-DNT — Backend Configuration"""

import os

# Network scanning
TARGET_SUBNET = os.getenv("KIBER_DNT_SUBNET", "10.10.40.0/24")
SCAN_TIMEOUT = int(os.getenv("KIBER_DNT_SCAN_TIMEOUT", "120"))
NMAP_ARGS = os.getenv("KIBER_DNT_NMAP_ARGS", "-p 80,443,554,8080 -sV --script=banner --host-timeout 30s")

# EPSS API
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_TIMEOUT = int(os.getenv("KIBER_DNT_EPSS_TIMEOUT", "10"))

# SOAR / WAF
SNORT_RULES_DIR = os.getenv("KIBER_DNT_SNORT_RULES_DIR", "/etc/snort/rules/local.rules")
SURICATA_RULES_DIR = os.getenv("KIBER_DNT_SURICATA_RULES_DIR", "/etc/suricata/rules/local.rules")
MODSECURITY_DIR = os.getenv("KIBER_DNT_MODSECURITY_DIR", "/etc/modsecurity/crs/custom")
DEPLOY_WAF_RULES = os.getenv("KIBER_DNT_DEPLOY_RULES", "false").lower() == "true"

# BAS
BAS_TIMEOUT = int(os.getenv("KIBER_DNT_BAS_TIMEOUT", "5"))

# LLM
OLLAMA_BASE_URL = os.getenv("KIBER_DNT_OLLAMA_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("KIBER_DNT_LLM_MODEL", "llama3.1:8b")

# Database
DB_PATH = os.getenv("KIBER_DNT_DB_PATH", "data/kiber_dnt.db")

# WebSocket
WS_HEARTBEAT = int(os.getenv("KIBER_DNT_WS_HEARTBEAT", "30"))

# Authentication
AUTH_USERNAME = os.getenv("KIBER_DNT_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("KIBER_DNT_PASSWORD", "kiberdnt2026")
AUTH_SECRET_TOKEN = os.getenv("KIBER_DNT_SECRET_TOKEN", "kiber-dnt-demo-token-2026")
AUTH_ENABLED = os.getenv("KIBER_DNT_AUTH_ENABLED", "true").lower() == "true"

# Logging
LOG_LEVEL = os.getenv("KIBER_DNT_LOG_LEVEL", "INFO")
