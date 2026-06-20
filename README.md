# 🇦🇿 Milli Kiber-DNT — Qapalı Dövrəli Kiber Müdafiə Platforması

> **National Cyber-DNT: Closed-Loop Cyber Defense Platform for Azerbaijan's Critical Infrastructure**

[![Demo](https://img.shields.io/badge/Live%20Demo-HTML-blue?style=flat-square)](milli-kiber-dnt-demo.html)
[![Technova](https://img.shields.io/badge/Technova-2026-8b5cf6?style=flat-square)](https://technova.az)
[![AIIRO](https://img.shields.io/badge/AIIRO-2026-10b981?style=flat-square)](https://aiiro.az)

---

## 📋 Overview

**Milli Kiber-DNT** is a high-fidelity proof-of-concept demonstration of an autonomous closed-loop cyber defense platform, purpose-built for Azerbaijan's national critical infrastructure. It simulates the complete **detect → analyze → remediate → verify → learn** lifecycle against realistic zero-day attack scenarios.

The demo is a single self-contained HTML file — open it in any modern browser, no server required.

## 🎯 Key Features

### Closed-Loop Core (5 Phases)

| # | Phase | Description |
|---|-------|-------------|
| 01 | **Kəşfiyyat & Kəşf** (Discovery) | Continuous asset discovery + Trend Micro ZDI integration + Micro-scanning |
| 02 | **AI Qərar Verici** (Decision) | CVSS/EPSS cross-referencing, business criticality scoring, AI confidence with transparent logic |
| 03 | **SOAR & Remediasiya** (Remediation) | Autopilot network isolation + WAF/IPS virtual patching with live rule generation |
| 04 | **BAS Doğrulama** (Verification) | Breach & Attack Simulation — exploit attempt blocked/failed visualization |
| 05 | **İnsident Öyrənmə** (Learning) | Automated LLM post-mortem report + "Genetik Yaddaş" knowledge base with instant recall |

### Attack Scenarios

- **Hikvision Smart City Camera Zero-Day RCE** — CVSS 9.8, 1,247 cameras across Baku
- **Absheron Water Treatment Station PLC Vulnerability** — CVSS 8.6, Siemens S7-1200 heap overflow
- **National Data Center Kubernetes RBAC Bypass** — CVSS 7.2, cluster-wide privilege escalation
- **Random Threat Generator** — Dynamic scenarios from a pool (Baku Metro SCADA, SOCAR oil platform, Central Bank SWIFT, etc.)

### Interactive Controls

- One-click simulation with real-time animated 5-stage core loop
- Simulation speed control (Yavaş / Normal / Sürətli)
- Pause / Step-through for presentations
- Color-coded live event log
- Toast notifications for key events
- Print-ready post-mortem reports

## 🚀 Getting Started

```bash
# Clone the repository
git clone https://github.com/chichakabdullayeva/-technova-aiiro2026.git

# Open the demo directly (no server needed)
open milli-kiber-dnt-demo.html
# OR just double-click the file in your file manager
```

**Requirements:** Any modern web browser (Chrome, Firefox, Edge, Safari). No installation, no server, no dependencies.

## 🏗️ Architecture

![Architecture Diagram](architecture-diagram.svg)

The platform follows a layered architecture:

1. **Input Layer** — ZDI threat intelligence, asset discovery, micro-scanning
2. **Core Loop** — 5-phase closed defense cycle
3. **Output Layer** — Isolation, patching, BAS verification, reports, knowledge base
4. **Feedback Loop** — Continuous learning feeds back into the discovery phase

## 🛡️ Technical Stack

- **HTML5** + **Tailwind CSS** (via CDN) — Professional dark cybersecurity UI
- **Chart.js** (via CDN) — AI confidence gauge visualization
- **Vanilla JavaScript** — Simulation engine, animation, data management
- **Canvas API** — Animated matrix/grid cyber background
- **CSS3 Animations** — Glass-morphism, glow effects, smooth transitions

## 🇦🇿 Azerbaijani Language

All interface text, labels, logs, and reports are in Azerbaijani. The platform is designed for presentation to Azerbaijani government and enterprise stakeholders.

## 📄 Project Files

| File | Description |
|------|-------------|
| `milli-kiber-dnt-demo.html` | Complete self-contained demo (72 KB) |
| `architecture-diagram.svg` | Architecture diagram |
| `problem-description.md` | Problem statement and background |
| `ethical-declaration.md` | Ethical principles and responsible use |

## 🤝 License & Ethics

This project is an **educational proof-of-concept** for cybersecurity defense demonstration. It is not intended for offensive use. See [ethical-declaration.md](ethical-declaration.md) for the full ethical framework.

---

<p align="center">
  <b>Technova & AIIRO 2026</b><br>
  <sub>Baku, Azerbaijan</sub>
</p>
