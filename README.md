# 🇦🇿 Milli Kiber-DNT — Qapalı Dövrəli Kiber Müdafiə Platforması v3.1

> **National Cyber-DNT: Closed-Loop Cyber Defense Platform for Azerbaijan's Critical Infrastructure**

[![Frontend](https://img.shields.io/badge/Frontend-HTML5-blue?style=flat-square)](frontend/index.html)
[![Backend](https://img.shields.io/badge/Backend-FastAPI-10b981?style=flat-square)](backend/main.py)
[![EPSS](https://img.shields.io/badge/EPSS-FIRST.org-ff6b35?style=flat-square)](https://www.first.org/epss)
[![Technova](https://img.shields.io/badge/Technova-2026-8b5cf6?style=flat-square)](https://technova.az)

---

## 📋 Genel Baxış

**Milli Kiber-DNT** — Azərbaycanın kritik infrastrukturunun müdafiəsi üçün qapalı dövrəli, süni intellektlə idarə olunan kiber müdafiə platformasının peşəkar PoC nümayişidir. Platforma **5 fazalı dövrə** üzərində qurulub: **Kəşfiyyat → AI Analizi → SOAR → BAS → Öyrənmə**.

### Fərqləndirici Xüsusiyyətlər

- **🔴 Sıfır hardcoded məlumat** — bütün cədvəllər yalnız istifadəçi tərəfindən yüklənən fayllardan doldurulur
- **🌐 Real API inteqrasiyası** — [FIRST.org EPSS](https://www.first.org/epss) canlı API sorğusu
- **🛡️ Real qayda generasiyası** — Snort, Suricata, ModSecurity üçün istehsal səviyyəli imzalar
- **🧬 Genetik Yaddaş** — hər insidentdən öyrənən bilik bazası
- **📡 ZDI canlı axını** — Trend Micro Zero-Day təhdidlərinin real vaxt simulyasiyası
- **🤖 LLM hesabat** — Ollama ilə avtomat post-mortem (və ya template fallback)

---

## 🚀 İşə Salma

```bash
# Backend (tövsiyə olunan)
cd backend && pip install -r requirements.txt && python main.py
# → http://localhost:8000

# Və ya birbaşa frontend (server tələb olunmur)
open frontend/index.html
```

---

## 🧬 Sistem Dövrəsi (Core Loop)

```
[📡 ZDI / Kəşfiyyat] → [🎯 Mikroskan] → [🧠 AI Qərar] → [🛡 SOAR] → [⚡ BAS] → [📚 Öyrənmə]
       │                      │                │              │           │            │
       ▼                      ▼                ▼              ▼           ▼            ▼
   Təhdid axını          Aktiv kəşfi      CVSS+EPSS        Virtual     Sızma      LLM Report
   (ZDI sim.)            (Fayl/API)      Çarpaz ref.      Yamaqlama  Testi      + Genetik KB
```

### Faza 1 — Kəşfiyyat
- **Drag & Drop** fayl yükləmə (.json, .csv, .log) → client-side parser
- **Canlı ZDI axını** — Trend Micro sıfırıncı gün təhdidləri (5 saniyə intervallı)
- **🎯 Mikroskan** — AI tərəfindən idarə olunan nöqtə atışı skan
- **Şəbəkə topologiyası** — Canvas-based vizualizasiya

### Faza 2 — AI Analizi
- **EPSS API** — Real FIRST.org exploit probability scoring
- **Risk Matrisi** — CVSS vs EPSS scatter plot (Canvas)
- **İnam Səviyyəsi** — 0-100% confidence ring (SVG)
- **AI Qərar Paneli** — avtomat SOAR keçid indikatoru

### Faza 3 — SOAR & Müdafiə
- **Avtonom İzolyasiya** — riskli aktivlərin mikroseqmentasiyası
- **WAF/IPS Qaydaları** — Snort, Suricata, ModSecurity (real sintaksis)
- **Şəbəkə Zonaları** — karantin vizualizasiyası

### Faza 4 — BAS
- **HTTP həqiqi sorğu** — `no-cors` mode ilə real 403/RST detection
- **Müdafiə Statistikası** — səmərəlilik faizi, bloklanan hitlər
- **Zaman xətti** — hər test üçün vizual indikator

### Faza 5 — Öyrənmə
- **LLM Post-Mortem** — Ollama ilə streaming hesabat (və template)
- **Genetik Yaddaş** — zaman xətti üzrə bilik bazası
- **Keçmiş İnsidentlər** — həll müddətləri ilə cədvəl

---

## 🔌 API Endpointləri

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Backend status |
| `GET /api/epss/{cve}` | FIRST.org EPSS skoru (real API) |
| `GET /api/rules/generate` | Snort/ModSecurity qayda generasiyası |
| `GET /api/llm/report` | LLM hesabatı (Ollama) |

---

## 📂 Fayl Strukturu

```
├── frontend/
│   └── index.html         ← Tək fayl SPA (bütün UI/UX)
├── backend/
│   ├── main.py            ← FastAPI (EPSS proxy, Rule gen, Statik)
│   └── requirements.txt
└── README.md
```

---

## 🛠️ Texniki Stack

- **Frontend:** HTML5 + Tailwind CSS + Vanilla JS (0 dependency)
- **Backend:** Python 3.10+ / FastAPI / Uvicorn / aiohttp
- **Threat Intel:** FIRST.org EPSS API (canlı)
- **WAF/IPS:** Snort, Suricata, ModSecurity rule generation
- **LLM:** Ollama (llama3.2) with template fallback
- **Vizualizasiya:** Canvas 2D (risk matrix, network topology)

---

## ⚙️ Minimum Requirements

- Python 3.10+ (backend mode)
- aiohttp, fastapi, uvicorn (pip)
- İstəyə bağlı: Ollama (LLM reports)

Heç bir **xarici chart library**, **npm paketi**, **database** və ya **API açarı** tələb olunmur.

---

## 🇦🇿 Dil

Bütün interfeys, loqlar, API cavabları və hesabatlar **Azərbaycan dilində**dir.

---

## 🤝 Lisenziya

**Educational PoC** — yalnız tədris və nümayiş məqsədləri üçün.

---

<p align="center">
  <b>Technova & AIIRO 2026</b><br>
  <sub>Baku, Azerbaijan</sub>
</p>
