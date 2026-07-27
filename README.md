# ⚡ NetGuard — Real-Time Network Security Monitor

A Windows standalone application for real-time network monitoring, threat detection, and parental controls.

---

## 📁 Project Structure

```
netguard/
├── backend/
│   ├── main.py              # FastAPI server - all REST endpoints
│   ├── network_monitor.py   # psutil-based network monitoring
│   ├── threat_intel.py      # AbuseIPDB, OTX, URLhaus, ThreatFox, GSB integrations
│   ├── gemini_ai.py         # Google Gemini AI integration
│   ├── database.py          # SQLite storage for alerts, logs, blocked apps
│   └── parental_control.py  # App/domain blocking + safe mode
├── frontend/
│   └── main_window.py       # PyQt5 dark-theme desktop UI
├── data/                    # SQLite database (auto-created)
├── logs/                    # Log files
├── config.json              # API keys configuration
├── requirements.txt         # Python dependencies
├── launcher.py              # Entry point for .exe build
├── netguard.spec            # PyInstaller build spec
└── start_netguard.bat       # Easy Windows launcher script
```

---

## 🚀 Quick Start (Development Mode)

### 1. Prerequisites
- Python 3.9 or higher
- Windows 10/11 (Linux/Mac work too, with reduced OS features)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API Keys (Optional but Recommended)
Copy `config.json.example` to `config.json` if you want JSON config, or use `.env` for secrets:

| API | Free Tier | URL |
|-----|-----------|-----|
| AbuseIPDB | 1,000 checks/day | https://www.abuseipdb.com/register |
| AlienVault OTX | Unlimited | https://otx.alienvault.com/api |
| Google Safe Browsing | Free tier | https://console.cloud.google.com |
| Google Gemini | Free tier | https://aistudio.google.com/app/apikey |

> **Without API keys**: live monitoring still runs, but threat reputation falls back to simulated scoring. Demo startup alerts are optional and controlled by `settings.enable_demo_alerts` in `config.json`.

### 4. Start the Application

**Option A: Easy launcher (recommended)**
```
Double-click: start_netguard.bat
```

**Option B: Manual start**
```bash
# Terminal 1 — Start backend
cd backend
python main.py

# Terminal 2 — Start frontend  
cd frontend
python main_window.py
```

The backend API runs at: `http://127.0.0.1:8765`  
API docs available at: `http://127.0.0.1:8765/docs`

---

## 📦 Build Windows Executable (.exe)

### Requirements
```bash
pip install pyinstaller
```

### Build Steps
```bash
# From project root directory
pyinstaller netguard.spec

# Or single-command build:
pyinstaller --noconfirm --onedir --windowed \
  --add-data "backend;backend" \
  --add-data "config.json;." \
  --hidden-import uvicorn \
  --hidden-import psutil \
  launcher.py --name NetGuard
```

### Output
The built executable will be in:
```
dist/NetGuard/NetGuard.exe
```

Copy the entire `dist/NetGuard/` folder to distribute the app.

---

## 🎯 Features

### 📊 Dashboard
- Real-time bandwidth graph (upload/download KB/s)
- Live stat cards: connections, alerts, blocked apps
- Recent alerts panel with severity indicators

### ⚙️ Processes Tab
- Per-process network usage (upload/download)
- Active connection count per app
- Block/unblock apps from internet access
- Filter processes by name

### 🚨 Alerts Tab
- Real-time threat alerts with severity levels (High/Medium/Low)
- Click any alert to see **AI-powered explanation** from Gemini
- Risk scoring from 0-10 combining multiple threat sources

### 🔍 Threat Checker Tab
- Manually check any IP address
- Check URLs for phishing/malware
- Ask the AI assistant about security events

### 👪 Parental Controls
- Safe Mode (auto-blocks malicious domains)
- Block specific domains
- View and manage blocked applications
- Activity logging

### 📋 Activity Logs
- Full history of all actions taken
- Timestamps for every event

---

## 🧠 Risk Scoring System

NetGuard combines multiple threat intelligence sources into a unified 0-10 risk score:

| Score Range | Severity | Action |
|-------------|----------|--------|
| 0-4.9 | Low | No alert |
| 5-6.9 | Medium | Usually no automatic malicious-IP alert |
| 7-8.9 | High | Alert + review |
| 9-10 | Critical | High-severity alert; no automatic Safe Mode block for malicious IPs yet |

**Score calculation:**
- AbuseIPDB confidence score (60% weight)
- AlienVault OTX pulse count (40% weight)

---

## ⚙️ Backend API Reference

All endpoints available at `http://127.0.0.1:8765/api/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/bandwidth` | Current upload/download speeds |
| GET | `/connections` | Active network connections |
| GET | `/processes` | Per-process network usage |
| GET | `/alerts` | Recent threat alerts |
| POST | `/check/ip/{ip}` | Check IP reputation |
| POST | `/check/url` | Check URL safety |
| POST | `/processes/block` | Block an app |
| POST | `/processes/unblock` | Unblock an app |
| POST | `/parental/domains/block` | Block a domain |
| POST | `/parental/safemode` | Toggle safe mode |
| POST | `/gemini/explain` | Ask AI assistant |
| GET | `/stats` | Dashboard statistics |
| GET | `/logs` | Activity logs |

Full interactive API docs: `http://127.0.0.1:8765/docs`

---

## 🔐 Permissions Note

Some features require elevated privileges:
- **Packet capture** (scapy): Run as Administrator
- **Process connection listing**: Run as Administrator for full data
- **Actual OS-level app blocking**: Requires netsh or Windows Firewall API

For demo/testing purposes, the app works without admin rights using simulated data.

---

## ⚠️ Important Notes

1. **This is a monitoring/detection tool** — actual network blocking at the OS level requires Windows Firewall API integration and administrator privileges
2. **For production use**, consider running the backend as a Windows Service
3. **API rate limits** — free tiers have limits; the app caches results to minimize API calls
4. **Simulated scoring fallback** — without API keys, IP/URL reputation uses deterministic mock scoring (same IP always gets the same score)
5. **Demo startup alerts** — set `settings.enable_demo_alerts` to `true` only if you want sample alerts to appear immediately at launch

---

## 🛠️ Troubleshooting

**"Backend Offline" error**
→ Start `backend/main.py` first, wait 3 seconds, then launch frontend

**"psutil not available"**
→ `pip install psutil`

**"pyqtgraph not available" (no charts)**
→ `pip install pyqtgraph` — charts will be disabled but everything else works

**ImportError for PyQt5**
→ `pip install PyQt5==5.15.10`

**Permission denied errors**
→ Run as Administrator for full network monitoring capabilities

---

## 📝 License

MIT License — Free to use, modify, and distribute.
