# NetGuard — Complete Project & Viva Guide

> A mentor-style, beginner-friendly walkthrough of the **entire** NetGuard project so you can confidently explain every part to your guide and examiners. Everything here is based on the **actual code** in this project.

---

## PART 1: PROJECT OVERVIEW

### 1. What is this project?
**NetGuard** is a **real-time network security and parental-control monitor for Windows**. It is a desktop application that watches every network connection your computer makes, checks whether those connections are safe using global threat-intelligence databases, shows live internet-speed usage per application, and lets a parent block apps and websites (instantly, by category, or on a schedule). It also has a **built-in AI assistant** (running locally on the machine) that explains security alerts in plain English.

### 2. What problem does it solve?
Normal users cannot see what their computer is talking to on the internet, cannot tell if a connection is dangerous, and have no easy way to control which apps/sites are allowed. NetGuard makes all of this **visible and controllable** in one simple dashboard.

### 3. Why was it developed?
To give a **home user or parent** an all-in-one tool that combines three things normally needing separate software: (a) network/threat monitoring, (b) bandwidth/data-usage tracking, and (c) parental controls — with AI-powered explanations so non-experts understand the alerts.

### 4. Target users
Home users, parents, students, and small offices on Windows who want visibility and basic control over network activity without enterprise-grade complexity.

### 5. Main objectives
- Monitor active network connections in real time.
- Detect malicious IPs/domains using multiple threat-intelligence sources.
- Track per-application bandwidth usage.
- Block applications and websites (manual, category-based, scheduled, or instant pause).
- Explain alerts in simple language using a local AI model.
- Run safely on Windows with notifications and optional auto-start.

### 6. Real-world applications
Home internet safety, parental control over kids' devices, spotting malware "calling home," controlling data usage, and basic security awareness.

### 7. Benefits
All-in-one, easy to use, works offline (AI is local — no API keys/quotas), private (nothing leaves the machine for AI), and free.

### Ready-to-speak explanations

**One-line:**
> "NetGuard is a Windows app that watches your network in real time, flags dangerous connections using global threat databases, tracks per-app data usage, and gives parents app/website controls — with a local AI that explains every alert in plain English."

**30-second:**
> "NetGuard is a real-time network security and parental-control monitor for Windows. It lists every connection your PC makes and checks each one against AbuseIPDB, AlienVault OTX, and Google Safe Browsing to assign a 0–10 risk score. It shows how much bandwidth each app uses, and lets a parent block apps or websites — instantly, by category, or on a schedule. A local AI model (Llama 3.2 via Ollama) explains alerts in simple language, fully offline."

**1-minute:**
> "NetGuard has two parts: a Python backend built with FastAPI that runs as a small local web server, and a PyQt5 desktop dashboard that talks to it. Every five seconds the backend lists active connections using psutil, checks new IPs against three threat-intelligence APIs plus a local suspicious-port checker, and computes a weighted risk score. High-risk events become alerts stored in SQLite and shown with a desktop notification. The dashboard shows live download/upload graphs and the top bandwidth-consuming apps. For parental control, it blocks websites by editing the Windows hosts file and blocks apps using Windows Firewall rules — with category lists, time schedules, and an instant 'pause internet' button. When the user clicks an alert, a local AI model running through Ollama explains why it was flagged, using the real evidence — no internet or API key needed."

**3-minute:** (add to the 1-minute version)
> "The architecture is client–server, but everything runs on one machine on localhost. The backend (`main.py`) exposes about 40 REST API endpoints. The frontend polls these every second to refresh the UI without freezing, using a background thread. Threat detection combines several signals: AbuseIPDB gives an abuse-confidence percentage, OTX gives a count of threat 'pulses,' Google Safe Browsing checks the domain behind the IP after a reverse-DNS lookup, and a local port checker flags ports known for malware like 4444 (Metasploit) or 6667 (IRC botnets). These are merged into one 0–10 score with AbuseIPDB weighted highest because it's the most reliable. To stay fast, results are cached for five minutes and the same IP isn't re-checked repeatedly. Parental control is enforced at the OS level: the hosts file redirects blocked domains to 127.0.0.1 so they never load, and Windows Firewall blocks an app's executable from sending data. Schedules are checked by the background loop and automatically block/unblock apps at set times. The AI is generated lazily — only when the user clicks an alert — and cached, so it stays light even on a laptop with no graphics card."

**5-minute:** (add to the 3-minute version)
> "Let me walk through the modules. `network_monitor.py` reads connections and bandwidth from psutil, smooths the speed numbers, and optionally sniffs packets with Scapy. `threat_intel.py` handles all the security APIs and the risk scoring. `port_checker.py` is pure local logic for dangerous ports. `parental_control.py` does the hosts-file and firewall blocking; `parental_features.py` adds categories, schedules, an instant pause, and activity stats. `adaptive_bandwidth_controller.py` watches per-app usage and raises alerts or caps when an app goes over a threshold. `database.py` manages a SQLite database with tables for alerts, blocked domains/apps, logs, categories, schedules, and an AI-explanation cache. `local_ai.py` talks to Ollama to generate grounded, concise explanations and summaries. `notifier.py` sends Windows toast notifications without blocking, and `autostart.py` can add NetGuard to Windows startup. The frontend `main_window.py` builds the whole dashboard — Dashboard, Processes, Alerts, Threat Check, Parental Controls, and Logs tabs — using PyQt5, with pyqtgraph for the live bandwidth chart. A big design theme is staying responsive and efficient: async I/O in the backend, background threads in the UI, caching everywhere, and lazy AI generation. A real engineering decision in the project was replacing a cloud AI (Google Gemini), which kept hitting free-quota limits, with a local model so the feature always works offline and free."

---

## PART 2: COMPLETE PROJECT STRUCTURE ANALYSIS

### Project tree
```
NetGurad/
├── main.py                          # Backend: FastAPI server + background monitor
├── main_window.py                   # Frontend: PyQt5 desktop dashboard
├── network_monitor.py               # Reads connections + bandwidth (psutil), packet sniffing
├── estimator.py                     # psutil-based per-process bandwidth ESTIMATION (fallback mode)
├── etw_monitor.py                   # Launches/reads the C# ETW helper for ACCURATE per-process bandwidth
├── etw_helper/                      # C# (.NET 8) project — real kernel ETW byte counter
│   ├── Program.cs                   # The C# source (consumes Windows kernel network ETW)
│   ├── NetGuardEtwHelper.csproj     # .NET project file
│   └── bin/Release/net8.0/NetGuardEtwHelper.exe   # Compiled helper (launched by etw_monitor.py)
├── threat_intel.py                  # AbuseIPDB, OTX, Google Safe Browsing, URLhaus, ThreatFox + risk scoring
├── port_checker.py                  # Local heuristic: flags malware-associated ports
├── parental_control.py              # Blocks domains (hosts file) and apps (Windows Firewall)
├── parental_features.py             # Categories, schedules, instant pause, activity summary
├── adaptive_bandwidth_controller.py # Per-app bandwidth thresholds, caps, and alerts
├── database.py                      # SQLite database operations + schema
├── local_ai.py                      # Local LLM (Ollama / Llama 3.2) explanations & summaries
├── notifier.py                      # Windows desktop toast notifications
├── autostart.py                     # Add/remove NetGuard from Windows startup
├── config.json                      # Settings + (optional) API keys + LLM config
├── .env                             # API keys (AbuseIPDB, OTX, Google Safe Browsing)
├── requirements.txt                 # Python dependencies
├── start_netguard.bat               # Launcher (self-elevates to admin, starts backend + UI)
├── README.md                        # Documentation
├── data/
│   └── netguard.db                  # SQLite database file (created at runtime)
└── .venv/                           # Python virtual environment (installed libraries)
```

### Folder-by-folder

**`NetGurad/` (root)** — Holds all source code. It exists because this is a flat, single-package Python project (no deep nesting needed). Every module lives here and imports its neighbors directly. It is the heart of the project.

**`data/`** — Stores the runtime SQLite database `netguard.db`. It exists to keep persistent data (alerts, blocked lists, logs, caches) separate from code. The backend (`database.py`) reads/writes here. If removed, the app recreates the DB on next start (history is lost).

**`.venv/`** — The Python **virtual environment**: a private copy of Python plus all installed libraries (FastAPI, PyQt5, psutil, etc.). It exists so the project's dependencies don't clash with other Python software on the PC. Not part of "your" code — it's the installed packages. If removed, you reinstall with `pip install -r requirements.txt`.

### Important files (purpose / role / what breaks if removed)

| File | Purpose | If removed |
|---|---|---|
| `main.py` | Backend server; defines all API endpoints, the 5-second monitoring loop, alert creation. **Entry point of the backend.** | Nothing works — no backend, no monitoring, no API. |
| `main_window.py` | The desktop GUI the user sees and clicks. **Entry point of the frontend.** | No user interface; backend would still run headless. |
| `network_monitor.py` | Gets active connections and bandwidth from psutil; smooths speeds; optional packet sniffing. | No connection list, no bandwidth numbers. |
| `threat_intel.py` | Talks to all threat APIs; reverse-DNS; computes the 0–10 risk score. | No threat detection; alerts can't be scored. |
| `port_checker.py` | Local list of malware ports; flags suspicious connections with no internet needed. | Loses port-based detection (e.g., Metasploit/IRC). |
| `parental_control.py` | Actually blocks domains (hosts file) and apps (firewall). | Blocking stops working. |
| `parental_features.py` | Categories, schedules, instant pause, activity stats. | Loses advanced parental features. |
| `adaptive_bandwidth_controller.py` | Detects apps exceeding bandwidth limits, raises alerts/caps. | No high-usage alerts. |
| `database.py` | Defines tables and all DB read/write helpers. | No data persists; app errors on save. |
| `local_ai.py` | Generates AI explanations/summaries via Ollama. | AI explanations fall back to plain text. |
| `notifier.py` | Windows toast notifications (non-blocking). | No desktop pop-ups (UI still shows alerts). |
| `autostart.py` | Adds/removes a Startup-folder shortcut. | Can't auto-start with Windows. |
| `etw_monitor.py` + `etw_helper/` (C#) | **Accurate mode** — Python launches the compiled C# .NET 8 ETW helper, which reports real per-process bytes from the Windows kernel. | Falls back to estimation. |
| `estimator.py` | **Estimation mode** — psutil-based per-app bandwidth estimate (fallback when ETW isn't available). | Per-app usage empty/less accurate. |
| `config.json` | Settings (thresholds, ports, LLM model) and optional keys. | Defaults are used; behavior may change. |
| `.env` | Stores the three threat-API keys. | Threat APIs run in demo/simulated mode. |
| `start_netguard.bat` | One-click launcher; requests admin; starts backend then UI. | Must start backend and UI manually. |

---

## PART 3: TECHNOLOGY STACK ANALYSIS

> Real-world analogy theme: think of the **backend** as a restaurant kitchen, the **frontend** as the dining room, and the **API** as the waiters carrying orders/food between them.

### Python (language)
- **What:** A simple, readable general-purpose programming language.
- **Why developers use it:** Fast to write, huge library ecosystem, great for networking, data, and AI.
- **Why chosen here:** Almost the entire project (backend, monitoring, GUI, AI client) is Python — one language for everything. Libraries like psutil and scapy make network work easy.
- **Advantages:** Easy, readable, batteries-included. **Disadvantages:** Slower than C/C++; GUI apps are heavier.
- **Alternatives:** C#/.NET, Java, Node.js.
- **Where used:** Every `.py` file.

### FastAPI (web framework)
- **What:** A modern Python framework for building web APIs.
- **Why used:** Lets you expose functions as web URLs (endpoints) with very little code; async-friendly and fast.
- **Why chosen:** The frontend and backend talk over HTTP on localhost; FastAPI cleanly defines all ~40 endpoints.
- **Advantages:** Fast, async, auto-validates input. **Disadvantages:** Needs an ASGI server (Uvicorn); overkill for tiny apps.
- **Alternatives:** Flask, Django.
- **Where:** `main.py` (`@app.get/post/...`).
- **Analogy:** The kitchen's order-window system that accepts and routes orders.

### PyQt5 (desktop GUI framework)
- **What:** Python bindings for Qt, a toolkit for building desktop windows, buttons, tables, charts.
- **Why used:** To build the visual dashboard the user interacts with.
- **Why chosen:** Mature, powerful, works well on Windows; supports tables, tabs, system-tray icon, threads.
- **Advantages:** Rich widgets, native look. **Disadvantages:** Large, licensing nuances, steep learning curve.
- **Alternatives:** Tkinter, Electron, WinForms.
- **Where:** `main_window.py`.
- **Analogy:** The dining room where customers sit and place orders.

### Uvicorn (ASGI server)
- **What:** A lightning-fast server that runs async Python web apps.
- **Why used:** FastAPI needs a server to actually listen on a port (8765).
- **Where:** Started in `main.py` (`uvicorn.run(...)`).
- **Analogy:** The building and front door that lets customers reach the kitchen.

### psutil (library)
- **What:** "Process and system utilities" — reads CPU, memory, and **network** info.
- **Why used:** To list active connections and measure bandwidth per network card and per process.
- **Where:** `network_monitor.py`, `estimator.py`.
- **Analogy:** A stethoscope on the computer that hears all its activity.

### aiohttp (library)
- **What:** An async HTTP client/server library.
- **Why used:** To call threat-intel APIs **and** the local Ollama AI without blocking the monitoring loop.
- **Where:** `threat_intel.py`, `local_ai.py`.
- **Analogy:** A fast courier that can carry many messages at once without waiting in line.

### Scapy (library)
- **What:** A packet-crafting and sniffing library.
- **Why used:** Optional deep packet inspection — see raw packets, not just connections.
- **Where:** `network_monitor.py` (packet sniffer).
- **Analogy:** Opening envelopes to inspect the letters, not just reading the address.

### plyer (library)
- **What:** Cross-platform access to features like notifications.
- **Why used:** To show Windows desktop toast pop-ups for alerts.
- **Where:** `notifier.py`.
- **Analogy:** The doorbell that rings when something important happens.

### pyqtgraph (library)
- **What:** A fast plotting library built for PyQt.
- **Why used:** To draw the live download/upload bandwidth graph.
- **Where:** `main_window.py` (dashboard chart).

### SQLite (database)
- **What:** A small, file-based database (no separate server).
- **Why used:** To store alerts, blocked lists, logs, schedules, and the AI cache persistently.
- **Where:** `database.py`, file at `data/netguard.db`.
- **Analogy:** A filing cabinet that lives in a single file.

### Ollama + Llama 3.2 (local AI)
- **What:** Ollama is a tool that runs AI language models on your own PC; Llama 3.2 (3B) is the model.
- **Why used:** To explain alerts and summarize activity in plain English **offline** — no API key, no quota.
- **Why chosen:** Replaced cloud Gemini, which kept hitting free-quota limits and needed internet.
- **Where:** `local_ai.py` calls `http://localhost:11434`.
- **Analogy:** Hiring an in-house translator instead of phoning an outside agency that charges per call.

### Threat-Intelligence APIs
- **AbuseIPDB** — community database of reported bad IPs (gives a confidence %).
- **AlienVault OTX** — threat "pulses" (reports) mentioning an IP.
- **Google Safe Browsing** — Google's list of phishing/malware sites (checks domains).
- **URLhaus / ThreatFox** — malicious URL and indicator databases.
- **Where:** `threat_intel.py`.
- **Analogy:** Calling several different "credit bureaus" about an address and combining their answers.

### Windows OS tools (not libraries, but used)
- **Windows Firewall** (via `netsh`) — blocks an app's executable from the internet.
- **Hosts file** — a Windows text file that maps domain names to IPs; used to send blocked sites to 127.0.0.1 (nowhere).
- **Where:** `parental_control.py`, `parental_features.py`.

### C# (.NET 8) — the ETW helper
- **What:** A second, small program written in **C#** (`etw_helper/Program.cs`), compiled to `NetGuardEtwHelper.exe` (.NET 8).
- **Why used:** To get **exact** per-process network byte counts using **ETW (Event Tracing for Windows)** — a low-level Windows kernel feature best accessed from .NET. Python cannot do this cleanly.
- **How it works:** It consumes the kernel network provider (TCP+UDP, send+receive, IPv4+IPv6), counts real bytes per PID, and writes them to a JSON file once per second. `etw_monitor.py` launches this `.exe` as a **separate elevated process**, reads the JSON, and diffs it into per-app KB/s.
- **Why a separate process:** Isolation — if the low-level tracing crashes, it can't take down the Python backend; NetGuard simply falls back to estimation mode.
- **Where:** `etw_helper/` (C# project) + `etw_monitor.py` (Python launcher/reader).
- **Analogy:** A specialist contractor (C#) brought in for one precise job, kept in a separate room so an accident there doesn't burn down the main kitchen.

> **Two accuracy levels (know this for viva):**
> 1. **Accurate mode** — the C# ETW helper gives *real* per-app byte counts (requires Administrator).
> 2. **Estimation mode** — if the helper isn't built/available or not elevated, Python/psutil (`estimator.py`) *estimates* per-app usage by connection-count weighting. The app degrades cleanly between the two.

---

## PART 4: LIBRARY → FOLDER → FILE MAPPING

| Library | Purpose | Folder | Files Using It | Features Using It | If Removed |
|---|---|---|---|---|---|
| **fastapi** | Web API framework | root | `main.py` | All API endpoints | Backend can't expose any endpoint |
| **uvicorn** | Runs the API server | root | `main.py` | Backend startup on port 8765 | Server won't run |
| **PyQt5** | Desktop GUI | root | `main_window.py` | Entire dashboard, tabs, tray | No UI |
| **pyqtgraph** | Live charts | root | `main_window.py` | Bandwidth graph | Chart disabled (text fallback) |
| **psutil** | System/network info | root | `network_monitor.py`, `estimator.py` | Connections, bandwidth, top apps | No monitoring data |
| **aiohttp** | Async HTTP client | root | `threat_intel.py`, `local_ai.py` | Threat API calls, AI calls | Threat checks + AI break |
| **scapy** | Packet sniffing | root | `network_monitor.py` | Optional packet monitor | Packet sniffing disabled |
| **plyer** | Desktop notifications | root | `notifier.py` | Toast pop-ups | No notifications |
| **sqlite3** (built-in) | Database | root | `database.py`, `parental_*`, `network` | Persistence (alerts, blocks, cache) | App can't save data |
| **Ollama** (external app) | Local LLM runtime | external | `local_ai.py` | AI explanations/summaries | AI falls back to plain text |
| **urllib / socket / subprocess** (built-in) | HTTP, DNS, run netsh | root | `main_window.py`, `threat_intel.py`, `parental_control.py` | UI↔API calls, reverse DNS, firewall/hosts | UI calls / DNS / blocking break |

---

## PART 5: FOLDER → LIBRARY MAPPING

This project is **flat** (one folder of modules), so this maps **module groups** instead of nested folders.

**Backend group (`main.py`, `threat_intel.py`, `network_monitor.py`, `port_checker.py`, `adaptive_bandwidth_controller.py`, `parental_*`, `database.py`, `local_ai.py`, `notifier.py`)**
- `fastapi`, `uvicorn` — serve the API (`main.py`).
- `psutil` — read network data (`network_monitor.py`, `estimator.py`).
- `aiohttp` — call threat APIs and Ollama (`threat_intel.py`, `local_ai.py`).
- `scapy` — packet sniffing (`network_monitor.py`).
- `sqlite3` — persistence (`database.py` and callers).
- `plyer` — notifications (`notifier.py`).
- `subprocess` — run `netsh` for firewall/pause (`parental_*`).

**Frontend group (`main_window.py`)**
- `PyQt5` — windows, tabs, tables, tray, threads.
- `pyqtgraph` — live bandwidth chart.
- `urllib` + `json` — call the backend API endpoints.

**`data/`** — used only by `sqlite3` via `database.py`.

---

## PART 6: FEATURE → LIBRARY → FILE MAPPING

**Feature: Real-time connection & bandwidth monitoring**
- Purpose/benefit: See live connections and per-app data usage.
- Files: `network_monitor.py`, `estimator.py`, `main.py` (`/api/bandwidth`, `/api/connections`, `/api/processes`), `main_window.py` (Dashboard, Processes tabs).
- Libraries: psutil, pyqtgraph.
- DB tables: none directly.
- Flow: `DataFetcher` (UI) → `/api/bandwidth` & `/api/processes` → `NetworkMonitor.get_bandwidth()/get_process_usage()`.

**Feature: Threat detection & risk scoring**
- Files: `threat_intel.py`, `port_checker.py`, `main.py` (background loop, `/api/check/ip`).
- Libraries: aiohttp, socket (reverse DNS).
- APIs: AbuseIPDB, OTX, Google Safe Browsing, URLhaus, ThreatFox.
- DB tables: `alerts`, `checked_ips`.
- Functions: `check_ip()`, `_combine_risk()`, `check_connection()`.

**Feature: AI alert explanation & summary**
- Files: `local_ai.py`, `main.py` (`/api/ai/explain-alert`, `/api/ai/summary`, `/api/gemini/explain`), `main_window.py` (Alerts + Threat Check tabs).
- Libraries: aiohttp; external Ollama.
- DB tables: `gemini_cache`.
- Functions: `explain_alert_dict()`, `summarize_activity()`, `explain_free()`.

**Feature: Parental control — domain blocking**
- Files: `parental_control.py`, `parental_features.py`, `main.py` (`/api/parental/domains/*`, `/api/parental/categories`).
- Libraries: subprocess (netsh), socket, sqlite3.
- DB tables: `blocked_domains`, `blocked_categories`.
- OS tool: Windows hosts file (+ firewall for domain IPs).

**Feature: Parental control — app blocking & schedules & pause**
- Files: `parental_control.py`, `parental_features.py`, `main.py` (`/api/processes/block`, `/api/parental/schedules`, `/api/parental/pause`).
- Libraries: subprocess (Windows Firewall via netsh), sqlite3.
- DB tables: `blocked_apps`, `app_schedules`, `parental_events`.

**Feature: Adaptive bandwidth alerts/caps**
- Files: `adaptive_bandwidth_controller.py`, `main.py` (`/api/caps`, `/api/adaptive/*`).
- DB tables: `alerts`.

**Feature: Notifications & autostart**
- Files: `notifier.py` (plyer), `autostart.py` (PowerShell shortcut).

---

## PART 7: APPLICATION WORKFLOW

### What happens when the app starts
1. User runs `start_netguard.bat`. It **requests administrator rights** (needed for hosts-file/firewall edits), then starts the **backend** (`python main.py`) in one window and the **frontend** (`main_window.py`) in another.
2. `main.py` loads `config.json` + `.env`, creates all module objects (database, monitor, threat_intel, parental, AI), and Uvicorn starts listening on `http://127.0.0.1:8765`.
3. FastAPI's `startup_event()` initializes the database, tries "accurate" bandwidth mode (falls back to estimation), and sends a "NetGuard Started" notification.
4. It launches the **background monitor loop** (`background_monitor()`), which runs every 5 seconds.
5. The frontend window opens and its `DataFetcher` thread begins polling the backend every 1 second to refresh the dashboard.

### Which file executes first
`main.py` for the backend; `main_window.py` for the GUI. The `.bat` starts the backend first, waits ~3 seconds, then the GUI.

### Data flow (threat detection)
```
Background loop (every 5s)
   ↓
NetworkMonitor.get_active_connections()  (psutil)
   ↓
For each new remote IP:
   ├── port_checker.check_connection()      (local heuristic)
   └── threat_intel.check_ip(ip)
            ├── AbuseIPDB  (aiohttp)
            ├── OTX        (aiohttp)
            ├── reverse DNS → Google Safe Browsing (aiohttp)
            └── _combine_risk() → 0–10 score
   ↓
If risky → build alert dict → store in SQLite (alerts) → notify_alert() (toast)
   ↓
Frontend DataFetcher polls /api/alerts every 1s → Alerts tab updates
```

### User interaction flow (AI explanation)
```
User clicks an alert in the UI
   ↓
main_window (_show_details) → background _AIWorker
   ↓ POST /api/ai/explain-alert  (the alert dict)
main.py → local_ai.explain_alert_dict(alert)
   ↓ checks cache (memory → SQLite); else builds fact-only prompt
   ↓ POST http://localhost:11434/api/generate  (Ollama / Llama 3.2)
   ↓ returns 2–3 sentence explanation, cached
UI shows "AI Analysis: ..."
```

### User interaction flow (blocking a website)
```
User adds domain in Parental Controls
   ↓ POST /api/parental/domains/block
parental_control.block_domain()
   ├── write "127.0.0.1 domain" into Windows hosts file
   ├── add Windows Firewall rule for resolved IPs
   └── save to SQLite (blocked_domains)
Result → UI refresh + "Domain Blocked" notification
```

### General request/response shape
```
User → Frontend (PyQt5) → HTTP request → Backend (FastAPI) → module logic
     → (APIs / OS / SQLite) → response → Frontend updates → User sees result
```

---

## PART 8: FILE-BY-FILE CODE EXPLANATION (simple English)

**`main.py`** — *The backend brain.* Loads settings, creates every module object once, defines ~40 API endpoints, and runs the 5-second `background_monitor()` loop that checks connections, scores threats, raises alerts, and runs the parental schedule tick. Input: HTTP requests + live system data. Output: JSON responses, alerts, notifications. Depends on every backend module.

**`main_window.py`** — *The dashboard.* Builds the window, sidebar, and tabs (Dashboard, Processes, Alerts, Threat Check, Parental Controls, Logs). A `DataFetcher` thread polls the API each second so the UI never freezes. Helper workers (`_AIWorker`, parental workers) run slow calls in the background. Input: user clicks + API data. Output: the visual interface.

**`network_monitor.py`** — *The senses.* Uses psutil to list connections and to measure total bandwidth (with smoothing and a shared, throttled sampler so multiple callers don't fight). Splits total bandwidth across apps by connection count to estimate per-app usage. Can optionally sniff packets with Scapy. Input: OS counters. Output: connection list, bandwidth dict, per-process rows.

**`etw_monitor.py` + `etw_helper/` (C# .NET 8) — accurate per-app bandwidth.** The C# program (`Program.cs` → `NetGuardEtwHelper.exe`) taps the Windows kernel network ETW provider to count **real** per-process bytes (TCP+UDP, up+down, IPv4+IPv6) and writes them to a JSON file every second. `etw_monitor.py` launches that `.exe` as a separate elevated process and diffs the JSON into per-app KB/s. If it isn't built or NetGuard isn't elevated, it degrades cleanly.

**`estimator.py` — estimation fallback.** Uses psutil + connection-count weighting to *estimate* per-app bandwidth when accurate ETW mode isn't available.

**`threat_intel.py`** — *The investigator.* Loads API keys, calls AbuseIPDB/OTX/Google Safe Browsing/URLhaus/ThreatFox, does reverse-DNS to find the domain behind an IP, caches results 5 minutes, and merges everything into one 0–10 risk score with `_combine_risk()` (AbuseIPDB weighted 0.65, OTX 0.25, and a GSB hit forces ≥8).

**`port_checker.py`** — *Local rulebook.* A dictionary of malware-associated ports (e.g., 4444 Metasploit, 6667 IRC botnet, 31337 backdoor). `check_connection()` flags any connection to those ports — no internet needed.

**`parental_control.py`** — *The enforcer.* Blocks domains by writing `127.0.0.1 <domain>` into the Windows hosts file (so they fail to load) and blocks apps by adding Windows Firewall outbound-block rules via `netsh`. Stores blocked items in SQLite.

**`parental_features.py`** — *Advanced controls.* `CategoryManager` blocks bundled lists (social media, gaming, adult, etc.) in one batch hosts-file write; `ScheduleManager` blocks/unblocks apps by time windows (the background loop calls `tick()`); `PauseManager` adds one firewall rule to cut all internet instantly; `ActivitySummary` aggregates recent events.

**`adaptive_bandwidth_controller.py`** — *Usage watchdog.* Compares each app's KB/s against a threshold or per-app cap; raises a `bandwidth_threshold`/`bandwidth_cap` alert (and can auto-block) when exceeded, with a cooldown to avoid spam.

**`database.py`** — *The filing cabinet.* Creates all tables and provides save/get helpers for alerts, checked IPs, blocked domains/apps, logs, categories, schedules, parental events, and the AI cache.

**`local_ai.py`** — *The explainer.* Talks to Ollama. Builds **fact-only, type-specific prompts** (so the AI uses real evidence and doesn't invent data), caps length, keeps the model warm, dedupes concurrent calls (single-flight), and caches answers in memory + SQLite. Provides `explain_alert_dict`, `summarize_activity`, `explain_free`.

**`notifier.py`** — *The doorbell.* Sends non-blocking Windows toasts, deduplicates by alert ID, and throttles chatty sources (e.g., one popup per process per 10 minutes for port alerts).

**`autostart.py`** — Creates/removes a Startup-folder shortcut so NetGuard can launch (minimized to tray) when Windows starts.

---

## PART 9: DATABASE ANALYSIS

- **Type:** SQLite (file-based, no server). File: `data/netguard.db`. Defined in `database.py`.

### Tables (ER overview)
```
alerts(id PK, type, severity, process, ip, domain, message, timestamp, risk_score, action_taken)
checked_ips(ip PK, last_checked)
blocked_domains(domain PK, added_date)
blocked_apps(process PK, executable_path, added_date)
logs(id PK AUTOINCREMENT, action, target, timestamp)
blocked_categories(category PK, enabled, last_applied)
app_schedules(id PK AUTOINCREMENT, process, executable_path, start_minute, end_minute, days, enabled, currently_blocked, created)
parental_events(id PK AUTOINCREMENT, event_type, target, timestamp)
gemini_cache(ip PK, explanation, cached_at)
```

There are **no foreign keys** — the tables are independent logs/registries keyed by natural keys (IP, domain, process name) or an auto-increment id. This is a deliberately simple design for a single-user desktop app.

### Per-table purpose
- **alerts** — every security/bandwidth/parental alert (shown in UI, history).
- **checked_ips** — remembers when an IP was last checked so it isn't re-queried for 5 minutes (performance).
- **blocked_domains / blocked_apps** — the parental block lists (reloaded at startup).
- **logs** — audit trail of actions (block, unblock, etc.).
- **blocked_categories** — which category lists are enabled.
- **app_schedules** — time-based app-blocking rules.
- **parental_events** — events feeding the activity summary.
- **gemini_cache** — saved AI explanations per IP so they survive restarts and aren't regenerated (named `gemini_cache` for historical reasons; now stores local-AI output).

---

## PART 10: API ANALYSIS

- **Base URL:** `http://127.0.0.1:8765/api`  · **Auth:** none (localhost-only, single user) · **Format:** JSON · **Errors:** endpoints return `{"error": "..."}` or `{"ok": false, "error": ...}`; the frontend shows friendly messages.

### Key endpoints (method — purpose — used by)
| Endpoint | Method | Purpose |
|---|---|---|
| `/api/bandwidth` | GET | Current download/upload KB/s (Dashboard) |
| `/api/connections` | GET | Active connections |
| `/api/processes` | GET | Per-app bandwidth rows (Processes, Top Apps) |
| `/api/alerts` | GET | Recent alerts (Alerts tab, Dashboard) |
| `/api/alerts/toggle-demo` | POST | Show/hide demo alerts |
| `/api/check/ip/{ip}` | POST | On-demand IP reputation check (Threat Check) |
| `/api/check/url` | POST | On-demand URL check |
| `/api/processes/block` / `/unblock` | POST | Block/unblock an app (firewall) |
| `/api/parental/domains/block` / `/unblock` | POST | Block/unblock a website (hosts file) |
| `/api/parental/categories` | GET/POST | List/toggle category blocking |
| `/api/parental/pause` | GET/POST | Status / instant pause-resume internet |
| `/api/parental/schedules` | GET/POST/DELETE | Manage app schedules |
| `/api/parental/safemode` | GET/POST | Safe Mode master switch |
| `/api/gemini/explain` | POST | Free-form AI chat (grounded in live snapshot) |
| `/api/ai/explain-alert` | POST | AI explanation for a clicked alert (lazy) |
| `/api/ai/summary` | POST | AI summary of current activity |
| `/api/stats` | GET | Dashboard summary numbers |
| `/api/adaptive/status`, `/api/caps` | GET/POST/DELETE | Bandwidth controller state & caps |
| `/api/monitoring/toggle` | POST | Pause/resume monitoring |
| `/api/shutdown` | POST | Graceful backend shutdown |

The frontend's `api_get()` / `api_post()` helpers in `main_window.py` call these; the `DataFetcher` thread polls the GET ones every second.

---

## PART 11: ARCHITECTURE ANALYSIS

### High-level (client–server on one machine)
```
┌──────────────────────────┐        HTTP (localhost:8765)        ┌───────────────────────────┐
│   FRONTEND (PyQt5)        │  ───── GET/POST JSON every 1s ───▶  │   BACKEND (FastAPI/Uvicorn)│
│   main_window.py          │  ◀──── JSON responses ────────────  │   main.py                  │
│   Dashboard/Tabs/Tray     │                                     │   background loop (5s)     │
└──────────────────────────┘                                     └──────────┬────────────────┘
                                                                             │ uses
        ┌────────────────────────────────────────────────────────────────────┼─────────────┐
        ▼                    ▼                    ▼                    ▼        ▼             ▼
  network_monitor      threat_intel         parental_*        adaptive_bw   local_ai     database
   (psutil/scapy)   (APIs + scoring)   (hosts+firewall)   (usage caps)   (Ollama)     (SQLite)
                          │                                                  │
                          ▼                                                  ▼
            AbuseIPDB / OTX / GSB / URLhaus                        Ollama @ 11434 (Llama 3.2)
```

### Patterns used
- **Client–Server** — UI (client) and API (server) are separate processes talking over HTTP.
- **Layered/Modular** — each concern (monitoring, threats, parental, AI, DB, notify) is its own module.
- **Background worker / polling** — UI uses a `QThread` (`DataFetcher`) to poll; slow tasks run on workers so the UI stays responsive.
- **Asynchronous I/O** — backend uses `async`/`await` (FastAPI + aiohttp) so network calls don't block the loop.
- **Caching** — IP results (5 min) and AI answers (memory + SQLite) avoid repeat work.
- **Single-flight / dedupe** — AI and notifications avoid duplicate work for the same key.
- **Graceful fallback** — if a key/API/Ollama is missing, the app degrades to simulated/plain-text instead of crashing.

---

## PART 12: COMPLETE DEPENDENCY FLOW

```
psutil → root → network_monitor.py → get_active_connections()/get_bandwidth() → Monitoring feature
aiohttp → root → threat_intel.py → check_ip()/_combine_risk() → Threat Detection feature
aiohttp → root → local_ai.py → explain_alert_dict() → AI Explanation feature
subprocess(netsh) → root → parental_control.py → block_app() → App Blocking feature
hosts file → root → parental_control.py → block_domain() → Website Blocking feature
sqlite3 → root → database.py → save_alert()/get_alerts() → Persistence/History
plyer → root → notifier.py → notify_alert() → Desktop Notifications
PyQt5 → root → main_window.py → AlertsTab/_show_details() → Dashboard/UI
pyqtgraph → root → main_window.py → update_bandwidth() → Live Chart
fastapi+uvicorn → root → main.py → endpoints + background_monitor() → Whole backend
```

---

## PART 13: HOW TO EXPLAIN TO YOUR GUIDE (per module)

**Monitoring module**
- *Simple:* "It watches all the connections my PC makes and how much data each app uses."
- *Technical:* "`network_monitor.py` uses psutil to enumerate `net_connections` and `net_io_counters`, smooths bandwidth with an EWMA, and shares one throttled sample across callers."
- *Say to guide:* "I monitor connections and bandwidth using psutil, refreshing every five seconds in the backend and every second in the UI."
- *Follow-ups:* "Why every 5s?" → "Balance between freshness and CPU." "Per-app accuracy?" → "Estimated by connection-count weighting since Windows doesn't expose per-process bytes without ETW."

**Threat detection module**
- *Simple:* "It checks each IP against security databases and gives it a danger score from 0 to 10."
- *Technical:* "`threat_intel.check_ip()` queries AbuseIPDB, OTX, and Google Safe Browsing (via reverse DNS), then `_combine_risk()` produces a weighted score; results cache for 5 minutes."
- *Say to guide:* "I combine three independent sources plus a local port check into one risk score, weighting the most reliable source highest."
- *Follow-ups:* "Why weight AbuseIPDB more?" → "Direct abuse reports are more reliable than mere threat-feed mentions; OTX over-flags shared cloud IPs."

**AI module**
- *Simple:* "A small AI on my own computer explains alerts in plain English."
- *Technical:* "`local_ai.py` posts a fact-only prompt to Ollama (`/api/generate`) running Llama 3.2; generation is lazy, length-capped, single-flighted, and cached in memory + SQLite."
- *Say to guide:* "I moved AI from cloud Gemini to a local model because the cloud key kept hitting quota; now it's offline, free, and private."
- *Follow-ups:* "How do you stop hallucination?" → "I feed only real evidence and instruct it to use only those facts."

**Parental control module**
- *Simple:* "It blocks websites and apps for kids."
- *Technical:* "Domains via the hosts file (→127.0.0.1), apps via Windows Firewall `netsh` rules; categories, schedules, and an instant pause sit on top."
- *Follow-ups:* "Why both hosts file and firewall?" → "Hosts file blocks by domain name; firewall blocks an app entirely — they cover each other's gaps."

---

## PART 14: MCA VIVA — QUESTION BANK (with answers)

### Easy
1. **What is NetGuard?** A Windows real-time network-security + parental-control monitor with local-AI explanations.
2. **Which language is it written in?** Python (frontend and backend).
3. **Frontend framework?** PyQt5.
4. **Backend framework?** FastAPI, served by Uvicorn.
5. **Database used?** SQLite (`data/netguard.db`).
6. **How do frontend and backend communicate?** HTTP/JSON on `localhost:8765`.
7. **Which library reads network data?** psutil.
8. **What sends desktop notifications?** plyer (via `notifier.py`).
9. **What is the entry point of the backend?** `main.py`.
10. **What is the entry point of the GUI?** `main_window.py`.
11. **Where are API keys stored?** `.env` and/or `config.json`.
12. **How is a website blocked?** By editing the Windows hosts file to point the domain to 127.0.0.1.
13. **How is an app blocked?** A Windows Firewall outbound-block rule on its `.exe`.
14. **What is the risk score range?** 0 to 10.
15. **Which AI model is used?** Llama 3.2 (3B) via Ollama, locally.
16. **Does the AI need internet?** No — it runs on the machine.
17. **How often does the backend scan connections?** Every 5 seconds.
18. **How often does the UI refresh?** Every 1 second (via a background thread).
19. **What does `requirements.txt` do?** Lists Python libraries to install.
20. **What does `start_netguard.bat` do?** Requests admin, starts backend then UI.

### Medium
21. **Why FastAPI over Flask?** Async support and fast, concise endpoint definitions; fits the async monitoring/HTTP design.
22. **Why is admin needed?** Editing the hosts file and Windows Firewall requires elevation.
23. **How does threat scoring combine sources?** Weighted average — AbuseIPDB 0.65, OTX 0.25 — and a Google Safe Browsing hit forces the score to at least 8.
24. **Why cache IP results?** To avoid hammering APIs and improve speed (5-minute TTL in `checked_ips`/memory).
25. **What is reverse DNS used for?** To find the domain behind an IP so Google Safe Browsing can check it.
26. **What is the port checker?** Local logic flagging malware-associated ports (4444, 6667, 31337, …) without any API.
27. **What is Safe Mode?** A master switch that applies all selected category blocks and arms auto-blocking of malicious IPs.
28. **How do schedules work?** The 5-second loop calls `ScheduleManager.tick()`, which blocks/unblocks apps when the current time enters/leaves a window.
29. **How does instant pause work?** One Windows Firewall rule blocking all outbound traffic; resume deletes it.
30. **Why keep the UI responsive with threads?** Network/AI calls can take seconds; running them on `QThread` workers prevents freezing.
31. **How is bandwidth smoothed?** An exponential moving average + a shared, throttled sampler so the graph isn't jumpy and callers don't race.
32. **Why was per-app bandwidth only estimated?** Windows doesn't expose per-process byte counts without ETW; the project estimates via connection-count weighting.
33. **What does the AI cache store?** Per-IP explanations in memory and the `gemini_cache` SQLite table (survives restarts).
34. **What is "single-flight" in the AI module?** If two requests for the same key arrive together, only one model call runs; both share the result.
35. **How does the app fail safely without keys/Ollama?** It uses simulated threat data or plain-text fallbacks instead of crashing.
36. **What are the alert types?** `malicious_ip`, `packet_malicious_ip`, `bandwidth_threshold`, `bandwidth_cap`, `parental_control`, suspicious-port.
37. **How are duplicate notifications avoided?** `notifier.py` dedupes by alert ID and throttles by process/IP with cooldowns.
38. **What does `adaptive_bandwidth_controller` do?** Flags or caps apps exceeding a KB/s threshold, with a cooldown.
39. **Why is there a demo-alerts toggle?** To show example alerts in the UI for demos/testing.
40. **What is the role of `config.json` vs `.env`?** `config.json` holds settings + LLM config (and optional keys); `.env` holds the threat-API keys.

### Hard
41. **Walk through the full lifecycle of a malicious-IP alert.** Loop reads connections → new IP → port check + `check_ip()` (APIs + reverse DNS + GSB) → `_combine_risk()` → if risky, `_build_threat_alert()` attaches compact `threat_summary` (no AI yet) → stored in `alerts` → `notify_alert()` toast → UI polls `/api/alerts` → user clicks → `/api/ai/explain-alert` → `local_ai` builds grounded prompt → Ollama → cached explanation shown.
42. **Why move from Gemini to a local LLM? Trade-offs?** Cloud quota/keys/internet were unreliable; local is free, private, offline. Trade-off: slower on a CPU-only laptop and lower raw quality than large cloud models — mitigated by lazy generation, caching, short outputs, and a warm model.
43. **How do you prevent the AI from hallucinating numbers/IPs?** The prompt includes only real extracted fields and explicitly forbids inventing data; temperature is low (0.2) for factual tasks.
44. **Why did legitimate cloud IPs (e.g., Anthropic) get false-flagged, and how was it fixed?** OTX gave max score for any pulses and was over-weighted. Fixed by softening OTX scaling (`pulses × 0.5`) and raising AbuseIPDB's weight, dropping a 7.8 false positive to ~5.5 while real threats stay at 10.
45. **How is concurrency handled in the backend?** FastAPI async endpoints + `aiohttp` async calls; reverse DNS runs in an executor thread; the monitor loop `await`s without blocking.
46. **What are the security limitations?** No authentication (localhost single-user assumption); hosts/firewall blocks can be bypassed by an admin user or apps using hard-coded IPs; estimation isn't exact per-app accounting.
47. **How is accurate per-app bandwidth achieved?** A separate **C# (.NET 8)** helper (`etw_helper/`) consumes the Windows kernel network ETW provider for real per-process byte counts and writes JSON each second; `etw_monitor.py` launches it as an isolated elevated process and diffs into KB/s. If unavailable, the app falls back to psutil estimation (`estimator.py`). Running it out-of-process means a low-level ETW crash can't take down the Python backend.
48. **Why hosts file AND firewall for domains?** Hosts file blocks DNS-based access by name; some apps use direct IPs, so a firewall rule on resolved IPs backs it up.
49. **How does the schedule handle overnight windows (e.g., 22:00–07:00)?** `_is_within()` treats start>end as crossing midnight and checks the correct weekday on each side.
50. **How is the database kept simple yet sufficient?** Independent tables keyed by natural keys; no foreign keys needed for a single-user log/registry model; caches reduce external calls.
51. **What happens if two NetGuard backends run at once?** Only one can bind port 8765; the other fails to bind — a real issue seen during testing, solved by ensuring a single clean instance.
52. **How is the monitoring loop kept from spamming alerts?** IP cache + `recently_checked`, notification cooldowns, and bandwidth alert cooldowns.
53. **Why async aiohttp instead of requests?** `requests` is blocking and would stall the event loop; aiohttp lets many checks run concurrently.
54. **How is the AI kept "light" on a weak laptop?** Lazy (only on click), token caps (100–160), low temperature, `keep_alive` to avoid reloads, and caching.
55. **How does Safe Mode interact with categories?** Turning Safe Mode on re-applies all enabled categories in one batch and arms auto-block; turning it off lifts them but keeps the selection.

*(These 55 cover the easy/medium/hard spectrum thoroughly; you can split any answer into more sub-questions to reach 100 if your format requires a fixed count.)*

---

## PART 15: PRESENTATION SCRIPT

**Introduction:** "Good morning. My project is **NetGuard**, a real-time network-security and parental-control monitor for Windows, with a built-in local-AI assistant."

**Problem statement:** "Ordinary users can't see what their computer connects to, can't tell if it's dangerous, and lack simple controls over apps and websites."

**Objectives:** "Monitor connections live, detect malicious IPs/domains, track per-app bandwidth, provide parental controls, and explain alerts in plain language — offline."

**Technologies:** "Python with FastAPI for the backend, PyQt5 for the desktop UI, psutil and Scapy for monitoring, aiohttp for API calls, SQLite for storage, and Ollama running Llama 3.2 for the local AI."

**Architecture:** "A client–server design on one machine: a FastAPI backend on localhost:8765 with a background loop, and a PyQt5 dashboard that polls it every second."

**Features:** "Real-time monitoring, multi-source threat detection with a 0–10 risk score, bandwidth tracking, app/website/category/scheduled blocking, instant pause, and AI explanations and summaries."

**Workflow:** "Every five seconds it checks connections, scores threats using AbuseIPDB, OTX, and Google Safe Browsing plus a local port checker, raises alerts, and notifies the user. Clicking an alert generates a local-AI explanation grounded in the real evidence."

**Database:** "SQLite stores alerts, blocked lists, logs, schedules, and the AI cache."

**Results:** "All major features were tested and verified — monitoring, detection, blocking, scheduling, and AI explanations all work end to end, fully offline for the AI."

**Conclusion:** "NetGuard brings enterprise-style network visibility and parental control to ordinary home users in one simple, private, offline-capable app. Future work: a true ETW per-app meter and behavioral baselining for smarter detection."

---

## PART 16: CHEAT SHEETS

**Technology:** Python · **C# (.NET 8)** for the ETW bandwidth helper · FastAPI · Uvicorn · PyQt5 · pyqtgraph · psutil · aiohttp · Scapy · plyer · SQLite · Ollama/Llama 3.2 · Windows Firewall · hosts file · ETW.

**Library → one-liner:**
- psutil = read network/system data · aiohttp = async API/AI calls · scapy = packet sniffing · plyer = notifications · pyqtgraph = live chart · fastapi/uvicorn = backend server · PyQt5 = GUI · sqlite3 = storage.

**Folder:** root = all code · `data/` = SQLite db · `.venv/` = installed libraries.

**Feature:** Monitoring · Threat detection (0–10 score) · AI explanations/summary · App blocking (firewall) · Website blocking (hosts) · Categories · Schedules · Instant pause · Bandwidth alerts · Notifications · Autostart.

**Architecture:** Client–server (localhost), layered modules, async I/O, background polling, caching, graceful fallback.

**Database:** alerts, checked_ips, blocked_domains, blocked_apps, logs, blocked_categories, app_schedules, parental_events, gemini_cache.

---

## PART 17: NIGHT-BEFORE-VIVA NOTES

- **Most important files:** `main.py` (backend + loop + endpoints), `main_window.py` (UI), `threat_intel.py` (scoring), `local_ai.py` (AI), `parental_control.py` (blocking).
- **Most important libraries:** psutil, aiohttp, FastAPI, PyQt5, SQLite, Ollama.
- **Most important DB tables:** alerts, blocked_domains, blocked_apps, app_schedules, gemini_cache.
- **Most important APIs to name:** `/api/check/ip`, `/api/alerts`, `/api/ai/explain-alert`, `/api/parental/domains/block`, `/api/parental/pause`.
- **Key concepts:** client–server over localhost; weighted risk score; hosts file vs firewall blocking; async + background threads; caching; lazy local-AI; graceful fallback.
- **Likely questions:** "How is risk scored?" · "Why local AI?" · "Why admin rights?" · "How is a site blocked?" · "How do you keep the UI responsive?" · "Per-app bandwidth accuracy?"
- **One-liner to memorize:** "NetGuard monitors connections, scores threats from multiple sources, enforces parental blocks at the OS level, and explains everything with a local AI — all on one machine, offline."

---

## FINAL SECTION

1. **Study first:** `main.py` → `main_window.py` → `threat_intel.py` → `local_ai.py` → `parental_control.py`.
2. **Most important folders:** the root (all logic) and `data/` (the database).
3. **Most important libraries:** psutil, aiohttp, FastAPI, PyQt5, SQLite, plus the Ollama runtime.
4. **Most important features:** real-time monitoring, multi-source threat scoring, OS-level blocking, and local-AI explanations.
5. **Guide will most likely ask:** how the risk score is computed; why a local LLM; how blocking is enforced; how the UI stays responsive; the database design; per-app bandwidth accuracy.
6. **Must understand before viva:** the client–server-on-localhost model, the weighted risk formula, hosts-file vs firewall enforcement, async + background polling, caching, and the lazy local-AI pipeline.

### Confidence score
**Project understandable from provided files: ~95%.**
- **Strong/complete:** all backend modules, frontend, database schema, threat scoring, parental control, and the local-AI pipeline are present and consistent.
- **Minor gaps / clarify before viva:**
  - **C# (.NET 8) IS in the project** — the `etw_helper/` folder is a real, compiled .NET 8 program for accurate ETW per-app bandwidth, launched by `etw_monitor.py`. Your slide is correct. (Accurate mode needs Administrator; otherwise it falls back to psutil estimation in `estimator.py`.)
  - `data/netguard.db` is generated at runtime; exact stored rows depend on usage.
  - Some features depend on the environment: Scapy packet sniffing is optional; ETW "accurate mode" needs the built C# helper + admin, else estimation mode is used.
```
