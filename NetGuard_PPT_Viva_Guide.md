# 🎓 NetGuard PPT — Slide-by-Slide Viva Guide (Simple English)

> For: Esha Patel (1MS24MC028), MCA, RIT — External Viva Preparation
> Goal: Understand **every slide** so you can explain the project in your **own words**, not from memory.
> Style: Very simple English. Every hard word is explained the first time.

**Golden rule for the viva:** For any point, say **(1) what it is → (2) why we did it → (3) one honest limit.** That structure sounds confident and mature.

---

# SLIDE 1 — Title

### 1. Slide overview
This is the front page. It shows the project name, your name, USN, and guide.

### 2. Every point
- **"Real-Time Network Analysis and Control System"** = the official title. "Real-time" = shows fresh data continuously. "Analysis" = it studies your network. "Control" = it can block/allow.
- **NetGuard** = the short name of your app (like a brand name).
- Your name, USN (1MS24MC028), Guide (Ms. Geetanjali R).

### 3. Technical terms
- **Network** = how computers talk over the internet.
- **Real-time** = data keeps updating live (here, every 5 seconds).

### 5. What to speak
> "Good morning. My project is called NetGuard — a Real-Time Network Analysis and Control System. It's a Windows app that watches my computer's internet activity live, warns me about dangerous connections, and lets me control which apps and websites can use the internet. I'm Esha Patel, guided by Ms. Geetanjali R."

### 6. Viva questions
- Why is it called "NetGuard"? → "Net" (network) + "Guard" (protect).
- What does "real-time" mean? → Continuously updating live data (every 5s).

### 8. Common mistakes
- Don't say "instant/real-time like a game." Say "continuously updating."

### 9. Key points
Project = watch + detect + control your PC's network, live.

### 10. Connects to next
"Now let me explain **why** this project is needed" → Problem Statement.

---

# SLIDE 2 — Problem Statement

### 1. Slide overview
Explains the **problem** your project solves and why it matters.

### 2. Every point (simple)
- Many apps use the internet **in the background** — you don't see them.
- So users **can't see or control** their network → slow internet + security risk.
- **Importance:** affects speed + can be a security danger + solving it gives control.
- **Real-world relevance:** students, home users, small offices face this; internet feels slow with no clear reason; hard to manage many apps at once.

### 3. Technical terms
- **Background app** = a program running without a visible window (e.g., an updater).
- **Bandwidth** = how much internet data is used (your "speed").

### 5. What to speak
> "These days our computers run many apps that use the internet quietly in the background. Normal users can't see which app is using their data or whether an app is talking to a dangerous server. This makes the internet slow and creates security risks. This is a common problem for students and home users. NetGuard solves this by giving clear visibility and control over network usage."

### 6. Viva questions
- Who faces this problem? → Students, home users, small offices.
- Why is background activity risky? → It can be malware silently sending data.

### 8. Common mistakes
- Don't just read bullets. Give the **chrome-using-data-silently** example.

### 9. Key points
Problem = no visibility + no control over background network use.

### 10. Connects to next
"To solve this, I set clear goals" → Objectives.

---

# SLIDE 3 — Objectives

### 1. Slide overview
The 5 **goals** the project set out to achieve.

### 2. Every point
1. **Real-time bandwidth monitoring** — show live upload/download speed.
2. **Per-application usage tracking** — show *which app* uses how much data.
3. **Threat detection using threat intelligence** — find dangerous connections using trusted databases.
4. **Application & website blocking** — let users block unwanted apps/sites.
5. **Parental controls** — website filtering, schedules, internet access management.

### 3. Technical terms
- **Upload** = data your PC sends out. **Download** = data it receives.
- **Threat intelligence** = ready-made databases of known-bad IPs/websites, maintained by security companies.
- **Parental controls** = features for parents to limit/protect usage.

### 5. What to speak
> "My project has five objectives. First, real-time bandwidth monitoring — showing live upload and download speeds. Second, per-application tracking — showing which app uses how much internet. Third, threat detection using trusted threat-intelligence sources like AbuseIPDB. Fourth, letting users block apps and websites. And fifth, parental controls like website filtering and schedules. These five together give complete visibility and control."

### 6. Viva questions
- Which objective was hardest? → Per-app bandwidth (needed ETW).
- What is threat intelligence? → Databases of known-bad IPs/URLs.
- Give an example threat-intel source. → AbuseIPDB, AlienVault OTX, Google Safe Browsing.

### 8. Common mistakes
- Don't confuse "threat intelligence" with antivirus. It checks *connections/IPs*, not files.

### 9. Key points
5 objectives = monitor, per-app, detect, block, parental.

### 10. Connects to next
"Now, how did I build it?" → Methodology.

---

# SLIDE 4 — Methodology (Approach + Tools)

### 1. Slide overview
**How** the project was built: the design approach and the main tools.

### 2. Every point
**Approach:**
- **Client–server architecture** on the local machine.
- **Backend** does monitoring + detection + control.
- **Desktop app (frontend)** shows the data.
- A **background service** keeps checking and creating alerts.

**Tools:**
- **psutil** — reads connections + bandwidth.
- **ETW** — accurate per-app bandwidth.
- **aiohttp** — fast, async calls to threat-intel APIs.
- **SQLite** — stores alerts/logs/history.
- **Windows Firewall & Hosts file** — block apps/websites.

### 3. Technical terms (very simple)
- **Client–server:** two parts — the **server** (backend) does the work; the **client** (frontend) shows it. *Analogy:* a restaurant — kitchen (server) cooks, waiter (client) serves.
- **Backend:** the "brain" that runs logic (Python + FastAPI).
- **Frontend:** the screen you see (PyQt5).
- **psutil:** a Python tool that reads system info (which app, how much data).
- **ETW (Event Tracing for Windows):** a built-in Windows feature that *tells* your program when network events happen → gives **accurate** per-app data.
- **aiohttp:** a Python tool to make many internet requests at once without waiting (**asynchronous**).
- **Asynchronous:** doing several things at once instead of one-by-one. *Analogy:* ordering food for 4 people at once, not waiting for each.
- **SQLite:** a small database stored in one file.
- **Windows Firewall:** the built-in gate that allows/blocks an app's internet.
- **Hosts file:** a small Windows file that maps website names to addresses — used to block sites.

### 5. What to speak
> "I used a client–server design. The backend, built with Python and FastAPI, does all the monitoring, threat detection, and blocking. The frontend, built with PyQt5, is the desktop window that shows everything. A background service keeps scanning every 5 seconds and raises alerts. For tools: psutil reads connections and bandwidth; ETW gives accurate per-app usage; aiohttp lets me call several threat APIs quickly; SQLite stores the data; and Windows Firewall plus the hosts file are used to block apps and websites."

### 6. Viva questions
- Why client–server? → UI stays responsive while backend does heavy work.
- Why ETW *and* psutil? → psutil for connections; ETW for accurate per-app bytes.
- What does async solve? → One slow API won't freeze the whole scan.

### 8. Common mistakes
- Don't say the frontend does the monitoring. The **backend** does; frontend only shows.

### 9. Key points
Backend = brain (FastAPI); Frontend = screen (PyQt5); psutil+ETW = monitor; aiohttp = fast APIs; SQLite = storage; Firewall+Hosts = blocking.

### 10. Connects to next
"Now, why these choices were good" → Methodology Justification.

---

# SLIDE 5 — Methodology (Justification)

### 1. Slide overview
**Why** the design choices are good.

### 2. Every point
- **Backend/GUI separation** → app stays responsive and efficient.
- **Local processing** → better privacy (data stays on your PC).
- **Asynchronous operations** → app doesn't freeze while checking threats.
- **Lightweight technologies** → low resource use, easy to deploy.

### 3. Technical terms
- **Responsive:** the app doesn't hang/freeze.
- **Privacy:** your data isn't sent to outsiders (only IPs go to reputation checks).
- **Deploy:** install and run on a computer.

### 5. What to speak
> "Separating the backend and the interface keeps the app smooth — heavy work happens in the background while the screen stays responsive. Processing locally protects privacy, because data stays on the user's own machine. Asynchronous operations mean the app never freezes while checking many IPs. And using lightweight tools keeps CPU and memory usage low, so it's easy to run and deploy."

### 6. Viva questions
- How does local processing help privacy? → Data isn't uploaded; only IPs are checked.
- What could freeze the app if not async? → Slow threat-API calls.

### 9. Key points
Separation = responsive; local = private; async = no freezing; lightweight = easy.

### 10. Connects to next
"Here's the overall design picture" → Architecture diagram.

---

# SLIDE 6 — System Design (Architecture Diagram)

### 1. Slide overview
A **picture** of all the parts and how data moves between them.

### 4. Explain the diagram (every box + arrow)
- **Dashboard (Frontend UI)** — the top box, what the user sees.
- **↕ REST API arrow** — the frontend and backend talk using **REST API** over HTTP. **REST API** = a set of web addresses (like `/api/alerts`) the frontend calls to get data.
- **Backend (Main controller)** — the central box; runs everything.
- Backend connects **down to 5 modules**:
  - **Net Monitor (psutil + ETW)** — reads connections/bandwidth.
  - **Threat Intel (IP & URL checks — AbuseIPDB, OTX, GSB)** — judges danger.
  - **Parental Ctrl (hosts file + firewall)** — blocks.
  - **AI Assistant & Summarization (via LLM)** — explains alerts.
  - **Usage Control (detect & allow/block)** — bandwidth decisions.
- **Database (bottom cylinder)** — stores `alerts | logs | checked_ips | blocked_apps | blocked_domains`. The cylinder shape always means "database."
- **Arrows = data flow.** Modules send results *down* into the database.

### 3. Technical terms
- **HTTP:** the language used to send web requests (GET/POST).
- **REST API:** a tidy way to build those requests using URLs.
- **LLM (Large Language Model):** the AI (Llama 3.2) that writes explanations.

### 5. What to speak
> "This is the architecture. At the top is the dashboard — the frontend the user sees. It talks to the backend through a REST API over HTTP. The backend is the main controller and connects to five modules: the network monitor using psutil and ETW; the threat-intelligence module that checks IPs and URLs against AbuseIPDB, OTX, and Google Safe Browsing; the parental-control module that blocks using the hosts file and firewall; the AI assistant that explains alerts; and the usage-control module for bandwidth decisions. All of these store their results in an SQLite database at the bottom, which holds alerts, logs, checked IPs, blocked apps, and blocked domains."

### 6. Viva questions
- What does the cylinder mean? → Database.
- How do frontend and backend communicate? → REST API over HTTP.
- Name the DB tables. → alerts, logs, checked_ips, blocked_apps, blocked_domains (also process_caps in code).

### 8. Common mistakes
- Don't say modules talk to each other directly — they all go **through the backend**.

### 9. Key points
UI → REST → Backend → 5 modules → Database.

### 10. Connects to next
"Let me explain each module" → Modules slide.

---

# SLIDE 7 — System Design (Modules)

### 1. Slide overview
Short description of each of the **8 modules**.

### 2. Every point (one simple line each)
- **Frontend** — the screen (dashboard, graphs, alerts, buttons).
- **Backend** — the brain (runs everything).
- **Network Monitoring** — tracks connections + per-app usage.
- **Threat Intelligence** — checks connections vs databases → risk score.
- **Bandwidth Control** — watches per-app usage vs limits → alerts.
- **Blocking & Control** — blocks apps/sites + parental features.
- **AI Integration** — explains alerts simply (local AI).
- **Database** — stores everything.

### 3. Technical terms
- **Risk score:** a single number 0–10 showing how dangerous a connection is.
- **Module:** one independent part of the program with one job.

### 5. What to speak
> "The project has eight modules. The frontend module is the visual dashboard. The backend module is the controller. The network-monitoring module tracks connections and per-app usage. The threat-intelligence module checks each connection against threat databases and gives a risk score from 0 to 10. The bandwidth-control module alerts when an app crosses a limit. The blocking-and-control module blocks apps and websites and provides parental controls. The AI module explains alerts in simple language. And the database module stores alerts, logs, and blocked items."

### 6. Viva questions
- Which module detects threats? → Threat Intelligence.
- Which stores data? → Database.
- What's a risk score range? → 0 to 10.

### 9. Key points
8 modules, each with one clear job.

### 10. Connects to next
"Here's how data flows through these modules" → Data flow.

---

# SLIDE 8 — System Design (Data Flow)

### 1. Slide overview
Step-by-step **journey of data** from opening the app to taking action.

### 2. Every point
1. Open NetGuard → backend monitors **every 5 seconds**.
2. Collect data → connections + per-app bandwidth read from the system.
3. Evaluate each connection → check IP vs databases; built-in **rules detect known malware ports**.
4. Calculate risk score → combine all into **0–10**.
5. Decision → low score = safe (just logged); high score = alert + notify.
6. Dashboard updates → live data, charts, alerts.
7. User acts → Block app (firewall rule), Block website (hosts file), Set schedule (next cycle).

### 3. Technical terms
- **Malware port:** a "door" number often used by bad software (e.g., 1337). Built-in **rules** flag these instantly, no internet needed.

### 5. What to speak
> "Here's the data flow. When the user opens NetGuard, the backend scans every 5 seconds. It reads the active connections and per-app bandwidth. For each connection, it checks the IP against threat databases and uses built-in rules to catch known malware ports. All results are combined into one risk score from 0 to 10. If the score is low, the connection is just logged; if it's high, an alert is saved and the user is notified. The dashboard updates live. Finally the user can act — block an app, which creates a firewall rule; block a website, which updates the hosts file; or set a schedule, applied on the next cycle."

### 6. Viva questions
- How often does it scan? → Every 5 seconds.
- What's a "high" score? → 6.5 or above triggers an alert (GSB flag → at least 8).
- How is an app blocked? → A Windows Firewall rule by the app's exe path.

### 8. Common mistakes
- Don't say every connection creates an alert — only **high-score** ones do.

### 9. Key points
Scan (5s) → check → score (0–10) → alert if high → user acts.

### 10. Connects to next
"These are the tools I used" → Tools & Technologies.

---

# SLIDE 9 — Tools & Technologies

### 1. Slide overview
A table of **all technologies** and what each does.

### 2. Every point
- **Python** — main language (backend + monitoring + GUI).
- **C# (.NET 8)** — the small ETW helper for accurate bandwidth.
- **FastAPI** — builds the backend API.
- **PyQt5** — builds the desktop window.
- **psutil** — reads network/system data.
- **aiohttp** — handles API communication.
- **SQLite** — stores alerts/logs.
- **Uvicorn** — runs the backend server.
- **Windows 10/11** — target OS.
- **Ollama + Llama 3.2** — local AI for explanations.
- **Windows Firewall** — blocks apps.
- **Hosts file** — blocks websites.
- **VS Code** — the editor used to build it.

### 3. Technical terms
- **C# / .NET 8:** a Microsoft language, good for Windows system features.
- **Uvicorn:** the program that actually runs a FastAPI app (the "engine").
- **Ollama:** software to run AI models on your own PC. **Llama 3.2:** the AI model.

### 5. What to speak
> "For technology: Python is my main language for the backend, monitoring, and GUI. A small C# .NET 8 helper gives accurate per-app bandwidth using ETW. FastAPI builds the backend API and Uvicorn runs it. PyQt5 builds the desktop interface. psutil reads system data, aiohttp handles API calls, and SQLite stores data. For AI, I use Ollama running Llama 3.2 locally, so explanations work offline with no API cost. Blocking uses Windows Firewall for apps and the hosts file for websites. I developed everything in VS Code on Windows."

### 6. Viva questions
- Why Python? → Easy + great libraries (psutil, scapy).
- Why FastAPI over Flask? → Async + auto interactive docs (`/docs`).
- Why local AI instead of an online one? → No API keys/quota, private, offline.
- Why C#? → Best access to Windows ETW for accurate bandwidth.

### 8. Common mistakes
- Don't say you used React — you used **PyQt5** (desktop).

### 9. Key points
Backend FastAPI (run by Uvicorn), Frontend PyQt5, Monitor psutil+ETW(C#), AI Ollama/Llama, Blocking Firewall+Hosts.

### 10. Connects to next
"Now the core logic/algorithms" → Implementation (Algorithms).

---

# SLIDE 10 — Implementation (Algorithms + Modules)

### 1. Slide overview
The four main **algorithms** (logic ideas) and the modules built.

### 2. Every point
**Algorithms:**
- **Risk Scoring System** — combine multiple sources into one score.
- **Port-Based Detection** — flag known bad ports.
- **IP Caching Mechanism** — remember recently-checked IPs to save API calls.
- **Alert Cooldown System** — stop repeated duplicate alerts.

**Modules implemented:** Network Monitor, Threat Detection, Bandwidth Tracker, App Blocker, Website Blocker, Parental Controls, Alert System.

### 3. Technical terms
- **Algorithm:** a step-by-step method to solve a problem.
- **Cache:** temporary storage of recent results to avoid redoing work. *Analogy:* keeping a phone number in your pocket instead of looking it up each time.
- **Cooldown:** a waiting time before doing something again (stops spam).

### 5. What to speak
> "I implemented four key algorithms. The risk-scoring system combines results from several threat sources into one number. Port-based detection instantly flags connections to known malware ports. The IP caching mechanism remembers IPs checked in the last five minutes so I don't call the paid APIs again and again. And the alert-cooldown system prevents the same alert from repeating and spamming the user. On top of these I built the network monitor, threat detection, bandwidth tracker, app and website blockers, parental controls, and the alert system."

### 6. Viva questions
- Why caching? → Save API calls, faster, avoid rate limits.
- Why cooldown? → Avoid duplicate alert spam.
- Is port detection online or offline? → Offline (local list).

### 9. Key points
4 algorithms: scoring, port detection, IP cache, alert cooldown.

### 10. Connects to next
"Let me show the actual code" → Code Snippets.

---

# SLIDE 11 — Implementation (Code Snippets)

### 1. Slide overview
Small pieces of **real code** for the four algorithms.

### 2 & 3. Explain each snippet (line by line, simple)

**Risk Scoring:**
```python
combined = (abuse_score * 0.65 + otx_score * 0.25) / (0.65 + 0.25)
if gsb_flagged:
    combined = max(combined, 8)
risk_score = round(min(10, combined), 1)
```
- Take the AbuseIPDB score, multiply by **0.65** (most trusted → biggest weight).
- Take the OTX score, multiply by **0.25** (supporting info → smaller weight).
- Divide by **(0.65+0.25)=0.9** → this makes it a fair **average** (this is called **normalizing**).
- If **Google Safe Browsing** flags it, force the score to at least **8** (Google is very reliable).
- `min(10, ...)` keeps it ≤ 10; `round(..., 1)` gives one decimal.
- **Why 0.65/0.25?** AbuseIPDB = direct abuse reports (strong); OTX = community mentions (weaker).

**Port-Based Detection:**
```python
if port in SUSPICIOUS_PORTS:
    label, reason = SUSPICIOUS_PORTS[port]
    return {"suspicious": True, "label": label, "reason": reason}
```
- `SUSPICIOUS_PORTS` is a list of bad ports (e.g., 1337 = backdoor). If the connection uses one, return "suspicious" with a label and reason.

**IP Caching:**
```python
if db.recently_checked(ip):
    continue
```
- If this IP was checked in the last 5 minutes, skip it (don't call APIs again).

**Alert Cooldown:**
```python
if _recently_pushed(push_key, ttl):
    return
```
- If this same alert was already shown recently (within `ttl` = time-to-live), don't show it again.

### 5. What to speak
> "These are real code snippets. The risk-scoring code multiplies AbuseIPDB's score by 0.65 and OTX's by 0.25, then divides by their sum to get a normalized weighted average — AbuseIPDB gets more weight because it's direct abuse reports. If Google Safe Browsing flags it, the score is forced to at least 8. The result is capped at 10. Port-based detection checks if the port is in my suspicious-ports list. IP caching skips IPs checked in the last five minutes. And the alert cooldown skips alerts already shown recently, so the user isn't spammed."

### 6. Viva questions
- Explain the risk formula. → (above).
- Why divide by 0.9? → To normalize into a fair 0–10 average.
- What is `ttl`? → Time-to-live; how long the cooldown lasts.
- What if GSB flags a domain? → Score forced to ≥ 8.

### 8. Common mistakes
- Don't say weights are 0.5/0.3 (old wrong version). It's **0.65/0.25 normalized**.

### 9. Key points
Weights 0.65 (AbuseIPDB) + 0.25 (OTX), normalized, GSB → ≥8, capped at 10.

### 10. Connects to next
"Here's the full step-by-step process" → Workflow.

---

# SLIDE 12 — Workflow (Step-by-step)

### 1. Slide overview
The 8 steps from launch to parental enforcement.

### 2. Every point (simple)
1. Launch → backend starts on **localhost:8765**.
2. Monitor scans connections **every 5s**.
3. Each new IP checked vs **AbuseIPDB, OTX, Google Safe Browsing**.
4. Risk score calculated (weighted formula).
5. High score → alert stored in SQLite + desktop notification.
6. User clicks alert → local **AI explanation**.
7. User can block app/domain from the interface.
8. Parental controls run in background (schedules + categories).

### 3. Technical terms
- **localhost:8765:** "localhost" = this same computer; "8765" = the port (door) the backend listens on.

### 5. What to speak
> "The workflow has eight steps. The user launches NetGuard and the backend starts on localhost port 8765. The monitor scans connections every five seconds. Each new IP is checked against AbuseIPDB, OTX, and Google Safe Browsing. A risk score is calculated using my weighted formula. If it's high, the alert is stored in SQLite and a desktop notification appears. The user can click the alert to get a simple AI explanation, and can block the app or domain directly. Meanwhile, parental controls run in the background, enforcing schedules and category rules automatically."

### 6. Viva questions
- What port does the backend use? → 8765.
- What is localhost? → The same computer (127.0.0.1).
- Where are alerts stored? → SQLite database.

### 9. Key points
Launch → scan 5s → check IP → score → alert+notify → AI explain → block → parental background.

### 10. Connects to next
"Now let me show the actual app" → Results (screenshots).

---

# SLIDES 13–17 — Results (Screenshots)

> These slides show the real app. For each, say **what screen it is, what's on it, and one highlight.**

### Slide 13 — Dashboard
- **Shows:** live Download/Upload KB/s, Active Alerts, Connections count, today's totals, a **live bandwidth graph**, and top data-consuming apps.
- **Say:** "This is the dashboard. It shows live upload and download speeds, the number of active connections, and a real-time bandwidth graph that updates every few seconds. It also lists the top data-consuming apps."
- **Q:** "Is the graph live?" → "Yes, it refreshes every few seconds."

### Slide 14 — Processes
- **Shows:** each app with PID, upload, download, connections, status (ALLOWED); **Block/Unblock Selected**; **Bandwidth Caps**; "Accurate Mode (Windows Only)".
- **Say:** "This is the Processes tab. It shows each app's PID, upload, download, and connection count. I can select an app and block it. Below, I can set bandwidth caps per app. 'Accurate Mode' means ETW is giving precise per-app data."
- **Q:** "What is PID?" → "Process ID — a unique number Windows gives each running program."
- **Q:** "What does Block do?" → "Creates a Windows Firewall rule to cut that app's internet."

### Slide 15 — Alerts
- **Shows:** alert list (time, severity, process, IP/domain, risk, message) + **AI Explanation** panel.
- **Say:** "This is the Alerts tab. Each alert shows the time, severity, the app, the risk score, and a message. When I click an alert, the local AI writes a simple explanation at the bottom."
- **Q:** "Where does the explanation come from?" → "Local Llama 3.2 via Ollama — offline."

### Slide 16 — Threat Check
- **Shows:** Check IP (e.g., 208.67.222.222 → SAFE, 2.8/10), Check URL (malware test URL → MALICIOUS, GSB Flagged), Ask AI / Summarize Activity.
- **Say:** "This is the Threat Check tab — a manual checker. I can type any IP to see its reputation, or any URL to see if it's malicious. Here a safe DNS IP shows SAFE, and a Google test malware URL shows MALICIOUS with Google Safe Browsing flagged. I can also ask the AI to summarize my activity."
- **Q:** "Are these results live?" → "Yes, from AbuseIPDB/OTX/GSB — no hardcoded IPs; only *ports* are hardcoded."

### Slide 17 — Parental Controls
- **Shows:** Pause Internet, Safe Mode, Category Blocking (Social Media, Gaming, etc.), App Schedules, Blocked Domains.
- **Say:** "This is Parental Controls. I can pause all internet instantly, turn on Safe Mode which auto-blocks malicious IPs and chosen categories, block content categories, schedule when an app is allowed, and block specific domains."
- **Q:** "How does category blocking work?" → "It blocks the domains belonging to that category via the hosts file/firewall when Safe Mode is on."
- **Q:** "How to stop a child disabling it?" → "A PIN lock is planned future work; currently it runs under the parent's admin account."

### Common mistakes (all Results slides)
- Don't just say "this is a screenshot." Explain **what each number/button means**.

### Connects to next
"Now, how I tested it" → Testing.

---

# SLIDE 18 — Testing

### 1. Slide overview
A table of **test cases** proving each feature works.

### 2. Every point
- **TC-01** Real-time monitoring → data updates live. ✅
- **TC-02** Malicious IP detection → flagged IP shows SUSPICIOUS. ✅
- **TC-03** Malicious URL detection → test URL shows MALICIOUS (GSB). ✅
- **TC-04** App blocking → firewall rule, app loses internet. ✅
- **TC-05** Website blocking → hosts file, site inaccessible. ✅
- **TC-06** App schedule → auto-block/unblock on time. ✅

### 3. Technical terms
- **Test case:** a planned check with steps + expected result + actual result + pass/fail.
- **Prerequisite:** what must be true before the test (e.g., "Run as Administrator").

### 5. What to speak
> "I tested all major features with six test cases. Real-time monitoring showed live updates. A flagged IP was correctly detected as suspicious, and a Google test malware URL as malicious. App blocking created a firewall rule and cut internet. Website blocking through the hosts file made a site inaccessible. And app scheduling automatically blocked and unblocked an app at the set time. All six passed."

### 6. Viva questions
- Why do TC-04/05/06 need admin? → Firewall and hosts file need admin rights.
- How did you test malicious IP safely? → Used a currently-flagged IP from AbuseIPDB, and a safe Google test URL.

### 8. Common mistakes
- Don't claim "Pass" if you didn't actually run it — re-run before viva.

### 9. Key points
6 test cases, all pass; blocking needs admin.

### 10. Connects to next
"Here are the challenges I faced" → Challenges.

---

# SLIDE 19 — Challenges

### 1. Slide overview
Problems during development and how you solved them.

### 2. Every point
- **Per-app usage was hard to measure** → used **ETW + psutil**.
- **Blocking needed admin** → app **auto-requests admin** at startup.
- **Repeated alerts spammed the user** → added an **alert cooldown**.
- **Gemini API hit free-quota limits** → switched to **local Ollama + Llama 3.2**.
- **Frequent threat checks slowed things** → used **IP caching + async requests**.

### 3. Technical terms
- **Quota/rate limit:** a cap on how many free API calls you get.
- **Admin (Administrator):** the higher-permission mode needed to change firewall/hosts.

### 5. What to speak
> "I faced several challenges. Measuring per-app usage accurately was hard, so I combined ETW with psutil. Blocking needed administrator rights, so the app auto-requests them at startup. Too many repeated alerts spammed the user, so I added a cooldown. The Gemini API kept hitting its free-quota limit and breaking explanations, so I switched to a local AI — Ollama with Llama 3.2 — which is free, offline, and has no quota. And frequent threat checks slowed performance, so I added IP caching and asynchronous requests."

### 6. Viva questions
- Why leave Gemini? → Free-quota limits broke it; local AI is free/offline/private.
- How did you fix alert spam? → Cooldown mechanism.
- How did you speed up threat checks? → Caching + async.

### 9. Key points
ETW, auto-admin, cooldown, local AI, caching+async.

### 10. Connects to next
"Here are the benefits" → Advantages.

---

# SLIDE 20 — Advantages

### 2. Every point
- Monitors + tracks per-app usage in real time.
- Detects suspicious connections quickly.
- Explains alerts in simple language.
- Blocks apps, websites, and content categories.
- Stores alerts/logs for later.
- Reduces repeated notifications (caching + cooldown).
**Improvements over existing systems:** simple UI, per-app (not just total) usage, multiple threat sources, lightweight, more user control.

### 5. What to speak
> "NetGuard's benefits: it monitors and tracks per-app usage live, detects suspicious connections quickly, and explains alerts in plain English. Users can block apps, sites, and categories, and all alerts are stored for later. Compared to existing tools, it's simpler, shows per-application usage instead of just totals, uses multiple threat sources for reliability, is lightweight, and gives more control."

### 6. Viva questions
- What's better than Task Manager? → Per-app *threat* info + blocking + AI explanations.
- Why "multiple threat sources"? → More reliable than one source.

### 9. Key points
Per-app + multi-source + simple + control = the edge.

### 10. Connects to next
"But it has limits too" → Limitations.

---

# SLIDE 21 — Limitations

### 2. Every point
- **Windows only** (uses Firewall + hosts).
- **Needs admin** to block.
- **Threat detection needs internet.**
- **Only the local PC** (not other devices).
**Areas for improvement:** ML detection, Linux/macOS, monitor all LAN devices, reduce API dependence, add user authentication for parental controls.

### 5. What to speak
> "It has honest limitations. It works only on Windows because it relies on the Windows Firewall and hosts file. It needs administrator rights to block. Threat detection needs an active internet connection. And it monitors only the local computer, not other devices. For improvement, I could add machine learning, support Linux and macOS, monitor all network devices, reduce API dependence with a local threat database, and add a PIN to protect parental settings."

### 6. Viva questions
- Why Windows only? → Uses Windows-specific Firewall + hosts file.
- What if internet is down? → Live IP/URL reputation won't work; port heuristics still do.

### 8. Common mistakes
- Don't hide limitations — examiners respect honesty.

### 9. Key points
Windows-only, admin-needed, internet-needed, local-only.

### 10. Connects to next
"Here's what I'd do next" → Future Work.

---

# SLIDE 22 — Future Work

### 2. Every point
**Enhancements:** ML detection, local threat database, user authentication, auto-block high-risk connections.
**Extensions:** Linux/macOS, monitor all LAN devices, mobile app, browser extension.

### 5. What to speak
> "In future, I'd enhance NetGuard with machine learning for smarter detection, a local threat database to depend less on external APIs, user authentication to protect parental settings, and automatic blocking of high-risk connections. I'd also extend it to Linux and macOS, monitor all devices on the network, build a mobile app for remote control, and create a browser extension that warns about unsafe sites in real time."

### 6. Viva questions
- Why no ML now? → It needs a large labeled dataset; reputation/heuristics are reliable and explainable for known threats. ML is future work.
- What's a local threat database? → Storing known-bad indicators on the PC to reduce internet dependence.

### 9. Key points
Future = ML, local DB, auth, auto-block, cross-platform, mobile, extension.

### 10. Connects to next
"To conclude" → Conclusion.

---

# SLIDE 23 — Conclusion

### 2. Every point
- NetGuard = real-time monitoring + security for Windows.
- Monitors, detects, blocks.
- Risk scoring identifies suspicious connections.
- Parental controls, bandwidth limits, scheduling.
- Simple explanations for alerts.
- **All 5 objectives achieved.**

### 5. What to speak
> "To conclude, NetGuard is a real-time network monitoring and security application for Windows. It monitors network activity, detects threats using a risk-scoring system, and lets users block apps and websites. Parental controls, bandwidth limits, and scheduling give better network management, and the local AI makes alerts easy to understand. All five objectives were achieved."

### 6. Viva questions
- Did you meet all objectives? → Yes — monitoring, detection, blocking, parental, easy explanations.
- Biggest learning? → Combining OS features (ETW/firewall) with threat intelligence and a clean client–server design.

### 9. Key points
All objectives met; monitor + detect + control + explain.

### 10. Connects to next
"Now the live demo" → Demo.

---

# SLIDE 24 — Demo

### 1. Slide overview
Placeholder for the **live demonstration**.

### 5. What to speak
> "Now I'll demonstrate NetGuard live." *(Then follow the demo order: Dashboard → Processes/Block → Threat Check IP+URL → suspicious port test → Alerts + AI explanation → Parental Controls.)*

### Demo tips
- Run **as Administrator**, keep **Ollama running**, have a **flagged IP** ready.
- Open `http://127.0.0.1:8765/docs` if you want to show the API.

### 10. Connects to next
"These are my references" → References.

---

# SLIDE 25 — References

### 1. Slide overview
The papers and documentation you used.

### 2. Every point
- **Papers [1]–[4]:** research on network monitoring, ML traffic classification, Python analyzers, and student cybersecurity awareness — they justify the problem and approach.
- **Web resources [5]–[9]:** official docs for FastAPI, psutil, AbuseIPDB, AlienVault OTX, Google Safe Browsing — the tools/APIs you used.

### 6. Viva questions
- Why cite these? → To base the work on credible sources and show the tools are real/documented.
- Which reference is your main threat source? → AbuseIPDB [7] + OTX [8] + Google Safe Browsing [9].

### 9. Key points
4 papers (justify problem/approach) + 5 web docs (tools/APIs).

---

# ✅ COMPLETE PPT SUMMARY (simple English)

NetGuard is a Windows desktop app that watches your computer's internet activity **live**, tells you which app uses how much data, warns you if a connection looks **dangerous** (using trusted threat databases), and lets you **block** apps or websites and set **parental controls**. It's built as a **client–server** app: a Python **FastAPI backend** does the work, a **PyQt5** desktop **frontend** shows it, an **SQLite** database stores everything, and a **local AI (Llama 3.2)** explains alerts in simple words. It scans every **5 seconds**, gives each connection a **risk score (0–10)**, and alerts you if the score is high. It blocks apps with the **Windows Firewall** and sites with the **hosts file**. All five objectives were achieved; main limits are Windows-only and needing admin + internet.

---

# 🎤 COMPLETE PRESENTATION SCRIPT (say this end-to-end)

*(Use the "What to speak" box from each slide, in order 1→25. Speak slowly, in your own words. Total ~12–15 minutes.)*

Opening: *"Good morning, I'm Esha Patel. My project is NetGuard — a Real-Time Network Analysis and Control System…"* → Problem → Objectives → Methodology → Architecture → Modules → Data flow → Tools → Algorithms → Code → Workflow → (show screenshots) → Testing → Challenges → Advantages → Limitations → Future work → Conclusion → *"Now I'll give a live demo."* → Demo → References → *"Thank you. I'm happy to answer questions."*

---

# 📝 100+ VIVA QUESTIONS WITH ANSWERS

**A. Basics (1–20)**
1. What is NetGuard? → Windows app for real-time network monitoring, threat detection, control.
2. Why "real-time"? → Live data, updated every 5 seconds.
3. Frontend tech? → PyQt5 (desktop).
4. Backend tech? → Python + FastAPI.
5. Backend port? → 8765 (localhost).
6. Database? → SQLite (`data/netguard.db`).
7. What is localhost? → The same computer (127.0.0.1).
8. What is a port? → A numbered "door" on an IP for a connection.
9. What is an IP address? → A computer's address on the internet.
10. What is a domain? → A website name (e.g., google.com).
11. What is bandwidth? → Data used per second.
12. Upload vs download? → Sent vs received data.
13. What is an API? → A way for programs to request data from each other.
14. What is REST? → A style of building APIs using URLs + HTTP methods.
15. What is JSON? → A text format for structured data.
16. What is a firewall? → A gate that allows/blocks network traffic.
17. What is the hosts file? → A Windows file mapping names to IPs, used to block sites.
18. What is threat intelligence? → Databases of known-bad IPs/URLs.
19. Which threat sources? → AbuseIPDB, OTX, Google Safe Browsing, URLhaus.
20. What is a risk score? → A 0–10 danger rating.

**B. Architecture & modules (21–40)**
21. Why client–server? → Responsive UI while backend does heavy work.
22. How do frontend/backend talk? → REST API over HTTP.
23. Name the 8 modules. → Frontend, Backend, Network Monitor, Threat Intel, Bandwidth Control, Blocking/Control, AI, Database.
24. What does the Network Monitor use? → psutil + ETW (+ scapy for packets).
25. What's ETW? → Windows Event Tracing → accurate per-app bytes.
26. What's psutil? → Python library reading system/connection info.
27. What's scapy? → Packet-capture library (optional).
28. Accurate vs Estimation mode? → Accurate = ETW (admin); Estimation = psutil fallback.
29. What does Threat Intel output? → A risk score.
30. What tables are in the DB? → alerts, logs, checked_ips, blocked_apps, blocked_domains, process_caps.
31. Why store checked_ips? → Cache to avoid repeat API calls (5 min).
32. What's aiohttp? → Async HTTP client for fast API calls.
33. Why async? → One slow API won't freeze the scan.
34. Who runs FastAPI? → Uvicorn.
35. What's the AI module? → Local Llama 3.2 via Ollama for explanations.
36. Why local AI? → No keys/quota, offline, private.
37. What's PID? → Process ID (unique number per running program).
38. How block an app? → Firewall rule by exe path (`netsh`).
39. How block a site? → Add domain to hosts file → 127.0.0.1.
40. What's Safe Mode? → Auto-blocks malicious IPs + chosen categories.

**C. Algorithms & code (41–60)**
41. Explain the risk formula. → (abuse×0.65 + otx×0.25)/0.9; GSB→≥8; cap 10.
42. Why 0.65 vs 0.25? → AbuseIPDB is direct abuse reports (stronger); OTX is corroborating.
43. Why divide by 0.9? → Normalize into a fair average.
44. What if GSB flags it? → Force score ≥ 8.
45. Port-based detection — online? → No, offline local list.
46. Example bad ports? → 1337 (backdoor), 4444 (Metasploit), 9050 (Tor).
47. What's IP caching? → Skip IPs checked within 5 minutes.
48. What's alert cooldown? → Skip alerts already shown recently (ttl).
49. What's ttl? → Time-to-live; cooldown duration.
50. Alert threshold? → ≥ 6.5 triggers an alert.
51. Why not alert every connection? → Too noisy; only high-risk.
52. Two-phase loop? → Phase 1 instant port alerts; Phase 2 concurrent IP checks.
53. Why concurrent IP checks? → Avoid one slow API stalling the sweep.
54. Reverse DNS use? → Turn IP into hostname for Safe Browsing.
55. What does `continue` do in the cache snippet? → Skip to the next connection.
56. What's `max(combined, 8)`? → Ensures at least 8 when GSB flags.
57. What's `round(..., 1)`? → One decimal place.
58. Is scoring ML? → No, it's a weighted rule; ML is future work.
59. Where is the port list? → `port_checker.py` (`SUSPICIOUS_PORTS`).
60. Where is the risk formula? → `threat_intel.py` (`_combine_risk`).

**D. Networking & security (61–80)**
61. TCP vs UDP? → Both are transport protocols; TCP reliable, UDP fast.
62. What's a socket? → An IP+port connection endpoint.
63. What's a malware port? → A port often used by bad software.
64. What's an IoC? → Indicator of Compromise (bad IP/domain/port).
65. What's reputation scoring? → Rating an IP by past behavior.
66. What's a heuristic? → A rule-of-thumb detection (e.g., bad ports).
67. What's defense in depth? → Multiple protection layers.
68. What's least privilege? → Ask for admin only when needed.
69. Why privacy-friendly? → Local processing; only IPs sent to reputation APIs.
70. What is packet sniffing? → Reading packets at the network card.
71. Does sniffing read content? → No, only headers (from/to/protocol).
72. What if scapy is unavailable? → psutil + ETW still work; only packet feed is lost.
73. What's HTTPS? → Encrypted HTTP.
74. Can you block HTTPS sites? → Yes, by domain (hosts) or app (firewall).
75. What's a DoS? → Flooding to overwhelm — *not* part of NetGuard.
76. Is NetGuard an antivirus? → No; it checks connections, not files.
77. Is your data uploaded anywhere? → No; only IPs go to reputation checks.
78. Can it stop malware? → It can detect risky connections and block apps/sites; it's not a full AV.
79. What's Google Safe Browsing? → Google's live malware/phishing URL list.
80. What's AbuseIPDB confidence? → % of how likely an IP is abusive.

**E. Tricky / scenario / follow-ups (81–100+)**
81. "Is it truly real-time?" → Real-time monitoring sense: 5-second polling; ETW bandwidth is event-driven.
82. "Did you hardcode the malicious IPs?" → No — no IP list in code; scores are live. Only *ports* are hardcoded (searchable proof).
83. "Why does auto-block not slow chrome to the KB/s number?" → The cap is a trigger, not a speed limiter; firewall can only allow/block.
84. "Why did you get repeated cap alerts?" → A fixed bug — the controller kept re-alerting after blocking; fixed by skipping once already blocked.
85. "Why did 'Block Selected' fail once?" → ETW rows lacked the exe path; fixed by resolving the path from the PID.
86. "What if two apps use the same port?" → Port detection flags the port regardless of app; that's intended.
87. "How accurate is bandwidth?" → Accurate mode (ETW) is precise per-PID; estimation is approximate.
88. "How do you prevent API abuse?" → IP cache (5 min) + async batching.
89. "What happens with no API keys?" → It falls back to simulated deterministic scoring (not a hardcoded blacklist).
90. "Why SQLite not MySQL?" → Local, single-user, zero-config, private.
91. "Why FastAPI not Flask?" → Async + auto `/docs`.
92. "Why PyQt5 not a web UI?" → Native desktop app, rich widgets, charts.
93. "How to stop a child disabling parental controls?" → PIN lock is future work; currently runs under parent's admin.
94. "Biggest challenge?" → Accurate per-app bandwidth (solved with ETW + PID resolution).
95. "What's your original contribution?" → Integrating multi-source threat intel + port heuristics + ETW usage control + local-AI explanations into one lightweight tool, with the scoring/adaptive logic.
96. "What's the weakest part?" → No ML yet; Windows-only.
97. "Show me it's real, not fake." → Open `/docs`, run a live IP check; search code for the IP (not found).
98. "What is Uvicorn's role?" → It's the server that runs the FastAPI app.
99. "What is normalization here?" → Dividing by the weight sum so the score is a fair average.
100. "If internet fails during demo?" → Port heuristics + cached results + the UI still work; explain the dependency honestly.
101. "Why is 35.190.x flagged sometimes?" → Shared Google Cloud IP with old abuse reports → provider-level false positive; GSB clears it.
102. "How is a domain 'category' blocked?" → Its domains are added to the hosts file/firewall when Safe Mode is on.

---

# 🧑‍⚖️ MOCK EXTERNAL VIVA (practice, answer out loud)

1. "In one minute, explain NetGuard and why you built it."
2. "Draw and explain your architecture."
3. "What exactly is 'real-time' here? Justify it."
4. "Open the app and block an app live — explain what happens on the OS."
5. "Explain your risk-scoring formula, and why the weights aren't equal."
6. "Show me a live threat check and prove the result isn't hardcoded."
7. "Why local AI instead of Gemini?"
8. "What breaks if the internet is off?"
9. "How would you stop a child turning off parental controls?"
10. "What's your project's biggest limitation, and how would you fix it?"

*After each: state **what → why → one limit**. If unsure, say "In my current version it works like X; a better approach would be Y" — honesty scores well.*

---

# ⚡ FINAL REVISION SHEET

**Definitions to memorize**
- Threat intelligence = databases of known-bad IPs/URLs.
- Risk score = 0–10 danger rating.
- ETW = Windows event tracing → accurate per-app bytes.
- Firewall rule = allow/deny an app's traffic.
- Hosts file = local name→IP map used to block sites.
- Polling = checking at fixed intervals (5s).
- Cache/cooldown = avoid repeat work / repeat alerts.
- Normalization = divide by weight sum → fair average.

**Key numbers**
- Port **8765** (backend), scan every **5 seconds**, alert at **≥6.5**, GSB → **≥8**, cache **5 min**.
- Weights: AbuseIPDB **0.65**, OTX **0.25**.

**Key ports:** 1337 (backdoor), 4444 (Metasploit), 6667 (IRC botnet), 9050 (Tor), 5900 (VNC).

**Pieces:** Frontend **PyQt5** · Backend **FastAPI** (run by **Uvicorn**) · DB **SQLite** · AI **Ollama/Llama 3.2** · Monitor **psutil + ETW + scapy** · Block **Firewall + Hosts**.

**Common mistakes to avoid**
- Saying "React" (it's PyQt5) or "MySQL" (it's SQLite).
- Saying weights are 0.5/0.3 (they're 0.65/0.25 normalized).
- Overclaiming "instant real-time" (it's 5-second polling).
- Claiming IPs are hardcoded (only ports are).
- Hiding limitations (be honest).

**Confidence tips**
- Speak slowly; use "what → why → limit."
- If stuck: "In my version it works like this; a future improvement would be…"
- Always be ready to open `/docs` and do one live check.

*You understand your project now — explain it in your own words, be honest about limits, and demo confidently. All the best! 🎉*
