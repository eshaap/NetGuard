"""
NetGuard - Real-Time Network Analysis + Threat Detection Tool
Backend: FastAPI server
"""

import asyncio
import ctypes
from collections import deque
import json
import os
import sys
import sqlite3
import time
import random
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from network_monitor import NetworkMonitor
from threat_intel import ThreatIntelligence
from local_ai import LocalAI
from database import Database
from parental_control import ParentalControl
from parental_features import (
    CategoryManager, PauseManager, ScheduleManager, ActivitySummary,
)
from adaptive_bandwidth_controller import AdaptiveBandwidthController
from notifier import notify_alert, notify_block, show_system_notification
from port_checker import check_connection

app = FastAPI(title="NetGuard API", version="1.0.0")


CONFIG_FILE = Path(__file__).parent / "config.json"


def _is_windows_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ensure_admin():
    """Relaunch the backend with elevation so hosts-file and firewall writes succeed."""
    if os.name != "nt":
        return
    if os.environ.get("NETGUARD_ELEVATED") == "1":
        return
    if _is_windows_admin():
        os.environ["NETGUARD_ELEVATED"] = "1"
        return

    params = f'"{Path(__file__).resolve()}"'
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            str(Path(__file__).resolve().parent),
            1,
        )
    except Exception as exc:
        raise RuntimeError(f"Administrator privileges are required to run NetGuard: {exc}")
    raise SystemExit(0)


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize modules
CONFIG = load_config()
SETTINGS = CONFIG.get("settings", {})
MONITOR_INTERVAL_SECONDS = max(1, int(SETTINGS.get("monitor_interval_seconds", 5)))
ALERT_RISK_THRESHOLD = float(SETTINGS.get("alert_risk_threshold", 7.0))
MAX_ALERTS_IN_MEMORY = max(10, int(SETTINGS.get("max_alerts_in_memory", 100)))
ENABLE_DEMO_ALERTS = bool(SETTINGS.get("enable_demo_alerts", False))
BANDWIDTH_CONTROL_ENABLED = bool(SETTINGS.get("bandwidth_control_enabled", True))
BANDWIDTH_THRESHOLD_KBPS = float(SETTINGS.get("bandwidth_threshold_kbps", 1024.0))
BANDWIDTH_AUTO_BLOCK = bool(SETTINGS.get("bandwidth_auto_block", False))
BANDWIDTH_ALERT_COOLDOWN = max(1, int(SETTINGS.get("bandwidth_alert_cooldown_seconds", 30)))

db = Database()
monitor = NetworkMonitor()
threat_intel = ThreatIntelligence()
ai = LocalAI(db=db)
parental = ParentalControl(db)
categories = CategoryManager(db, parental)
pause_mgr = PauseManager(db)
schedules = ScheduleManager(db, parental)
activity = ActivitySummary(db)
bandwidth_controller = AdaptiveBandwidthController(
    db=db,
    threshold_kbps=BANDWIDTH_THRESHOLD_KBPS,
    auto_block=BANDWIDTH_AUTO_BLOCK,
    cooldown_seconds=BANDWIDTH_ALERT_COOLDOWN,
)

# In-memory alerts store (also persisted to DB)
active_alerts = deque(maxlen=MAX_ALERTS_IN_MEMORY)
monitoring_active = True
show_demo_alerts = ENABLE_DEMO_ALERTS  # Toggle to show/hide demo alerts
demo_alert_ids = set()  # Track which alerts are demo alerts
last_adaptive_actions = []
last_process_sample_count = 0
last_adaptive_alerts = []


def _lookup_process_executable(process_name: str, process_rows: list) -> str:
    """Best-effort lookup of an executable path for a process name."""
    target = (process_name or "").strip().lower()
    if not target:
        return ""

    for row in process_rows or []:
        if (row.get("process") or "").strip().lower() == target and row.get("exe"):
            return row.get("exe", "")
    return ""


def _resolve_exe_live(process_name: str, pid=None) -> str:
    """Resolve a process's executable path from the live process table.

    Accurate/ETW mode often reports processes without an exe path, but Windows
    Firewall needs the full path to create a block rule. psutil can recover it
    from the PID (preferred) or by matching the process name.
    """
    try:
        import psutil
    except Exception:
        return ""
    if pid:
        try:
            return (psutil.Process(int(pid)).exe() or "").strip()
        except Exception:
            pass
    target = (process_name or "").strip().lower()
    if not target:
        return ""
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if (proc.info.get("name") or "").strip().lower() == target and proc.info.get("exe"):
                return (proc.info["exe"] or "").strip()
        except Exception:
            continue
    return ""


def _store_alert(alert: dict):
    """Persist an alert in memory and in SQLite."""
    active_alerts.appendleft(alert)
    db.save_alert(alert)


def _extract_threat_summary(ip_result: dict) -> dict:
    """Pull a few compact, real evidence fields off a check_ip() result so the
    AI can explain the alert accurately later. No model call here (lazy)."""
    ip_result = ip_result or {}
    details = ip_result.get("details", {}) or {}
    abuse = details.get("abuseipdb", {}) or {}
    return {
        "abuse_confidence": abuse.get("confidence"),
        "abuse_reports": abuse.get("total_reports", 0),
        "country": abuse.get("country", ""),
        "isp": abuse.get("isp", ""),
        "otx_pulses": ip_result.get("otx_pulses", 0),
        "gsb_flagged": ip_result.get("gsb_flagged", False),
        "gsb_threat_type": ip_result.get("gsb_threat_type", ""),
        "domain": ip_result.get("domain", ""),
    }


async def _build_threat_alert(conn: dict, ip: str, domain: str, risk_score: float, ip_result: dict, action_taken: str, action_note: str = "") -> dict:
    """Create a normalized malicious-IP alert payload. The AI explanation is
    generated lazily (on click) — here we only attach the compact evidence."""
    message = f"Malicious IP detected: {ip} (Risk: {risk_score}/10)"
    if action_note:
        message = f"{message} - {action_note}"

    return {
        "id": f"alert_{int(time.time())}_{random.randint(1000,9999)}",
        "type": "malicious_ip",
        "severity": "high" if risk_score >= 9 else "medium",
        "process": conn.get("process", "unknown"),
        "ip": ip,
        "domain": domain or ip,
        "message": message,
        "threat_summary": _extract_threat_summary(ip_result),
        "timestamp": datetime.now().isoformat(),
        "risk_score": risk_score,
        "action_taken": action_taken,
    }


def handle_packet_threat_result(packet_info: dict, threat_result: dict):
    """Create alerts for high-risk IPs discovered by lightweight packet sampling."""
    risk_score = threat_result.get("risk_score", 0)
    ip = threat_result.get("ip")
    if risk_score < 5 or not ip:
        return

    alert = {
        "id": f"packet_alert_{int(time.time())}_{random.randint(1000,9999)}",
        "type": "packet_malicious_ip",
        "severity": "high" if risk_score >= 9 else "medium",
        "process": "packet_sniffer",
        "ip": ip,
        "domain": ip,
        "message": (
            f"Packet-level monitor observed {ip} "
            f"({packet_info.get('protocol', 'IP')}, Risk: {risk_score}/10)"
        ),
        "timestamp": datetime.now().isoformat(),
        "risk_score": risk_score,
        "action_taken": "alert" if risk_score >= ALERT_RISK_THRESHOLD else "monitored"
    }
    _store_alert(alert)
    notify_alert(alert)
    db.recently_checked(ip)


@app.on_event("startup")
async def startup_event():
    """Initialize database and start background monitoring."""
    global active_alerts
    db.init_db()

    # Prefer accurate (ETW) per-process bandwidth. Silently fall back to
    # estimation if it can't start (not elevated, helper missing, etc.).
    try:
        mode_result = monitor.set_mode("accurate")
        if mode_result.get("ok"):
            print("[NetGuard] Accurate per-process bandwidth (ETW) enabled.")
        else:
            print(f"[NetGuard] Estimation mode: {mode_result.get('error', 'ETW unavailable')}")
    except Exception as exc:
        print(f"[NetGuard] Accurate mode unavailable, using estimation: {exc}")

    show_system_notification(
        "NetGuard Started",
        "Background monitoring is active. You will be notified of threats.",
    )
    
    if ENABLE_DEMO_ALERTS:
        # Optional seed data for UI demos only.
        global demo_alert_ids
        demo_alerts = [
            {
                "id": "demo_alert_001",
                "type": "malicious_ip",
                "severity": "high",
                "process": "svchost.exe",
                "ip": "203.0.113.45",
                "domain": "malicious-c2.ru",
                "message": "Backdoor.Win32.Agent detected",
                "timestamp": (datetime.now() - timedelta(seconds=30)).isoformat(),
                "risk_score": 9,
                "action_taken": "blocked"
            },
            {
                "id": "demo_alert_002",
                "type": "suspicious_domain",
                "severity": "medium",
                "process": "chrome.exe",
                "ip": "203.0.113.45",
                "domain": "Suspicious Domain Request",
                "message": "Suspicious Domain Request detected",
                "timestamp": (datetime.now() - timedelta(seconds=120)).isoformat(),
                "risk_score": 6,
                "action_taken": "monitored"
            },
            {
                "id": "demo_alert_003",
                "type": "malicious_ip",
                "severity": "high",
                "process": "unknown_pkg_92",
                "ip": "198.51.100.89",
                "domain": "Outbound Port Scanning",
                "message": "Outbound Port Scanning detected",
                "timestamp": (datetime.now() - timedelta(seconds=240)).isoformat(),
                "risk_score": 8,
                "action_taken": "terminated"
            },
        ]
        active_alerts.extend(demo_alerts)
        demo_alert_ids = {alert["id"] for alert in demo_alerts}
    
    monitor.start_packet_sniffing(
        threat_intel=threat_intel,
        event_loop=asyncio.get_running_loop(),
        packet_count=100,
        packet_filter="ip and (tcp or udp)",
        result_callback=handle_packet_threat_result,
    )
    asyncio.create_task(background_monitor())


@app.on_event("shutdown")
async def shutdown_event():
    """Close async resources before shutting down the API."""
    await threat_intel.close()


async def background_monitor():
    """Background task: monitor network and check for threats."""
    global active_alerts, monitoring_active
    while True:
        if monitoring_active:
            try:
                # Get current connections
                connections = monitor.get_active_connections()
                process_rows = monitor.get_process_usage()

                # ── Phase 1: instant local heuristics (no network I/O) ──
                # Suspicious-port/process detection is a local lookup, so fire those
                # alerts immediately instead of letting them queue behind the slow
                # threat-intel API calls. IPs that still need a reputation lookup are
                # collected and checked concurrently in Phase 2.
                pending = []
                for conn in connections:
                    ip = conn.get("remote_ip")
                    domain = conn.get("domain")

                    if not ip or ip in ("", "0.0.0.0", "127.0.0.1"):
                        continue

                    # Port/process heuristic runs BEFORE the IP cache check so
                    # torrent clients and suspicious ports are always detected,
                    # even for peer IPs that were recently seen as "clean".
                    port_result = check_connection(conn)
                    if port_result["suspicious"] and not db.recently_checked_port(ip, conn.get("remote_port", 0)):
                        port_risk = port_result["risk_boost"]
                        port_alert = {
                            "id": f"alert_port_{int(time.time())}_{random.randint(1000,9999)}",
                            "type": "suspicious_port",
                            "severity": port_result["severity"],
                            "process": conn.get("process", "unknown"),
                            "ip": ip,
                            "domain": domain or ip,
                            "message": (
                                f"Connection to suspicious port "
                                f"{port_result['port']} "
                                f"({port_result['label']}): "
                                f"{port_result['reason']}"
                            ),
                            "timestamp": datetime.now().isoformat(),
                            "risk_score": min(10, port_risk),
                            "action_taken": "monitored",
                        }
                        _store_alert(port_alert)
                        notify_alert(port_alert)

                    # Check if already recently checked (avoid spam on IP reputation)
                    if db.recently_checked(ip):
                        continue

                    pending.append((conn, ip, domain, port_result))

                # ── Phase 2: threat-intel reputation lookups run concurrently ──
                # Previously each IP was awaited one-at-a-time, so a single slow or
                # timing-out API (e.g. OTX) stalled every later connection in the
                # sweep — that was the cause of very late alerts. Running the lookups
                # together (bounded by a semaphore so we don't open too many sockets
                # at once) means one slow lookup no longer delays the others.
                if pending:
                    lookup_sem = asyncio.Semaphore(8)

                    async def _lookup_ip(target_ip):
                        async with lookup_sem:
                            return await threat_intel.check_ip(target_ip)

                    ip_results = await asyncio.gather(
                        *[_lookup_ip(ip) for (_, ip, _, _) in pending],
                        return_exceptions=True,
                    )

                    for (conn, ip, domain, port_result), ip_result in zip(pending, ip_results):
                        # A failed/timed-out lookup must not abort the whole sweep.
                        if not isinstance(ip_result, dict):
                            print(f"[Threat Intel] lookup failed for {ip}: {ip_result}")
                            continue

                        risk_score = ip_result.get("risk_score", 0)

                        # Boost risk score if the port/process is also suspicious
                        if port_result["suspicious"]:
                            risk_score = min(10, risk_score + port_result["risk_boost"])

                        # Check if parental control violation
                        if domain and parental.is_blocked_domain(domain):
                            alert = {
                                "id": f"alert_{int(time.time())}_{random.randint(1000,9999)}",
                                "type": "parental_control",
                                "severity": "medium",
                                "process": conn.get("process", "unknown"),
                                "ip": ip,
                                "domain": domain or ip,
                                "message": f"Blocked domain accessed: {domain}",
                                "timestamp": datetime.now().isoformat(),
                                "risk_score": 5,
                                "action_taken": "blocked"
                            }
                            _store_alert(alert)
                            notify_alert(alert)

                        elif risk_score >= ALERT_RISK_THRESHOLD:
                            action_taken = "monitored"
                            action_note = "monitoring recommended"

                            if risk_score >= 9 and parental.safe_mode:
                                block_result = None
                                normalized_domain = parental._normalize_domain(domain or "")
                                if normalized_domain:
                                    block_result = parental.block_domain(normalized_domain)
                                    if block_result.get("ok"):
                                        db.log_action("safe_mode_block_domain", normalized_domain)
                                        action_taken = "blocked"
                                        action_note = f"Safe Mode blocked domain {normalized_domain}"
                                    else:
                                        action_taken = "alert"
                                        action_note = f"Safe Mode could not block domain: {block_result.get('error', 'unknown error')}"
                                else:
                                    process_name = conn.get("process", "unknown")
                                    exe_path = _lookup_process_executable(process_name, process_rows)
                                    if exe_path:
                                        block_result = parental.block_app(process_name, exe_path)
                                        if block_result.get("ok"):
                                            db.log_action("safe_mode_block_app", process_name)
                                            action_taken = "blocked"
                                            action_note = f"Safe Mode blocked process {process_name}"
                                        else:
                                            action_taken = "alert"
                                            action_note = f"Safe Mode could not block process: {block_result.get('error', 'unknown error')}"
                                    else:
                                        action_taken = "alert"
                                        action_note = "Safe Mode could not find a domain or executable path to block"
                            elif risk_score >= ALERT_RISK_THRESHOLD:
                                action_taken = "alert"
                                action_note = "review recommended"

                            alert = await _build_threat_alert(
                                conn=conn,
                                ip=ip,
                                domain=domain,
                                risk_score=risk_score,
                                ip_result=ip_result,
                                action_taken=action_taken,
                                action_note=action_note,
                            )
                            _store_alert(alert)
                            notify_alert(alert)

                if BANDWIDTH_CONTROL_ENABLED:
                    global last_process_sample_count
                    last_process_sample_count = len(process_rows)
                    bandwidth_actions = bandwidth_controller.check_usage_and_control(process_rows)
                    global last_adaptive_actions
                    last_adaptive_actions = bandwidth_actions[:20]
                    global last_adaptive_alerts
                    last_adaptive_alerts = [
                        {
                            "process": action.get("process", ""),
                            "exe": action.get("exe", ""),
                            "upload_kbps": action.get("upload_kbps", 0),
                            "download_kbps": action.get("download_kbps", 0),
                            "total_kbps": action.get("total_kbps", 0),
                            "alert": action.get("alert", {}),
                        }
                        for action in bandwidth_actions[:20]
                    ]
                    for action in bandwidth_actions:
                        alert = action.get("alert")
                        if alert:
                            active_alerts.appendleft(alert)
                            notify_alert(alert)

                try:
                    schedules.tick()
                except Exception as sched_err:
                    print(f"[Schedule Error] {sched_err}")

            except Exception as e:
                print(f"[Monitor Error] {e}")

        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)


# ─────────────────────────── API ENDPOINTS ───────────────────────────

@app.get("/api/bandwidth")
async def get_bandwidth():
    """Real-time bandwidth stats."""
    return monitor.get_bandwidth()


@app.get("/api/connections")
async def get_connections():
    """All active network connections with process info."""
    return monitor.get_active_connections()


@app.get("/api/packets")
async def get_packets(limit: int = 50):
    """Recently captured lightweight packet metadata from Scapy."""
    return monitor.recent_packets[:max(1, min(limit, 100))]


@app.get("/api/packets/status")
async def get_packet_status():
    """Packet sniffer health information."""
    return {
        "active": monitor.packet_sniffing_active,
        "error": monitor.packet_sniffing_error,
        "captured": len(monitor.recent_packets),
        "threat_results": len(monitor.packet_threat_results),
    }


@app.get("/api/processes")
async def get_processes():
    """Per-process network usage."""
    return monitor.get_process_usage()


@app.get("/api/processes/mode")
async def get_process_mode():
    return {"mode": monitor.get_mode()}


@app.post("/api/processes/mode")
async def set_process_mode(data: dict):
    mode = data.get("mode", "estimation")
    result = monitor.set_mode(mode)
    return result


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Get recent alerts."""
    global show_demo_alerts, demo_alert_ids
    if show_demo_alerts:
        return list(active_alerts)[:limit]
    else:
        # Filter out demo alerts
        real_alerts = [alert for alert in active_alerts if alert.get("id") not in demo_alert_ids]
        return real_alerts[:limit]


@app.post("/api/alerts/toggle-demo")
async def toggle_demo_alerts(data: dict):
    """Toggle visibility of demo alerts."""
    global show_demo_alerts
    if "show_demo" in data:
        show_demo_alerts = bool(data["show_demo"])
    else:
        show_demo_alerts = not show_demo_alerts
    return {"show_demo_alerts": show_demo_alerts}


@app.get("/api/alerts/demo-status")
async def get_demo_status():
    """Get current demo alert visibility status."""
    return {
        "show_demo_alerts": show_demo_alerts,
        "demo_alerts_enabled": ENABLE_DEMO_ALERTS,
        "demo_alert_count": len(demo_alert_ids),
    }


@app.get("/api/alerts/history")
async def get_alert_history():
    """Get historical alerts from database."""
    return db.get_alerts()


@app.post("/api/check/ip/{ip}")
async def check_ip(ip: str):
    """Manually check an IP address."""
    result = await threat_intel.check_ip(ip)
    return result


@app.post("/api/check/url")
async def check_url(data: dict):
    """Check a URL for malicious content."""
    url = data.get("url", "")
    result = await threat_intel.check_url(url)
    return result


@app.get("/api/processes/blocked")
async def get_blocked_processes():
    """List of blocked processes."""
    return {
        "manual_blocks": parental.get_blocked_apps(),
        "adaptive_blocks": bandwidth_controller.get_blocked_processes(),
    }


@app.post("/api/processes/block")
async def block_process(data: dict):
    """Block an application from internet access."""
    process = data.get("process")
    executable_path = data.get("exe", "")
    # Accurate/ETW mode often sends an empty exe path; firewall blocking needs it,
    # so recover it from the live process table (by PID, else by name).
    if not (executable_path or "").strip():
        executable_path = _resolve_exe_live(process, data.get("pid"))
    source = (data.get("source") or "manual").lower()
    if source == "adaptive":
        result = bandwidth_controller.block_process(process, executable_path)
        db.log_action("block_app_adaptive", process)
    else:
        result = parental.block_app(process, executable_path)
        db.log_action("block_app", process)
    if result.get("ok"):
        notify_block("app", process)
    return {"status": "blocked", "process": process, **result}


@app.post("/api/processes/unblock")
async def unblock_process(data: dict):
    """Unblock an application."""
    process = data.get("process")
    source = (data.get("source") or "manual").lower()
    if source == "adaptive":
        result = bandwidth_controller.unblock_process(process)
        db.log_action("unblock_app_adaptive", process)
    else:
        result = parental.unblock_app(process)
        db.log_action("unblock_app", process)
    return {"status": "unblocked", "process": process, **result}


@app.get("/api/parental/domains/blocked")
async def get_blocked_domains():
    """Get list of blocked domains."""
    return parental.get_blocked_domains()


@app.post("/api/parental/domains/block")
async def block_domain(data: dict):
    """Block a domain (parental control)."""
    domain = data.get("domain")
    result = parental.block_domain(domain)
    if result.get("ok"):
        db.log_action("block_domain", result.get("domain", domain or ""))
        notify_block("domain", result.get("domain", domain or ""))
    return {"status": "blocked" if result.get("ok") else "error", **result}


@app.post("/api/parental/domains/unblock")
async def unblock_domain(data: dict):
    """Unblock a domain (parental control)."""
    domain = data.get("domain")
    result = parental.unblock_domain(domain)
    if result.get("ok"):
        db.log_action("unblock_domain", result.get("domain", domain or ""))
    return {"status": "unblocked" if result.get("ok") else "error", **result}


@app.post("/api/parental/safemode")
async def toggle_safe_mode(data: dict):
    """Safe Mode is the master switch for parental control:
      - ON  -> applies every checked category + arms threat-intel auto-block.
      - OFF -> lifts every category block (selection is kept for next time)
               and stops the threat-intel auto-block.
    """
    enabled = bool(data.get("enabled", True))
    parental.set_safe_mode(enabled)
    cat_result = categories.apply_all_enabled() if enabled else categories.unapply_all_enabled()
    return {"safe_mode": enabled, "categories": cat_result}


@app.get("/api/parental/safemode")
async def get_safe_mode():
    return {"safe_mode": parental.safe_mode}


# ─── Category Blocking ────────────────────────────────────────────────

@app.get("/api/parental/categories")
async def list_categories():
    return categories.list_categories()


@app.post("/api/parental/categories")
async def set_category(data: dict):
    category = (data.get("category") or "").strip()
    enabled = bool(data.get("enabled", False))
    return categories.set_enabled(category, enabled)


# ─── Instant Pause ────────────────────────────────────────────────────

@app.get("/api/parental/pause")
async def pause_status():
    return pause_mgr.status()


@app.post("/api/parental/pause")
async def toggle_pause(data: dict):
    paused = bool(data.get("paused", False))
    return pause_mgr.pause() if paused else pause_mgr.resume()


# ─── Schedules ────────────────────────────────────────────────────────

@app.get("/api/parental/schedules")
async def list_schedules():
    return schedules.list_schedules()


@app.post("/api/parental/schedules")
async def add_schedule(data: dict):
    return schedules.add_schedule(
        process=(data.get("process") or "").strip(),
        executable_path=(data.get("executable_path") or "").strip(),
        start_time=(data.get("start_time") or "").strip(),
        end_time=(data.get("end_time") or "").strip(),
        days=data.get("days") or [],
    )


@app.delete("/api/parental/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int):
    return schedules.remove_schedule(schedule_id)


# ─── Activity Summary ─────────────────────────────────────────────────

@app.get("/api/parental/activity")
async def parental_activity(days: int = 7):
    return activity.summary(days)


def _build_activity_snapshot() -> dict:
    """Compact, fact-only snapshot of current monitoring state for the AI."""
    alerts = list(active_alerts)
    type_counts = {}
    for a in alerts:
        t = a.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    alert_types = ", ".join(f"{t} x{c}" for t, c in type_counts.items()) or "none"

    top_apps = "none"
    try:
        rows = sorted(
            monitor.get_process_usage(),
            key=lambda p: (p.get("upload_kbps", 0) + p.get("download_kbps", 0)),
            reverse=True,
        )[:3]
        if rows:
            top_apps = ", ".join(
                f"{r.get('process', '?')} "
                f"{round((r.get('upload_kbps', 0) + r.get('download_kbps', 0)), 1)} KB/s"
                for r in rows
            )
    except Exception:
        pass

    return {
        "total_alerts": len(alerts),
        "high_risk": sum(1 for a in alerts if a.get("severity") == "high"),
        "alert_types": alert_types,
        "active_connections": len(monitor.get_active_connections()),
        "blocked_apps": len(parental.get_blocked_apps()),
        "top_apps": top_apps,
        "safe_mode": parental.safe_mode,
    }


def _snapshot_one_liner(snap: dict) -> str:
    return (f"{snap['total_alerts']} alerts ({snap['high_risk']} high), "
            f"{snap['active_connections']} connections, "
            f"{snap['blocked_apps']} blocked apps, "
            f"top app: {snap['top_apps']}, "
            f"Safe Mode {'on' if snap['safe_mode'] else 'off'}.")


@app.post("/api/gemini/explain")
async def gemini_explain(data: dict):
    """Free-form question, grounded in a compact live snapshot of current state.
    Route path kept as /gemini/explain for frontend compatibility."""
    snapshot = _snapshot_one_liner(_build_activity_snapshot())
    explanation = await ai.explain_free(data.get("text", ""), snapshot=snapshot)
    return {"explanation": explanation}


@app.post("/api/ai/explain-alert")
async def ai_explain_alert(data: dict):
    """Generate a grounded, type-specific explanation for a single alert (lazy,
    called when the user clicks an alert). Cached + single-flighted."""
    explanation = await ai.explain_alert_dict(data or {})
    return {"explanation": explanation}


@app.post("/api/ai/summary")
async def ai_summary(data: dict = None):
    """AI summary of the overall current monitoring picture."""
    summary = await ai.summarize_activity(_build_activity_snapshot())
    return {"summary": summary}


@app.get("/api/logs")
async def get_logs():
    """Get activity logs."""
    return db.get_logs()


@app.get("/api/stats")
async def get_stats():
    """Dashboard summary statistics."""
    return {
        "total_alerts": len(active_alerts),
        "high_risk": sum(1 for a in active_alerts if a.get("severity") == "high"),
        "blocked_apps": len(parental.get_blocked_apps()),
        "adaptive_blocked_apps": len(bandwidth_controller.get_blocked_processes()),
        "active_connections": len(monitor.get_active_connections()),
        "safe_mode": parental.safe_mode,
        "uptime": monitor.get_uptime(),
        "monitoring_active": monitoring_active,
        "demo_alerts_enabled": ENABLE_DEMO_ALERTS,
        "show_demo_alerts": show_demo_alerts,
        "packet_sniffing_active": monitor.packet_sniffing_active,
        "packet_sniffing_error": monitor.packet_sniffing_error,
        "process_mode": monitor.get_mode(),
        "bandwidth_control_enabled": BANDWIDTH_CONTROL_ENABLED,
        "bandwidth_threshold_kbps": BANDWIDTH_THRESHOLD_KBPS,
        "bandwidth_auto_block": BANDWIDTH_AUTO_BLOCK,
    }


@app.get("/api/adaptive/status")
async def get_adaptive_status():
    """Expose current adaptive bandwidth controller state for the UI."""
    return {
        "enabled": BANDWIDTH_CONTROL_ENABLED,
        "threshold_kbps": BANDWIDTH_THRESHOLD_KBPS,
        "auto_block": BANDWIDTH_AUTO_BLOCK,
        "cooldown_seconds": BANDWIDTH_ALERT_COOLDOWN,
        "blocked_processes": bandwidth_controller.get_blocked_processes(),
        "recent_actions": bandwidth_controller.get_recent_actions(),
        "recent_alerts": last_adaptive_alerts,
        "last_sample_count": last_process_sample_count,
    }


@app.get("/api/threat/status")
async def threat_api_status():
    """Report which threat-intel APIs have real keys configured.

    Drives the frontend's real-vs-demo status label so it reflects reality
    (keys can be supplied via config.json OR .env) instead of a hardcoded string.
    """
    import threat_intel as _ti
    live = []
    if _ti.ABUSEIPDB_KEY:
        live.append("abuseipdb")
    if _ti.OTX_KEY:
        live.append("otx")
    if _ti.GOOGLE_SAFE_BROWSING_KEY:
        live.append("gsb")
    if _ti.URLHAUS_KEY:
        live.append("urlhaus")
    return {"real_apis": bool(live), "live_sources": live}


@app.post("/api/adaptive/decision")
async def adaptive_decision(data: dict):
    """Let the user allow or block a high-usage process."""
    process = (data.get("process") or "").strip()
    decision = (data.get("decision") or "").strip().lower()
    exe_path = (data.get("exe") or "").strip()
    if not process:
        return {"ok": False, "error": "Process name is required."}
    if decision == "block":
        result = bandwidth_controller.block_process(process, exe_path)
        return {"ok": result.get("ok", False), "decision": "block", **result}
    if decision == "allow":
        db.log_action("adaptive_allow_process", process)
        return {"ok": True, "decision": "allow", "process": process}
    return {"ok": False, "error": "Decision must be allow or block."}


@app.get("/api/caps")
async def get_caps():
    """List all per-process bandwidth caps."""
    return bandwidth_controller.get_caps()


@app.post("/api/caps")
async def set_cap(data: dict):
    """Add or update a per-process bandwidth cap."""
    process = (data.get("process") or "").strip()
    action = (data.get("action") or "alert").strip().lower()
    if not process:
        return {"ok": False, "error": "process is required"}
    try:
        cap_kbps = float(data["cap_kbps"])
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "error": "cap_kbps must be a number"}
    return bandwidth_controller.set_cap(process, cap_kbps, action)


@app.delete("/api/caps/{process}")
async def remove_cap(process: str):
    """Remove a per-process bandwidth cap."""
    return bandwidth_controller.remove_cap(process)


@app.post("/api/monitoring/toggle")
async def toggle_monitoring(data: dict):
    """Start/stop background monitoring."""
    global monitoring_active
    monitoring_active = data.get("active", True)
    return {"monitoring": monitoring_active}


@app.post("/api/shutdown")
async def shutdown_backend():
    """
    Gracefully shut down the backend process.
    Called by the frontend's Exit NetGuard action.
    Closes aiohttp sessions (via shutdown_event) then exits the process.
    """
    async def _deferred_exit():
        await asyncio.sleep(0.4)   # let the HTTP response be sent first
        os._exit(0)

    asyncio.create_task(_deferred_exit())
    return {"ok": True, "message": "Backend shutting down"}


if __name__ == "__main__":
    _ensure_admin()
    uvicorn.run(app, host="127.0.0.1", port=8765, reload=False)
