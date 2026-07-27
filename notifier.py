"""
notifier.py
NetGuard – Windows desktop notification helper.

All public functions are non-blocking: notifications fire in a daemon thread
so they never stall the asyncio monitoring loop or crash the backend.
"""

import threading
import time
from collections import OrderedDict

try:
    from plyer import notification as _plyer_notify
    PLYER_AVAILABLE = True
except ImportError:
    _plyer_notify = None
    PLYER_AVAILABLE = False
    print("[Notifier] plyer not installed – desktop notifications disabled. "
          "Run: pip install plyer")

# ── Duplicate-suppression registry ───────────────────────────────────
# OrderedDict used as an ordered set so we can evict the oldest entry
# when the cap is reached (prevents unbounded memory growth).
_MAX_TRACKED = 500
_notified_ids: "OrderedDict[str, bool]" = OrderedDict()
_lock = threading.Lock()

# ── Time-window suppression ──────────────────────────────────────────
# Throttles desktop toasts by a *meaningful* key (e.g. process name) so a
# torrent client making hundreds of peer connections produces ONE popup,
# not hundreds. Alerts are still stored and shown in the UI — this only
# limits the noisy desktop notifications.
_recent_pushes: "OrderedDict[str, float]" = OrderedDict()
_PUSH_COOLDOWN_SECONDS = {
    "suspicious_port": 600,   # one popup per process per 10 min
    "malicious_ip": 300,      # one popup per IP per 5 min
    "packet_malicious_ip": 300,
}
_DEFAULT_PUSH_COOLDOWN = 60


def _recently_pushed(key: str, ttl: int) -> bool:
    """Return True if a toast with this key fired within the last ttl seconds."""
    now = time.time()
    with _lock:
        # Drop expired entries so the dict doesn't grow unbounded.
        for k in list(_recent_pushes.keys()):
            if now - _recent_pushes[k] > max(_PUSH_COOLDOWN_SECONDS.values()):
                _recent_pushes.pop(k, None)
            else:
                break
        last = _recent_pushes.get(key)
        if last is not None and (now - last) < ttl:
            return True
        _recent_pushes[key] = now
        if len(_recent_pushes) > _MAX_TRACKED:
            _recent_pushes.popitem(last=False)
        return False


# ── Internal helpers ──────────────────────────────────────────────────

def _fire(title: str, message: str) -> None:
    """Blocking plyer call – must always be called from a daemon thread."""
    if not PLYER_AVAILABLE:
        return
    try:
        _plyer_notify.notify(
            title=title[:64],
            message=message[:256],   # Windows toast character limit
            app_name="NetGuard",
            timeout=6,
        )
    except Exception as exc:
        print(f"[Notifier] Delivery failed: {exc}")


def _already_notified(alert_id: str) -> bool:
    """Return True if this alert_id was already sent. Thread-safe."""
    with _lock:
        if alert_id in _notified_ids:
            return True
        if len(_notified_ids) >= _MAX_TRACKED:
            _notified_ids.popitem(last=False)   # evict oldest
        _notified_ids[alert_id] = True
        return False


# ── Public API ────────────────────────────────────────────────────────

def show_system_notification(title: str, message: str) -> None:
    """
    Fire a Windows desktop toast notification without blocking the caller.

    Usage anywhere in the backend:
        from notifier import show_system_notification
        show_system_notification("NetGuard Alert", "Something happened")
    """
    threading.Thread(target=_fire, args=(title, message), daemon=True).start()


def notify_alert(alert: dict) -> None:
    """
    Inspect an alert dict and send a desktop notification if it meets the
    severity threshold. Silently skips duplicate alert IDs.

    Trigger conditions:
      - malicious_ip / packet_malicious_ip  with risk_score >= 5
      - bandwidth_threshold  (any)
      - parental_control     (any)
    """
    if not PLYER_AVAILABLE or not isinstance(alert, dict):
        return

    alert_id = alert.get("id", "")
    if alert_id and _already_notified(alert_id):
        return

    alert_type  = alert.get("type", "")
    severity    = alert.get("severity", "low").upper()
    process     = alert.get("process", "") or "Unknown"
    risk_score  = float(alert.get("risk_score", 0))
    message     = alert.get("message", "")
    ip          = alert.get("ip", "")
    domain      = alert.get("domain", "")

    # For IP-based threat alerts, only notify on HIGH severity (risk >= 9).
    # Medium-risk alerts are stored and shown in the UI but not pushed as
    # desktop notifications. Operational alerts (bandwidth, parental) always fire.
    if alert_type in ("malicious_ip", "packet_malicious_ip", "suspicious_domain"):
        if severity != "HIGH":
            return

    # Time-window throttle so chatty sources (torrent clients hitting hundreds
    # of peers) don't spam the desktop. Port/P2P alerts dedupe per *process*;
    # IP alerts dedupe per *IP*. The alert is still saved + shown in the UI.
    if alert_type == "suspicious_port":
        push_key = f"port:{process.lower()}"
    elif alert_type in ("malicious_ip", "packet_malicious_ip"):
        push_key = f"ip:{ip}"
    else:
        push_key = ""
    if push_key:
        ttl = _PUSH_COOLDOWN_SECONDS.get(alert_type, _DEFAULT_PUSH_COOLDOWN)
        if _recently_pushed(push_key, ttl):
            return

    target = domain if (domain and domain != ip) else ip

    if alert_type == "bandwidth_threshold":
        title = "NetGuard - High Bandwidth Usage"
        body  = f"[{severity}] {process}\n{message}"

    elif alert_type in ("malicious_ip", "packet_malicious_ip"):
        title = f"NetGuard - Malicious IP Detected (Risk {risk_score:.0f}/10)"
        body  = f"[{severity}] Process: {process}\nIP/Domain: {target}\n{message}"

    elif alert_type == "parental_control":
        title = "NetGuard - Parental Control Triggered"
        body  = f"[{severity}] Blocked domain: {target}\nProcess: {process}"

    else:
        title = f"NetGuard - {alert_type.replace('_', ' ').title()}"
        body  = f"[{severity}] {process}\n{message}"

    show_system_notification(title, body)


def notify_block(action: str, target: str, process: str = "") -> None:
    """
    Send a notification when a domain or application is explicitly blocked.

    Args:
        action:  'domain' or 'app'
        target:  the domain name or process name that was blocked
        process: (optional) the process that triggered a domain block
    """
    if not PLYER_AVAILABLE:
        return

    if action == "domain":
        title = "NetGuard - Domain Blocked"
        body  = f"Domain '{target}' has been blocked."
        if process:
            body += f"\nTriggered by process: {process}"
    else:
        title = "NetGuard - Application Blocked"
        body  = f"'{target}' has been blocked from internet access."

    show_system_notification(title, body)
