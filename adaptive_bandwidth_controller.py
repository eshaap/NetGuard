"""
adaptive_bandwidth_controller.py
Adaptive response layer for per-process bandwidth threshold enforcement.
"""

import os
import platform
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional


class AdaptiveBandwidthController:
    """
    Monitor per-process bandwidth usage and react when configured thresholds are exceeded.

    This controller does not shape traffic. Instead, it watches current usage values,
    emits alerts, and can optionally block the executable with Windows Firewall.
    """

    def __init__(
        self,
        db,
        threshold_kbps: float = 1024.0,
        auto_block: bool = False,
        cooldown_seconds: int = 30,
    ):
        self.db = db
        self.threshold_kbps = max(0.0, float(threshold_kbps or 0.0))
        self.auto_block = bool(auto_block)
        self.cooldown_seconds = max(1, int(cooldown_seconds or 30))
        self.blocked_processes = self._load_blocked_processes()
        self._last_alert_times: Dict[str, float] = {}
        self._cap_last_alert_times: Dict[str, float] = {}
        self._recent_actions: List[Dict] = []
        self._process_caps: Dict[str, Dict] = self._load_caps()

    def _ensure_caps_table(self):
        with sqlite3.connect(self.db.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS process_caps (
                    process   TEXT PRIMARY KEY,
                    cap_kbps  REAL NOT NULL,
                    action    TEXT NOT NULL DEFAULT 'alert',
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)

    def _load_caps(self) -> Dict[str, Dict]:
        """Load per-process bandwidth caps from SQLite so they survive restarts."""
        self._ensure_caps_table()
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                rows = conn.execute(
                    "SELECT process, cap_kbps, action FROM process_caps"
                ).fetchall()
        except Exception:
            return {}
        return {
            row[0]: {"cap_kbps": float(row[1]), "action": row[2]}
            for row in rows if row and row[0]
        }

    def set_cap(self, process_name: str, cap_kbps: float, action: str = "alert") -> Dict:
        """Add or update a per-process bandwidth cap."""
        process_name = (process_name or "").strip()
        if not process_name:
            return {"ok": False, "error": "Process name is required."}
        cap_kbps = max(1.0, float(cap_kbps or 1.0))
        action = action if action in ("alert", "block") else "alert"

        self._process_caps[process_name] = {"cap_kbps": cap_kbps, "action": action}
        self._cap_last_alert_times.pop(process_name, None)  # reset cooldown on update
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO process_caps (process, cap_kbps, action, created_at)
                    VALUES (?, ?, ?, datetime('now'))
                    """,
                    (process_name, cap_kbps, action),
                )
            self.db.log_action(
                "set_bandwidth_cap",
                f"{process_name} -> {cap_kbps:.0f} KB/s ({action})",
            )
            return {"ok": True, "process": process_name, "cap_kbps": cap_kbps, "action": action}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def remove_cap(self, process_name: str) -> Dict:
        """Remove a per-process bandwidth cap and restore internet access if the
        process was auto-blocked because it exceeded that cap."""
        process_name = (process_name or "").strip()
        if not process_name:
            return {"ok": False, "error": "Process name is required."}
        self._process_caps.pop(process_name, None)
        self._cap_last_alert_times.pop(process_name, None)

        # If the process is currently blocked by the adaptive controller
        # (i.e. the cap's auto-block fired), lift the firewall rule now.
        unblock_result = None
        if process_name in self.blocked_processes:
            unblock_result = self.unblock_process(process_name)

        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute("DELETE FROM process_caps WHERE process = ?", (process_name,))
            self.db.log_action("remove_bandwidth_cap", process_name)
            return {"ok": True, "process": process_name, "unblocked": unblock_result}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_caps(self) -> List[Dict]:
        """Return all configured per-process caps."""
        return [
            {"process": proc, "cap_kbps": info["cap_kbps"], "action": info["action"]}
            for proc, info in sorted(self._process_caps.items())
        ]

    def _load_blocked_processes(self) -> Dict[str, str]:
        """Load existing blocked processes from SQLite so state survives restarts."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                rows = conn.execute(
                    "SELECT process, COALESCE(executable_path, '') FROM blocked_apps"
                ).fetchall()
        except Exception:
            return {}
        return {row[0]: row[1] for row in rows if row and row[0]}

    def _resolve_exe_from_pid(self, pid) -> str:
        """Best-effort lookup of a process's executable path from its PID.

        ETW/accurate mode often reports processes without an exe path, but
        firewall blocking needs one. psutil can usually recover it from the PID.
        Returns an empty string if it can't (process gone, access denied, etc.).
        """
        if not pid:
            return ""
        try:
            import psutil
            return (psutil.Process(int(pid)).exe() or "").strip()
        except Exception:
            return ""

    def _firewall_rule_name(self, process_name: str) -> str:
        return f"NetGuard Adaptive Block {process_name}"

    def _has_invalid_netsh_chars(self, *values: str) -> bool:
        for value in values:
            if any(char in (value or "") for char in ('"', "\n", ";")):
                return True
        return False

    def _run_netsh(self, args: List[str]) -> Dict:
        """Execute a Windows Firewall command and return a structured result."""
        if platform.system() != "Windows":
            return {
                "ok": False,
                "error": "Adaptive blocking is only implemented for Windows.",
                "output": "",
            }

        try:
            completed = subprocess.run(
                ["netsh", *args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc), "output": ""}

        output = (completed.stdout or completed.stderr or "").strip()
        return {
            "ok": completed.returncode == 0,
            "error": "" if completed.returncode == 0 else output,
            "output": output,
        }

    def _save_cap_alert(self, process_name: str, total_kbps: float, cap_kbps: float, action_taken: str, exe_path: str = "") -> Dict:
        """Persist a per-process cap violation alert."""
        alert = {
            "id": f"cap_{uuid.uuid4().hex}",
            "type": "bandwidth_cap",
            "severity": "high" if action_taken == "blocked" else "medium",
            "process": process_name,
            "exe": exe_path,
            "ip": "",
            "domain": "",
            "message": (
                f"{process_name} exceeded its {cap_kbps:.0f} KB/s cap "
                f"at {total_kbps:.1f} KB/s."
            ),
            "timestamp": datetime.now().isoformat(),
            "risk_score": 6.5 if action_taken == "blocked" else 5.5,
            "action_taken": action_taken,
            "cap_kbps": cap_kbps,
        }
        self.db.save_alert(alert)
        return alert

    def _save_alert(self, process_name: str, usage_kbps: float, action_taken: str, exe_path: str = "", risk_score: float = 0) -> Dict:
        """Persist a bandwidth alert using the existing alerts table."""
        alert = {
            "id": f"bandwidth_{uuid.uuid4().hex}",
            "type": "bandwidth_threshold",
            "severity": "high" if action_taken == "blocked" else "medium",
            "process": process_name,
            "exe": exe_path,
            "ip": "",
            "domain": "",
            "message": (
                f"{process_name} exceeded the configured bandwidth limit "
                f"at {usage_kbps:.1f} KB/s."
            ),
            "timestamp": datetime.now().isoformat(),
            "risk_score": risk_score,
            "action_taken": action_taken,
        }
        self.db.save_alert(alert)
        return alert

    def check_usage_and_control(self, process_data: List[Dict]) -> List[Dict]:
        """
        Evaluate current per-process usage and apply configured controls.

        Expects rows shaped like NetworkMonitor.get_process_usage():
        {
            "process": "chrome.exe",
            "exe": "C:\\Path\\chrome.exe",
            "upload_kbps": 123.4,
            "download_kbps": 456.7,
            ...
        }
        """
        actions = []
        now = time.time()

        for row in process_data or []:
            process_name = (row.get("process") or "").strip()
            exe_path = (row.get("exe") or "").strip()
            # In accurate/ETW mode many high-traffic rows arrive without an exe
            # path. Firewall blocking requires the executable path, so resolve it
            # from the PID here — otherwise auto-block silently fails for exactly
            # the busy apps a cap is meant to stop.
            if not exe_path:
                exe_path = self._resolve_exe_from_pid(row.get("pid"))
            upload_kbps = max(0.0, float(row.get("upload_kbps", 0.0) or 0.0))
            download_kbps = max(0.0, float(row.get("download_kbps", 0.0) or 0.0))
            total_kbps = upload_kbps + download_kbps

            if not process_name:
                continue

            # ── Per-process cap (takes priority over the global threshold) ──
            cap_info = self._process_caps.get(process_name)
            if cap_info:
                cap_kbps = cap_info["cap_kbps"]
                cap_action = cap_info.get("action", "alert")

                # If this cap enforces blocking and the process is already blocked,
                # the control is in place — stop re-alerting. A firewall-blocked app
                # still generates small residual traffic (reconnect attempts, DNS,
                # loopback), which at a low cap would otherwise trip an endless stream
                # of notifications about something we already handled. We alerted once
                # when the block was applied; that's enough.
                if cap_action == "block" and process_name in self.blocked_processes:
                    continue

                if total_kbps > cap_kbps:
                    last_cap_alert = self._cap_last_alert_times.get(process_name, 0.0)
                    if now - last_cap_alert >= self.cooldown_seconds:
                        self._cap_last_alert_times[process_name] = now
                        action_taken = "alert"
                        firewall_result = None
                        if cap_action == "block" and not self._has_invalid_netsh_chars(process_name, exe_path):
                            firewall_result = self.block_process(process_name, exe_path)
                            if firewall_result.get("ok"):
                                action_taken = "blocked"
                        alert = self._save_cap_alert(process_name, total_kbps, cap_kbps, action_taken, exe_path)
                        self.db.log_action(
                            "cap_exceeded",
                            f"{process_name} ({total_kbps:.1f} KB/s, cap: {cap_kbps:.0f} KB/s)",
                        )
                        actions.append({
                            "process": process_name,
                            "upload_kbps": round(upload_kbps, 1),
                            "download_kbps": round(download_kbps, 1),
                            "total_kbps": round(total_kbps, 1),
                            "threshold_kbps": cap_kbps,
                            "cap_kbps": cap_kbps,
                            "action_taken": action_taken,
                            "blocked": process_name in self.blocked_processes,
                            "firewall": firewall_result,
                            "alert": alert,
                            "exe": exe_path,
                            "source": "cap",
                        })
                # Skip global threshold check for capped processes regardless of usage.
                continue

            # ── Global threshold ──
            if total_kbps <= self.threshold_kbps:
                continue

            last_alert = self._last_alert_times.get(process_name, 0.0)
            if now - last_alert < self.cooldown_seconds:
                continue

            self._last_alert_times[process_name] = now
            action_taken = "alert"
            firewall_result = None
            # Bandwidth alerts are capped at 6.9 so they never reach the
            # "confirmed malicious threat" range (7+). High bandwidth usage
            # is a performance concern, not a confirmed security threat.
            raw = 5.0 + ((total_kbps - self.threshold_kbps) / max(self.threshold_kbps, 1.0)) * 2.0
            risk_score = min(6.9, max(5.0, round(raw, 1)))

            if self.auto_block:
                if self._has_invalid_netsh_chars(process_name, exe_path):
                    firewall_result = {"ok": False, "error": "Invalid characters in process name or path."}
                else:
                    firewall_result = self.block_process(process_name, exe_path)
                if firewall_result.get("ok"):
                    action_taken = "blocked"

            alert = self._save_alert(process_name, total_kbps, action_taken, exe_path, risk_score)
            self.db.log_action(
                "bandwidth_threshold_exceeded",
                f"{process_name} ({total_kbps:.1f} KB/s)",
            )

            actions.append(
                {
                    "process": process_name,
                    "upload_kbps": round(upload_kbps, 1),
                    "download_kbps": round(download_kbps, 1),
                    "total_kbps": round(total_kbps, 1),
                    "threshold_kbps": self.threshold_kbps,
                    "action_taken": action_taken,
                    "blocked": process_name in self.blocked_processes,
                    "firewall": firewall_result,
                    "alert": alert,
                    "exe": exe_path,
                    "source": "global",
                }
            )

        if actions:
            self._recent_actions = (actions + self._recent_actions)[:50]

        return actions

    def block_process(self, process_name: str, exe_path: str) -> Dict:
        """Create a Windows Firewall block rule and persist the process as blocked."""
        process_name = (process_name or "").strip()
        exe_path = (exe_path or "").strip()

        if not process_name:
            return {"ok": False, "error": "Process name is required."}
        if not exe_path:
            return {"ok": False, "error": "Executable path is required for firewall blocking."}
        if self._has_invalid_netsh_chars(process_name, exe_path):
            return {"ok": False, "error": "Invalid characters in process name or path."}
        if not os.path.exists(exe_path):
            return {"ok": False, "error": f"Executable path not found: {exe_path}"}

        self._run_netsh(
            [
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={self._firewall_rule_name(process_name)}",
            ]
        )
        result = self._run_netsh(
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={self._firewall_rule_name(process_name)}",
                "dir=out",
                "action=block",
                f"program={exe_path}",
                "enable=yes",
            ]
        )

        if result.get("ok"):
            self.blocked_processes[process_name] = exe_path
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO blocked_apps (process, executable_path, added_date)
                    VALUES (?, ?, datetime('now'))
                    """,
                    (process_name, exe_path),
                )
            self.db.log_action("adaptive_block_process", process_name)

        return {"process": process_name, "exe": exe_path, **result}

    def unblock_process(self, process_name: str) -> Dict:
        """Remove a Windows Firewall block rule and delete persisted state."""
        process_name = (process_name or "").strip()
        if not process_name:
            return {"ok": False, "error": "Process name is required."}

        result = self._run_netsh(
            [
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={self._firewall_rule_name(process_name)}",
            ]
        )

        # Keep local and persisted state in sync even if the rule was already absent.
        self.blocked_processes.pop(process_name, None)
        with sqlite3.connect(self.db.db_path) as conn:
            conn.execute("DELETE FROM blocked_apps WHERE process = ?", (process_name,))
        self.db.log_action("adaptive_unblock_process", process_name)

        if result.get("ok") or "No rules match" in (result.get("error") or ""):
            result["ok"] = True
            result["error"] = ""

        return {"process": process_name, **result}

    def get_blocked_processes(self) -> List[Dict[str, str]]:
        """Expose the current blocked-process list for API or UI use."""
        return [
            {"process": process, "exe": exe}
            for process, exe in sorted(self.blocked_processes.items())
        ]

    def get_recent_actions(self) -> List[Dict]:
        """Return recent adaptive decisions for the dashboard."""
        return list(self._recent_actions[:20])
