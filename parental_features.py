"""
parental_features.py
Extended parental controls: category blocking, schedules, instant pause, activity reports.
Builds on the existing ParentalControl (hosts file + Windows Firewall).
"""

from __future__ import annotations

import sqlite3
import subprocess
import platform
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional


# Curated starter blocklists per category. Small but covers the most common
# requests. Users can still block extra domains manually.
CATEGORY_DOMAINS: Dict[str, List[str]] = {
    "social_media": [
        "facebook.com", "instagram.com", "tiktok.com", "twitter.com", "x.com",
        "snapchat.com", "reddit.com", "pinterest.com", "tumblr.com", "threads.net",
    ],
    "gaming": [
        "steampowered.com", "store.steampowered.com", "epicgames.com",
        "roblox.com", "minecraft.net", "ea.com", "playstation.com",
        "xbox.com", "battle.net", "twitch.tv",
    ],
    "streaming": [
        "youtube.com", "netflix.com", "hulu.com", "disneyplus.com",
        "primevideo.com", "hbomax.com", "max.com", "spotify.com",
    ],
    "adult": [
        "pornhub.com", "xvideos.com", "xhamster.com", "redtube.com",
        "youporn.com", "xnxx.com", "onlyfans.com", "stripchat.com",
        "chaturbate.com",
    ],
    "gambling": [
        "bet365.com", "draftkings.com", "fanduel.com", "pokerstars.com",
        "888casino.com", "williamhill.com", "betway.com", "mgmresorts.com",
    ],
}

CATEGORY_LABELS: Dict[str, str] = {
    "social_media": "Social Media",
    "gaming": "Gaming",
    "streaming": "Streaming Video / Music",
    "adult": "Adult Content",
    "gambling": "Gambling",
}


# ─────────────────────────── Category Manager ──────────────────────────

class CategoryManager:
    def __init__(self, db, parental):
        self.db = db
        self.parental = parental

    def list_categories(self) -> List[dict]:
        enabled = self._enabled_set()
        return [
            {
                "key": key,
                "label": CATEGORY_LABELS.get(key, key),
                "domain_count": len(domains),
                "enabled": key in enabled,
            }
            for key, domains in CATEGORY_DOMAINS.items()
        ]

    def _enabled_set(self) -> set:
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                "SELECT category FROM blocked_categories WHERE enabled = 1"
            ).fetchall()
        return {row[0] for row in rows}

    def apply_all_enabled(self) -> dict:
        """Re-apply (block) every category marked enabled in the DB.
        Used by Safe Mode toggle so a single switch enforces every selection."""
        keys = self._enabled_set()
        if not keys:
            return {"ok": True, "applied_categories": 0, "applied_domains": 0}
        all_domains = []
        for k in keys:
            all_domains.extend(CATEGORY_DOMAINS.get(k, []))
        result = self.parental.batch_block_domains(all_domains, remove=False)
        return {
            "ok": result.get("ok", False),
            "applied_categories": len(keys),
            "applied_domains": result.get("applied", 0),
            "error": result.get("error", ""),
        }

    def unapply_all_enabled(self) -> dict:
        """Turn Safe Mode OFF: remove every category's blocked domains AND clear
        the selection, so OFF is a clean slate (no domains blocked, no boxes
        checked). Categories are re-picked from scratch the next time Safe Mode
        is on."""
        keys = self._enabled_set()
        if not keys:
            return {"ok": True, "removed_categories": 0, "removed_domains": 0}
        all_domains = []
        for k in keys:
            all_domains.extend(CATEGORY_DOMAINS.get(k, []))
        result = self.parental.batch_block_domains(all_domains, remove=True)

        # Clear the armed selection so the checkboxes show unchecked while off.
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute("UPDATE blocked_categories SET enabled = 0")
        except Exception:
            pass

        return {
            "ok": result.get("ok", False),
            "removed_categories": len(keys),
            "removed_domains": result.get("applied", 0),
            "error": result.get("error", ""),
        }

    def set_enabled(self, category: str, enabled: bool) -> dict:
        """Mark a category as armed/disarmed. The actual hosts-file block only
        runs if Safe Mode is currently ON. Safe Mode acts as the master switch."""
        if category not in CATEGORY_DOMAINS:
            return {"ok": False, "error": f"Unknown category: {category}"}

        domains = CATEGORY_DOMAINS[category]
        safe_mode_on = bool(getattr(self.parental, "safe_mode", False))
        batch_result = {"ok": True, "applied": 0}

        # Disabling a category must ALWAYS remove its domains from the personal
        # blocked-domains list (and any hosts entries), even when Safe Mode is off.
        # Otherwise the domains get orphaned in the list and keep showing as
        # "blocked" after the checkbox is unchecked. Enabling only enforces while
        # Safe Mode is on; otherwise we just record the selection so Safe Mode can
        # apply it later.
        if safe_mode_on or not enabled:
            batch_result = self.parental.batch_block_domains(domains, remove=not enabled)

        # Persist the selection regardless — Safe Mode read this when it turns on.
        if batch_result.get("ok"):
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO blocked_categories (category, enabled, last_applied) "
                    "VALUES (?, ?, ?)",
                    (category, 1 if enabled else 0, datetime.now().isoformat()),
                )
            try:
                self.db.log_parental_event(
                    "category_arm" if enabled else "category_disarm", category
                )
            except Exception:
                pass

        return {
            "ok": batch_result.get("ok", False),
            "category": category,
            "enabled": enabled,
            "applied": batch_result.get("applied", 0),
            "safe_mode_on": safe_mode_on,
            "error": batch_result.get("error", ""),
        }


# ─────────────────────────── Pause Manager ─────────────────────────────

class PauseManager:
    """Instantly pause / resume all outbound internet on this machine
    via a single Windows Firewall rule."""

    RULE_NAME = "NetGuard PAUSE ALL"

    def __init__(self, db):
        self.db = db
        self._paused = False

    @property
    def paused(self) -> bool:
        return self._paused

    def _run_netsh(self, args: List[str]) -> dict:
        if platform.system() != "Windows":
            return {"ok": False, "error": "Pause is Windows-only."}
        try:
            result = subprocess.run(
                ["netsh", *args], capture_output=True, text=True, timeout=6, check=False
            )
            return {
                "ok": result.returncode == 0,
                "output": (result.stdout or result.stderr or "").strip(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _rule_names(self):
        return (f"{self.RULE_NAME} IPv4", f"{self.RULE_NAME} IPv6")

    def pause(self) -> dict:
        # Clean any prior NetGuard pause rules (current + legacy names) to avoid duplicates.
        for name in (self.RULE_NAME, *self._rule_names()):
            self._run_netsh([
                "advfirewall", "firewall", "delete", "rule", f"name={name}"
            ])
        # One rule with no remoteip/protocol filter blocks ALL outbound
        # traffic regardless of address family. Keeping a single rule also
        # avoids the netsh CIDR pitfall (0.0.0.0/0 and ::/0 aren't valid here).
        result = self._run_netsh([
            "advfirewall", "firewall", "add", "rule",
            f"name={self.RULE_NAME}",
            "dir=out", "action=block", "enable=yes",
            "profile=any",
        ])
        ok = result.get("ok", False)
        if ok:
            self._paused = True
            try:
                self.db.log_parental_event("pause_internet", "all")
            except Exception:
                pass
        return {
            "ok": ok,
            "paused": self._paused,
            "error": "" if ok else (result.get("output") or result.get("error", "")),
        }

    def resume(self) -> dict:
        # Delete both the current single-rule name and the older split rule names,
        # in case a previous version of the app created them.
        for name in (self.RULE_NAME, *self._rule_names()):
            self._run_netsh([
                "advfirewall", "firewall", "delete", "rule", f"name={name}"
            ])
        self._paused = False
        try:
            self.db.log_parental_event("resume_internet", "all")
        except Exception:
            pass
        return {"ok": True, "paused": False}

    def status(self) -> dict:
        return {"paused": self._paused}


# ─────────────────────────── Schedule Manager ──────────────────────────

class ScheduleManager:
    """Time-based app blocking. Each schedule says: between start_minute and
    end_minute on the given weekdays, the given process should be blocked."""

    def __init__(self, db, parental):
        self.db = db
        self.parental = parental

    def list_schedules(self) -> List[dict]:
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                "SELECT id, process, executable_path, start_minute, end_minute, days, "
                "enabled, currently_blocked, created FROM app_schedules ORDER BY id DESC"
            ).fetchall()
        return [
            {
                "id": row[0],
                "process": row[1],
                "executable_path": row[2] or "",
                "start_minute": row[3],
                "end_minute": row[4],
                "start_time": self._fmt_time(row[3]),
                "end_time": self._fmt_time(row[4]),
                "days": [int(d) for d in (row[5] or "").split(",") if d.strip().isdigit()],
                "enabled": bool(row[6]),
                "currently_blocked": bool(row[7]),
                "created": row[8],
            }
            for row in rows
        ]

    @staticmethod
    def _fmt_time(minute: int) -> str:
        minute = max(0, min(int(minute or 0), 24 * 60 - 1))
        return f"{minute // 60:02d}:{minute % 60:02d}"

    @staticmethod
    def parse_time(value: str) -> Optional[int]:
        try:
            parts = (value or "").strip().split(":")
            if len(parts) != 2:
                return None
            h = int(parts[0])
            m = int(parts[1])
            if not (0 <= h < 24 and 0 <= m < 60):
                return None
            return h * 60 + m
        except Exception:
            return None

    def add_schedule(self, process: str, executable_path: str, start_time: str,
                     end_time: str, days: List[int]) -> dict:
        process = (process or "").strip()
        if not process:
            return {"ok": False, "error": "Process name is required."}

        start_min = self.parse_time(start_time)
        end_min = self.parse_time(end_time)
        if start_min is None or end_min is None:
            return {"ok": False, "error": "Start/end time must be HH:MM (24h)."}
        if start_min == end_min:
            return {"ok": False, "error": "Start and end time cannot be the same."}

        valid_days = sorted({int(d) for d in days if 0 <= int(d) <= 6})
        if not valid_days:
            return {"ok": False, "error": "Pick at least one day of the week."}

        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO app_schedules (process, executable_path, start_minute, "
                "end_minute, days, enabled, currently_blocked, created) "
                "VALUES (?, ?, ?, ?, ?, 1, 0, ?)",
                (process, executable_path or "", start_min, end_min,
                 ",".join(str(d) for d in valid_days),
                 datetime.now().isoformat()),
            )
            sched_id = cursor.lastrowid
        try:
            self.db.log_parental_event("schedule_add", process)
        except Exception:
            pass
        return {"ok": True, "id": sched_id}

    def remove_schedule(self, schedule_id: int) -> dict:
        with sqlite3.connect(self.db.db_path) as conn:
            row = conn.execute(
                "SELECT process, currently_blocked FROM app_schedules WHERE id = ?",
                (schedule_id,),
            ).fetchone()
            if not row:
                return {"ok": False, "error": "Schedule not found."}
            process, currently_blocked = row[0], bool(row[1])
            conn.execute("DELETE FROM app_schedules WHERE id = ?", (schedule_id,))

        # If we currently have it blocked because of this schedule, unblock —
        # but only if no other active schedule still wants it blocked.
        if currently_blocked and not self._any_active_schedule_for(process):
            self.parental.unblock_app(process)
        try:
            self.db.log_parental_event("schedule_remove", process)
        except Exception:
            pass
        return {"ok": True}

    def _any_active_schedule_for(self, process: str) -> bool:
        now = datetime.now()
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                "SELECT start_minute, end_minute, days, enabled FROM app_schedules "
                "WHERE process = ?", (process,)
            ).fetchall()
        for start_min, end_min, days, enabled in rows:
            if not enabled:
                continue
            if self._is_within(now, start_min, end_min, days):
                return True
        return False

    @staticmethod
    def _is_within(now: datetime, start_min: int, end_min: int, days_str: str) -> bool:
        active_days = {int(d) for d in (days_str or "").split(",") if d.strip().isdigit()}
        if not active_days:
            return False
        weekday = now.weekday()  # Monday = 0
        cur_min = now.hour * 60 + now.minute
        # Same-day window
        if start_min < end_min:
            return weekday in active_days and start_min <= cur_min < end_min
        # Overnight window (e.g. 22:00 -> 07:00)
        if cur_min >= start_min:
            return weekday in active_days
        prev_day = (weekday - 1) % 7
        return prev_day in active_days

    def tick(self) -> List[dict]:
        """Apply / remove schedule-driven blocks. Called from the background loop."""
        actions = []
        now = datetime.now()
        with sqlite3.connect(self.db.db_path) as conn:
            rows = conn.execute(
                "SELECT id, process, executable_path, start_minute, end_minute, days, "
                "enabled, currently_blocked FROM app_schedules"
            ).fetchall()

        for (sched_id, process, exe, start_min, end_min, days, enabled,
             currently_blocked) in rows:
            if not enabled:
                if currently_blocked:
                    self.parental.unblock_app(process)
                    self._mark_blocked(sched_id, False)
                    actions.append({"process": process, "action": "unblock",
                                     "reason": "schedule_disabled"})
                continue

            should_block = self._is_within(now, start_min, end_min, days)
            if should_block and not currently_blocked:
                result = self.parental.block_app(process, exe or "")
                # Only mark as blocked if the firewall rule was actually created.
                # Otherwise leave currently_blocked=0 so the next tick retries,
                # and surface the reason instead of silently "succeeding".
                if result.get("ok"):
                    self._mark_blocked(sched_id, True)
                    try:
                        self.db.log_parental_event("schedule_block", process)
                    except Exception:
                        pass
                else:
                    print(f"[Schedule] Failed to block {process}: "
                          f"{result.get('error', 'unknown error')}")
                actions.append({"process": process, "action": "block",
                                 "ok": result.get("ok", False),
                                 "error": result.get("error", "")})
            elif not should_block and currently_blocked:
                # Only really unblock if no other schedule for this process is active.
                if not self._any_active_schedule_for(process):
                    self.parental.unblock_app(process)
                self._mark_blocked(sched_id, False)
                try:
                    self.db.log_parental_event("schedule_unblock", process)
                except Exception:
                    pass
                actions.append({"process": process, "action": "unblock",
                                 "reason": "schedule_window_ended"})

        return actions

    def _mark_blocked(self, schedule_id: int, blocked: bool):
        with sqlite3.connect(self.db.db_path) as conn:
            conn.execute(
                "UPDATE app_schedules SET currently_blocked = ? WHERE id = ?",
                (1 if blocked else 0, schedule_id),
            )


# ─────────────────────────── Activity Summary ──────────────────────────

class ActivitySummary:
    """Aggregate parental-control activity over a recent window."""

    def __init__(self, db):
        self.db = db

    def summary(self, days: int = 7) -> dict:
        days = max(1, min(int(days or 7), 90))
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db.db_path) as conn:
            # Parental events
            events = conn.execute(
                "SELECT event_type, target, timestamp FROM parental_events "
                "WHERE timestamp >= ? ORDER BY id DESC",
                (cutoff,)
            ).fetchall()
            # Block-related alerts (domain/process violations)
            alerts = conn.execute(
                "SELECT type, domain, process, severity, timestamp FROM alerts "
                "WHERE timestamp >= ?",
                (cutoff,)
            ).fetchall()

        block_count = sum(
            1 for ev in events
            if (ev[0] or "").endswith("_block") or ev[0] in ("pause_internet", "schedule_block")
        )

        top_blocked_domains = Counter(
            (a[1] or "").lower() for a in alerts
            if a[0] == "parental_control" and a[1]
        ).most_common(5)

        top_blocked_apps = Counter(
            ev[1] for ev in events
            if ev[0] == "schedule_block" and ev[1]
        ).most_common(5)

        hour_counts = Counter()
        for _, _, ts in events:
            try:
                hour_counts[datetime.fromisoformat(ts).hour] += 1
            except Exception:
                pass
        busiest_hours = sorted(
            hour_counts.items(), key=lambda kv: kv[1], reverse=True
        )[:3]

        recent_events = [
            {"event_type": ev[0], "target": ev[1], "timestamp": ev[2]}
            for ev in events[:20]
        ]

        return {
            "days": days,
            "total_events": len(events),
            "block_actions": block_count,
            "total_alerts": len(alerts),
            "top_blocked_domains": [
                {"domain": d, "count": c} for d, c in top_blocked_domains
            ],
            "top_blocked_apps": [
                {"process": p, "count": c} for p, c in top_blocked_apps
            ],
            "busiest_hours": [
                {"hour": h, "count": c} for h, c in busiest_hours
            ],
            "recent_events": recent_events,
        }
