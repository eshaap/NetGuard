"""
estimator.py
psutil-based estimated per-process network usage.
"""

import ipaddress
import psutil
import time
from collections import deque


class EstimatorMonitor:
    def __init__(self, smoothing_window: int = 4):
        self._last_io = None
        self._last_io_time = time.time()
        self._up_history = deque(maxlen=smoothing_window)
        self._down_history = deque(maxlen=smoothing_window)

    def get_process_bandwidth(self) -> dict:
        """Return {pid: (upload_kbps, download_kbps)} using connection-count weighting."""
        total = psutil.net_io_counters()
        now = time.time()
        if self._last_io is None:
            self._last_io = total
            self._last_io_time = now
            return {}

        elapsed = max(now - self._last_io_time, 1e-6)
        total_up = max(0.0, (total.bytes_sent - self._last_io.bytes_sent) / elapsed / 1024)
        total_down = max(0.0, (total.bytes_recv - self._last_io.bytes_recv) / elapsed / 1024)
        self._last_io = total
        self._last_io_time = now

        self._up_history.append(total_up)
        self._down_history.append(total_down)
        total_up = sum(self._up_history) / len(self._up_history)
        total_down = sum(self._down_history) / len(self._down_history)

        active = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.pid or conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(conn.raddr.ip)
                except ValueError:
                    continue
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    continue
                active[conn.pid] = active.get(conn.pid, 0) + 1
        except Exception:
            return {}

        if not active:
            return {}

        total_weight = sum(active.values()) or len(active)
        result = {}
        for pid, weight in active.items():
            share = weight / total_weight
            result[pid] = (round(total_up * share, 1), round(total_down * share, 1))
        return result

