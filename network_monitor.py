"""
network_monitor.py
Hybrid network monitor that can use psutil estimation or ETW fallback.
"""

import asyncio
import ipaddress
import psutil
import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional

from estimator import EstimatorMonitor
from etw_monitor import ETWMonitor

# Minimum gap between fresh net_io_counters() samples. Anything faster than this
# returns the cached reading so multiple callers in the same tick don't race
# each other and starve the delta window.
_BW_SAMPLE_MIN_INTERVAL = 0.75
# EWMA factor for total bandwidth smoothing on the dashboard chart.
_BW_SMOOTHING = 0.4
# How long a process keeps showing in the table after its last active
# connection, so the list stays readable instead of flickering on/off every
# few seconds. While lingering, its bandwidth fades toward zero.
_PROCESS_LINGER_SECONDS = 15
# Hard cap: drop a process from the cache entirely once it's this stale.
_PROCESS_CACHE_TTL_SECONDS = 30

try:
    from scapy.all import IP, TCP, UDP, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    IP = TCP = UDP = sniff = None
    SCAPY_AVAILABLE = False


class NetworkMonitor:
    def __init__(self):
        self.start_time = time.time()
        self._bw_lock = threading.Lock()
        self._bw_last_counters = self._read_nic_counters()
        self._bw_last_sample_time = time.time()
        self._bw_cached = {"download_kbps": 0.0, "upload_kbps": 0.0}
        self._bw_smoothed_down = 0.0
        self._bw_smoothed_up = 0.0
        self.packet_sniffer_thread = None
        self.packet_sniffing_active = False
        self.packet_sniffing_error = None
        self.recent_packets = []
        self.packet_threat_results = []
        self.packet_ip_check_times = {}
        self.mode = "estimation"
        self.estimator = EstimatorMonitor()
        self.etw = ETWMonitor()
        self._usage_cache = {}
        self._usage_cache_ts = {}

    _loopback_nics_cache = None

    @classmethod
    def _loopback_nic_names(cls) -> set:
        """Detect loopback interfaces by their actual addresses (127.x.x.x / ::1),
        not by name guessing. Cached because interfaces don't change often."""
        if cls._loopback_nics_cache is not None:
            return cls._loopback_nics_cache
        loopback = set()
        try:
            for nic, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    ip = (addr.address or "").split("%")[0]
                    if ip.startswith("127.") or ip == "::1":
                        loopback.add(nic)
                        break
        except Exception:
            pass
        cls._loopback_nics_cache = loopback
        return loopback

    @classmethod
    def _read_nic_counters(cls):
        """Sum bytes across all real NICs, excluding true loopback interfaces."""
        try:
            per_nic = psutil.net_io_counters(pernic=True)
        except Exception:
            return None
        loopback = cls._loopback_nic_names()
        bytes_sent = 0
        bytes_recv = 0
        for name, counters in per_nic.items():
            if name in loopback:
                continue
            bytes_sent += counters.bytes_sent
            bytes_recv += counters.bytes_recv
        return (bytes_sent, bytes_recv)

    def set_mode(self, mode: str) -> dict:
        mode = (mode or "estimation").lower()
        if mode == "accurate":
            if self.etw.start():
                self.mode = "accurate"
                return {"mode": self.mode, "ok": True}
            self.mode = "estimation"
            return {"mode": self.mode, "ok": False, "error": self.etw.last_error}

        self.mode = "estimation"
        self.etw.stop()
        return {"mode": self.mode, "ok": True}

    def get_mode(self) -> str:
        return self.mode

    def get_active_connections(self) -> List[Dict]:
        connections = []
        # Include SynSent so outgoing connection attempts are checked too —
        # malware and torrent peers often appear in SynSent before ESTABLISHED.
        _ACTIVE_STATUSES = {'ESTABLISHED', 'SYN_SENT', 'SynSent', ''}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr:
                    continue
                if conn.status not in _ACTIVE_STATUSES:
                    continue
                remote_ip = conn.raddr.ip
                # Strip IPv6 zone IDs (e.g. "fe80::1%eth0" → "fe80::1")
                if '%' in remote_ip:
                    remote_ip = remote_ip.split('%')[0]
                try:
                    process = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                except Exception:
                    process = "unknown"
                connections.append({
                    "local_ip": conn.laddr.ip if conn.laddr else None,
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "remote_ip": remote_ip,
                    "remote_port": conn.raddr.port,
                    "domain": None,
                    "process": process,
                    "status": conn.status
                })
        except Exception as e:
            print(f"Error getting connections: {e}")
        return connections

    def get_bandwidth(self) -> dict:
        """Return smoothed total bandwidth. Safe to call repeatedly — the sample
        window is throttled so callers within the same tick share one reading."""
        try:
            with self._bw_lock:
                now = time.time()
                elapsed = now - self._bw_last_sample_time
                if elapsed < _BW_SAMPLE_MIN_INTERVAL:
                    return dict(self._bw_cached)

                counters = self._read_nic_counters()
                if counters is None or self._bw_last_counters is None:
                    self._bw_last_counters = counters
                    self._bw_last_sample_time = now
                    return dict(self._bw_cached)

                sent_delta = max(0, counters[0] - self._bw_last_counters[0])
                recv_delta = max(0, counters[1] - self._bw_last_counters[1])
                # Guard against the rare divide-by-zero from a clock jump.
                window = max(elapsed, 1e-3)
                raw_up = sent_delta / window / 1024
                raw_down = recv_delta / window / 1024

                self._bw_smoothed_up = (
                    _BW_SMOOTHING * raw_up + (1 - _BW_SMOOTHING) * self._bw_smoothed_up
                )
                self._bw_smoothed_down = (
                    _BW_SMOOTHING * raw_down + (1 - _BW_SMOOTHING) * self._bw_smoothed_down
                )

                self._bw_last_counters = counters
                self._bw_last_sample_time = now
                self._bw_cached = {
                    "download_kbps": round(max(0.0, self._bw_smoothed_down), 2),
                    "upload_kbps": round(max(0.0, self._bw_smoothed_up), 2),
                }
                return dict(self._bw_cached)
        except Exception as e:
            return {"error": str(e)}

    def get_process_usage(self) -> list:
        if self.mode == "accurate":
            etw_data = self.etw.get_process_bandwidth()
            if etw_data:
                return self._build_process_rows_from_bandwidth_map(etw_data)
            if self.etw.last_error:
                self.mode = "estimation"

        return self._get_estimated_process_usage()

    def _get_estimated_process_usage(self) -> list:
        bw = self.get_bandwidth()
        total_up = max(0.0, float(bw.get("upload_kbps", 0.0) or 0.0))
        total_down = max(0.0, float(bw.get("download_kbps", 0.0) or 0.0))
        now = time.time()

        active_pids = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.pid or not conn.raddr:
                    continue
                # Accept ESTABLISHED (TCP) and stateless (UDP/QUIC) active connections
                if conn.status not in ('ESTABLISHED', ''):
                    continue
                try:
                    ip_obj = ipaddress.ip_address(conn.raddr.ip)
                except ValueError:
                    continue
                # Only skip true loopback (127.x) — allow private/LAN IPs
                if ip_obj.is_loopback or ip_obj.is_link_local:
                    continue
                active_pids[conn.pid] = active_pids.get(conn.pid, 0) + 1
        except Exception as e:
            print(f"[ERROR] Failed to read network connections: {e}")

        processes = []
        for pid, connections in active_pids.items():
            try:
                proc = psutil.Process(pid)
                name = proc.name() or "unknown"
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe_path = ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            processes.append({"pid": pid, "process": name, "exe": exe_path, "active_connections": connections})

        if not processes:
            return self._get_cached_process_usage(now)

        total_connections = sum(max(1, p["active_connections"]) for p in processes) or len(processes)
        for proc in processes:
            share = max(1, proc["active_connections"]) / total_connections
            proc["upload_kbps"] = round(total_up * share, 1)
            proc["download_kbps"] = round(total_down * share, 1)

            pid = proc["pid"]
            prev = self._usage_cache.get(pid, {"upload_kbps": 0.0, "download_kbps": 0.0})
            proc["upload_kbps"] = round((prev.get("upload_kbps", 0.0) * 0.7) + (proc["upload_kbps"] * 0.3), 1)
            proc["download_kbps"] = round((prev.get("download_kbps", 0.0) * 0.7) + (proc["download_kbps"] * 0.3), 1)
            self._usage_cache[pid] = {
                "upload_kbps": proc["upload_kbps"],
                "download_kbps": proc["download_kbps"],
                "pid": pid,
                "process": proc["process"],
                "exe": proc["exe"],
                "active_connections": proc["active_connections"],
            }
            self._usage_cache_ts[pid] = now

        return self._get_cached_process_usage(now, current_rows=processes)

    def _get_cached_process_usage(self, now: float, current_rows: list = None) -> list:
        """Return recent usage rows so the dashboard doesn't drop to zeros between spikes."""
        fresh_rows = []
        current_pids = {row["pid"] for row in (current_rows or [])}
        for pid, row in list(self._usage_cache.items()):
            age = now - self._usage_cache_ts.get(pid, now)
            if age > _PROCESS_CACHE_TTL_SECONDS:
                self._usage_cache.pop(pid, None)
                self._usage_cache_ts.pop(pid, None)
                continue
            # Processes currently holding a connection always show. Ones that
            # have gone quiet linger for a window so the table doesn't flicker.
            if pid not in current_pids:
                if age > _PROCESS_LINGER_SECONDS:
                    continue
                # Fade the lingering row's bandwidth toward zero over the window
                # so a disconnected process trends to 0 instead of freezing.
                decay = max(0.0, 1.0 - age / _PROCESS_LINGER_SECONDS)
                row = dict(row)
                row["upload_kbps"] = round(row.get("upload_kbps", 0.0) * decay, 1)
                row["download_kbps"] = round(row.get("download_kbps", 0.0) * decay, 1)
                fresh_rows.append(row)
                continue
            fresh_rows.append(dict(row))
        fresh_rows.sort(key=lambda p: (p.get("active_connections", 0), p.get("upload_kbps", 0) + p.get("download_kbps", 0)), reverse=True)
        return fresh_rows[:25]

    def _build_process_rows_from_bandwidth_map(self, bw_map: dict) -> list:
        rows = []
        now = time.time()
        for pid, (up, down) in bw_map.items():
            try:
                proc = psutil.Process(pid)
                row = {
                    "pid": pid,
                    "process": proc.name() or "unknown",
                    "exe": "",
                    "upload_kbps": round(float(up), 1),
                    "download_kbps": round(float(down), 1),
                    "active_connections": len(proc.connections(kind="inet")),
                }
            except Exception:
                continue
            rows.append(row)
            # Feed the same linger cache estimation uses, so accurate mode
            # rows also stay visible briefly instead of flickering.
            self._usage_cache[pid] = dict(row)
            self._usage_cache_ts[pid] = now
        return self._get_cached_process_usage(now, current_rows=rows)

    def start_packet_sniffing(
        self,
        threat_intel=None,
        event_loop: Optional[asyncio.AbstractEventLoop] = None,
        packet_count: int = 100,
        packet_filter: str = "ip and (tcp or udp)",
        result_callback: Optional[Callable[[dict, dict], None]] = None,
    ) -> bool:
        if not SCAPY_AVAILABLE:
            self.packet_sniffing_error = "Scapy is not installed. Run: pip install scapy"
            print(f"[Packet Sniffer] {self.packet_sniffing_error}")
            return False
        if self.packet_sniffing_active:
            return True
        self.packet_sniffing_active = True
        self.packet_sniffing_error = None
        self.packet_sniffer_thread = threading.Thread(
            target=self._run_packet_sniffer,
            kwargs={
                "threat_intel": threat_intel,
                "event_loop": event_loop,
                "packet_count": packet_count,
                "packet_filter": packet_filter,
                "result_callback": result_callback,
            },
            daemon=True,
            name="NetGuardPacketSniffer",
        )
        self.packet_sniffer_thread.start()
        return True

    def _run_packet_sniffer(self, threat_intel=None, event_loop=None, packet_count=100, packet_filter="ip and (tcp or udp)", result_callback=None):
        try:
            sniff(filter=packet_filter, prn=lambda packet: self.process_packet(packet, threat_intel, event_loop, result_callback), count=max(1, packet_count), store=False)
        except Exception as e:
            self.packet_sniffing_error = str(e)
        finally:
            self.packet_sniffing_active = False

    def process_packet(self, packet, threat_intel=None, event_loop=None, result_callback=None):
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return
        self.recent_packets.insert(0, packet_info)
        self.recent_packets = self.recent_packets[:100]

    def _extract_packet_info(self, packet):
        try:
            if IP not in packet:
                return None
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else None
            if protocol is None:
                return None
            return {"source_ip": packet[IP].src, "destination_ip": packet[IP].dst, "protocol": protocol, "timestamp": time.time()}
        except Exception:
            return None

    def get_uptime(self) -> str:
        elapsed = int(time.time() - self.start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        return f"{h:02d}:{m:02d}:{s:02d}"
