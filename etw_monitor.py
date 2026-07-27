"""
etw_monitor.py
Real per-process network usage via an out-of-process ETW helper.

Accurate mode is powered by a small .NET helper (etw_helper/) that consumes the
Windows kernel network ETW provider and writes real per-process byte counts
(TCP + UDP, send + receive) to a JSON file once per second. This Python class
launches that helper as a SEPARATE elevated process and diffs its output into
per-process KB/s.

Why a separate process: a crash in low-level ETW code cannot be caught by
Python and would otherwise take down the whole backend (this is exactly what the
old in-process pywintrace approach did). Running the helper out-of-process means
the worst case is "helper stops, fall back to estimation" — the backend is safe.

Requires Administrator (ETW is elevated-only). NetGuard self-elevates on launch.
If the helper is missing, not elevated, or dies, every method degrades cleanly:
start() returns False and get_process_bandwidth() returns {}.
"""

from __future__ import annotations

import json
import platform
import subprocess
import tempfile
import time
from pathlib import Path

_HELPER_EXE = (
    Path(__file__).parent / "etw_helper" / "bin" / "Release" / "net8.0" / "NetGuardEtwHelper.exe"
)
_SESSION_NAME = "NetGuardKernelNet"
_CREATE_NO_WINDOW = 0x08000000  # subprocess flag, Windows-only


class ETWMonitor:
    def __init__(self):
        self.available = platform.system().lower() == "windows"
        self.last_error = None
        self._running = False
        self._proc = None
        self._out_path = Path(tempfile.gettempdir()) / "netguard_bw.json"
        # pid -> (sentBytes, recvBytes) from the previous snapshot we read
        self._last_snapshot: dict[int, tuple[int, int]] = {}
        self._last_ts_ms = None  # timestamp of that snapshot, in ms

    # ─── lifecycle ────────────────────────────────────────────────────

    def start(self) -> bool:
        if not self.available:
            self.last_error = "ETW monitor is Windows-only"
            return False
        if self._running:
            return True
        if not _HELPER_EXE.exists():
            self.last_error = (
                "ETW helper not built. Build it with: "
                "dotnet build -c Release  (in the etw_helper folder)."
            )
            return False

        # Clear any ETW session orphaned by a previous hard-kill, and any stale
        # output file, so we start from a clean slate.
        self._stop_orphan_session()
        try:
            self._out_path.unlink()
        except OSError:
            pass

        try:
            self._proc = subprocess.Popen(
                [str(_HELPER_EXE), str(self._out_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception as exc:
            self.last_error = f"Could not launch ETW helper: {exc}"
            self._proc = None
            return False

        # Give it a moment, then make sure it didn't immediately exit (e.g.
        # NOT_ELEVATED). If it's still alive, the ETW session started.
        time.sleep(0.9)
        if self._proc.poll() is not None:
            self.last_error = self._read_exit_error()
            self._proc = None
            return False

        self._running = True
        self.last_error = None
        self._last_snapshot = {}
        self._last_ts_ms = None
        return True

    def stop(self):
        self._running = False
        if self._proc is not None:
            # Closing stdin signals the helper to stop its ETW session cleanly.
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
            except Exception:
                pass
            try:
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
            self._proc = None
        self._stop_orphan_session()
        try:
            self._out_path.unlink()
        except OSError:
            pass

    # ─── readout ──────────────────────────────────────────────────────

    def get_process_bandwidth(self) -> dict:
        """Return {pid: (upload_kbps, download_kbps)} for traffic since the
        previous call. Empty dict if not running or no fresh data."""
        if not self._running or self._proc is None:
            return {}
        if self._proc.poll() is not None:
            # Helper died unexpectedly — signal fallback to estimation.
            self.last_error = "ETW helper stopped unexpectedly."
            self._running = False
            return {}

        snapshot = self._read_snapshot()
        if not snapshot:
            return {}
        ts_ms = snapshot.get("ts")
        procs = snapshot.get("procs", {})

        result = {}
        if self._last_ts_ms is not None and ts_ms and ts_ms > self._last_ts_ms:
            elapsed = (ts_ms - self._last_ts_ms) / 1000.0
            if elapsed > 0:
                for pid_str, counts in procs.items():
                    try:
                        pid = int(pid_str)
                        sent, recv = int(counts[0]), int(counts[1])
                    except (ValueError, TypeError, IndexError):
                        continue
                    last_sent, last_recv = self._last_snapshot.get(pid, (0, 0))
                    d_sent = max(0, sent - last_sent)
                    d_recv = max(0, recv - last_recv)
                    up_kbps = d_sent / elapsed / 1024.0
                    down_kbps = d_recv / elapsed / 1024.0
                    if up_kbps > 0 or down_kbps > 0:
                        result[pid] = (round(up_kbps, 1), round(down_kbps, 1))

        # Update baseline for the next diff.
        new_baseline = {}
        for pid_str, counts in procs.items():
            try:
                new_baseline[int(pid_str)] = (int(counts[0]), int(counts[1]))
            except (ValueError, TypeError, IndexError):
                continue
        self._last_snapshot = new_baseline
        self._last_ts_ms = ts_ms
        return result

    # ─── helpers ──────────────────────────────────────────────────────

    def _read_snapshot(self):
        try:
            with open(self._out_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            # File missing or mid-write; caller treats as "no fresh data".
            return None

    def _read_exit_error(self) -> str:
        code = self._proc.returncode if self._proc else None
        err = ""
        try:
            raw = self._proc.stderr.read() if self._proc and self._proc.stderr else b""
            err = (raw or b"").decode(errors="ignore").strip()
        except Exception:
            pass
        if code == 5 or "NOT_ELEVATED" in err:
            return (
                "ETW helper requires Administrator privileges. Run NetGuard as "
                "administrator to enable accurate mode."
            )
        return f"ETW helper exited (code {code}): {err or 'unknown error'}"

    @staticmethod
    def _stop_orphan_session():
        try:
            subprocess.run(
                ["logman", "stop", _SESSION_NAME, "-ets"],
                capture_output=True,
                timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            pass
