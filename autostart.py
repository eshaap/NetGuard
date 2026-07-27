"""
autostart.py
NetGuard – Windows startup integration via the Startup folder.

Uses the Startup Folder method (safest, no registry writes, easily reversible):
  %%APPDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\NetGuard.lnk

The shortcut points at start_netguard.bat with --minimized so the app
loads directly to tray without opening the dashboard window.

No third-party packages required: the .lnk is created via the built-in
Windows Script Host COM object, invoked through a short PowerShell one-liner.
"""

import os
import subprocess
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────
_APPDATA        = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
_STARTUP_FOLDER = _APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
_SHORTCUT_PATH  = _STARTUP_FOLDER / "NetGuard.lnk"
_PROJECT_DIR    = Path(__file__).parent.resolve()
_BAT_PATH       = _PROJECT_DIR / "start_netguard.bat"


def is_autostart_enabled() -> bool:
    """Return True if the NetGuard startup shortcut already exists."""
    return _SHORTCUT_PATH.exists()


def enable_autostart() -> dict:
    """
    Create a .lnk shortcut in the Windows Startup folder.
    Launching with --minimized hides the dashboard and goes straight to tray.
    Safe to call multiple times – overwrites any previous shortcut.
    """
    if not _BAT_PATH.exists():
        return {"ok": False, "error": f"Launcher not found: {_BAT_PATH}"}

    # Escape backslashes for PowerShell string literals
    shortcut = str(_SHORTCUT_PATH).replace("\\", "\\\\")
    target   = str(_BAT_PATH).replace("\\", "\\\\")
    workdir  = str(_PROJECT_DIR).replace("\\", "\\\\")

    ps_cmd = (
        f"$ws = New-Object -ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut('{shortcut}'); "
        f"$s.TargetPath = '{target}'; "
        f"$s.Arguments = '--minimized'; "
        f"$s.WorkingDirectory = '{workdir}'; "
        f"$s.WindowStyle = 7; "          # 7 = minimized
        f"$s.Description = 'NetGuard Network Security Monitor'; "
        f"$s.Save()"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0:
            return {"ok": True}
        err = result.stderr.decode(errors="replace").strip()
        return {"ok": False, "error": err or "PowerShell returned non-zero exit code"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def disable_autostart() -> dict:
    """Remove the NetGuard startup shortcut if it exists."""
    try:
        if _SHORTCUT_PATH.exists():
            _SHORTCUT_PATH.unlink()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
