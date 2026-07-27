"""Remove leftover NetGuard firewall rules from Windows Firewall."""
import ctypes
import subprocess

if not ctypes.windll.shell32.IsUserAnAdmin():
    print("ERROR: This needs admin. Right-click PowerShell -> Run as administrator,")
    print("       then re-run:  .\\.venv\\Scripts\\python.exe _cleanup_firewall_rules.py")
    raise SystemExit(1)

# List all rules whose name starts with "NetGuard "
out = subprocess.run(
    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
    capture_output=True, text=True, timeout=20
).stdout

names = set()
for line in out.splitlines():
    if line.startswith("Rule Name:"):
        n = line.split(":", 1)[1].strip()
        if n.startswith("NetGuard "):
            names.add(n)

print(f"Found {len(names)} NetGuard firewall rules:")
for n in sorted(names):
    print(f"  - {n}")

if not names:
    print("Nothing to clean up.")
    raise SystemExit(0)

print("\nDeleting...")
for n in sorted(names):
    r = subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={n}"],
        capture_output=True, text=True, timeout=10
    )
    status = "OK" if r.returncode == 0 else "FAIL"
    print(f"  [{status}] {n}")

print("\nDone. Verify with: netsh advfirewall firewall show rule name=all | findstr NetGuard")
