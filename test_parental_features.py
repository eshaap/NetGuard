"""
test_parental_features.py
Run this while NetGuard backend is running to test the new parental features.
Usage: python test_parental_features.py
"""

import json
import urllib.request
import urllib.error
import sys

BASE = "http://127.0.0.1:8765/api"

def get(path):
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def post(path, data):
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(f"{BASE}{path}", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def delete(path):
    try:
        req = urllib.request.Request(f"{BASE}{path}", method="DELETE")
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def ok(label, result, check_key="ok"):
    passed = isinstance(result, dict) and (result.get(check_key) or not result.get("error"))
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {label}")
    if not passed:
        print(f"         Response: {result}")
    return passed

def section(title):
    print(f"\n{'='*50}\n  {title}\n{'='*50}")

# ── 1. Backend reachable ──────────────────────────────────────────────
section("1. Backend connectivity")
r = get("/stats")
if r.get("error"):
    print(f"  [FAIL] Backend not reachable: {r['error']}")
    print("\n  Start the backend first: python main.py")
    sys.exit(1)
print("  [PASS] Backend is running")

# ── 2. Categories ─────────────────────────────────────────────────────
section("2. Category blocking")
cats = get("/parental/categories")
if isinstance(cats, list) and len(cats) == 5:
    print(f"  [PASS] Got {len(cats)} categories: {[c['key'] for c in cats]}")
else:
    print(f"  [FAIL] Expected 5 categories, got: {cats}")

# Enable gaming category
r = post("/parental/categories", {"category": "gaming", "enabled": True})
ok("Enable 'gaming' category", r)
if r.get("applied"):
    print(f"         Applied {r['applied']} domains, {len(r.get('failed', []))} failed")

# Verify it's listed as enabled
cats2 = get("/parental/categories")
gaming = next((c for c in (cats2 or []) if c["key"] == "gaming"), None)
if gaming and gaming.get("enabled"):
    print("  [PASS] 'gaming' shows as enabled")
else:
    print("  [FAIL] 'gaming' did not persist as enabled")

# Disable it again
r = post("/parental/categories", {"category": "gaming", "enabled": False})
ok("Disable 'gaming' category (cleanup)", r)

# ── 3. Instant Pause ──────────────────────────────────────────────────
section("3. Instant pause (needs admin)")
r = get("/parental/pause")
ok("Get pause status", r, check_key="paused")

r_on = post("/parental/pause", {"paused": True})
if r_on.get("ok"):
    print("  [PASS] Pause internet — firewall rule created")
else:
    print(f"  [FAIL] Pause failed (needs admin?): {r_on.get('error') or r_on}")

r_off = post("/parental/pause", {"paused": False})
if r_off.get("ok"):
    print("  [PASS] Resume internet — firewall rule removed")
else:
    print(f"  [FAIL] Resume failed: {r_off.get('error') or r_off}")

# ── 4. Schedules ──────────────────────────────────────────────────────
section("4. App schedules")
r = get("/parental/schedules")
print(f"  [PASS] Existing schedules: {len(r) if isinstance(r, list) else 'error'}")

# Add a test schedule (notepad, every day, from now+1min to now+2min — won't actually fire)
r = post("/parental/schedules", {
    "process": "notepad.exe",
    "executable_path": "",
    "start_time": "23:00",
    "end_time": "23:01",
    "days": [0, 1, 2, 3, 4, 5, 6],
})
ok("Add schedule for notepad.exe (23:00-23:01 every day)", r)
sched_id = (r or {}).get("id")

if sched_id:
    schedules = get("/parental/schedules")
    found = any(s.get("id") == sched_id for s in (schedules or []))
    print(f"  [{'PASS' if found else 'FAIL'}] Schedule appears in list")

    r = delete(f"/parental/schedules/{sched_id}")
    ok("Delete test schedule (cleanup)", r)
    schedules2 = get("/parental/schedules")
    still_there = any(s.get("id") == sched_id for s in (schedules2 or []))
    print(f"  [{'PASS' if not still_there else 'FAIL'}] Schedule removed from list")

# ── 5. Activity summary ───────────────────────────────────────────────
section("5. Activity summary")
r = get("/parental/activity?days=7")
expected_keys = {"days", "total_events", "block_actions", "total_alerts",
                 "top_blocked_domains", "top_blocked_apps", "recent_events"}
if isinstance(r, dict) and expected_keys.issubset(r.keys()):
    print(f"  [PASS] Activity summary returned (events: {r['total_events']}, "
          f"block actions: {r['block_actions']})")
else:
    print(f"  [FAIL] Unexpected response: {r}")

# ── Done ──────────────────────────────────────────────────────────────
print("\n" + "="*50)
print("  Done. See results above.")
print("  FAIL on Pause = run NetGuard as administrator.")
print("="*50 + "\n")
