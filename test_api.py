#!/usr/bin/env python3
"""Test NetGuard API endpoints"""

import urllib.request
import json

API_BASE = "http://127.0.0.1:8765/api"

def test_endpoint(endpoint):
    try:
        url = f"{API_BASE}{endpoint}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            print(f"✅ {endpoint}: {len(data) if isinstance(data, list) else 'OK'} items")
            return True
    except Exception as e:
        print(f"❌ {endpoint}: {e}")
        return False

print("🔍 Testing NetGuard API endpoints...")
print("=" * 40)

# Test basic connectivity
try:
    urllib.request.urlopen("http://127.0.0.1:8765/api/stats", timeout=5)
    print("✅ Backend is running")
except:
    print("❌ Backend is NOT running")
    print("   Start with: python main.py")
    exit(1)

# Test endpoints
test_endpoint("/stats")
test_endpoint("/processes")
test_endpoint("/bandwidth")
test_endpoint("/alerts")

print("\nIf processes endpoint fails, check:")
print("- Backend is running: python main.py")
print("- psutil is installed: pip list | grep psutil")
print("- Admin privileges may be needed for full process info")