"""
threat_intel.py
Threat Intelligence API integrations:
  - AbuseIPDB (IP reputation)
  - AlienVault OTX (threat enrichment)
  - URLhaus (malicious URLs)
  - ThreatFox (IoC database)
  - Google Safe Browsing (phishing/malware URLs)

Configure API keys in config.json or environment variables.
"""

import os
import json
import asyncio
import random
import socket
import time
import hashlib
from pathlib import Path

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("[WARN] aiohttp not available, using mock threat data")

# ─── Load API keys ───────────────────────────────────────────────────
CONFIG_FILE = Path(__file__).parent / "config.json"
ENV_FILE = Path(__file__).parent / ".env"

def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def _load_env_file():
    if not ENV_FILE.exists():
        return
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value

_load_env_file()

CONFIG = load_config()

def _valid_api_key(value: str) -> str:
    """Return a usable API key, ignoring blank and placeholder config values."""
    value = (value or "").strip()
    if not value or value.upper().startswith("YOUR_"):
        return ""
    return value

ABUSEIPDB_KEY = _valid_api_key(CONFIG.get("abuseipdb_key")) or _valid_api_key(os.environ.get("ABUSEIPDB_KEY", ""))
OTX_KEY = _valid_api_key(CONFIG.get("otx_key")) or _valid_api_key(os.environ.get("OTX_KEY", ""))
GOOGLE_SAFE_BROWSING_KEY = (
    _valid_api_key(CONFIG.get("google_safe_browsing_key")) or
    _valid_api_key(os.environ.get("GOOGLE_SAFE_BROWSING_KEY", ""))
)
# abuse.ch gated all their APIs (incl. URLhaus) behind a free Auth-Key in 2024.
# Without it the endpoint returns 401, so a missing key means "unavailable".
URLHAUS_KEY = (
    _valid_api_key(CONFIG.get("urlhaus_key")) or
    _valid_api_key(os.environ.get("URLHAUS_KEY", ""))
)

# In-memory cache to avoid hammering APIs
_ip_cache: dict = {}
_url_cache: dict = {}
CACHE_TTL = 300  # 5 minutes


class ThreatIntelligence:
    def __init__(self):
        self.session = None

    async def close(self):
        if self.session is not None and not self.session.closed:
            await self.session.close()

    async def _get_session(self):
        if not AIOHTTP_AVAILABLE:
            return None
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8))
        return self.session

    # ─── IP Reputation ────────────────────────────────────────────────

    def _reverse_dns(self, ip: str) -> str:
        """Reverse-lookup the domain for an IP. Returns empty string on failure."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    async def check_ip(self, ip: str) -> dict:
        """Check IP against multiple threat intel sources, combine into risk score."""
        if not ip or ip.startswith(("10.", "192.168.", "127.", "172.")):
            return {"ip": ip, "risk_score": 0, "safe": True, "source": "private"}

        # Check cache
        cache_key = f"ip:{ip}"
        cached = _ip_cache.get(cache_key)
        if cached and time.time() - cached["_ts"] < CACHE_TTL:
            return cached

        results = {}
        live_sources = []
        simulated_sources = []

        # Try AbuseIPDB
        if ABUSEIPDB_KEY and AIOHTTP_AVAILABLE:
            results["abuseipdb"] = await self._check_abuseipdb(ip)
            live_sources.append("abuseipdb")
        else:
            results["abuseipdb"] = self._mock_abuseipdb(ip)
            simulated_sources.append("abuseipdb")

        # Try OTX
        if OTX_KEY and AIOHTTP_AVAILABLE:
            results["otx"] = await self._check_otx_ip(ip)
            live_sources.append("otx")
        else:
            results["otx"] = self._mock_otx(ip)
            simulated_sources.append("otx")

        # Google Safe Browsing via reverse DNS
        # Reverse-lookup runs in a thread so it doesn't block the event loop.
        domain = await asyncio.get_event_loop().run_in_executor(
            None, self._reverse_dns, ip
        )
        gsb_result = {"malicious": False, "threat_type": "", "domain": domain}
        if domain:
            if GOOGLE_SAFE_BROWSING_KEY and AIOHTTP_AVAILABLE:
                gsb_result = await self._check_google_safe_browsing(
                    f"http://{domain}"
                )
                gsb_result["domain"] = domain
                live_sources.append("gsb")
            else:
                gsb_result = self._mock_gsb(domain)
                gsb_result["domain"] = domain
                simulated_sources.append("gsb")
        results["gsb"] = gsb_result

        # Combine risk scores
        risk_score = self._combine_risk(results)

        result = {
            "ip": ip,
            "domain": domain,
            "risk_score": risk_score,
            "safe": risk_score < 5,
            "confidence": results.get("abuseipdb", {}).get("confidence", 0),
            "categories": results.get("abuseipdb", {}).get("categories", []),
            "otx_pulses": results.get("otx", {}).get("pulse_count", 0),
            "gsb_flagged": gsb_result.get("malicious", False),
            "gsb_threat_type": gsb_result.get("threat_type", ""),
            "source": "apis" if live_sources else "simulated",
            "live_sources": live_sources,
            "simulated_sources": simulated_sources,
            "details": results,
            "_ts": time.time(),
        }

        _ip_cache[cache_key] = result
        return result

    async def _check_abuseipdb(self, ip: str) -> dict:
        """Check AbuseIPDB for IP reputation."""
        session = await self._get_session()
        try:
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers, params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    confidence = d.get("abuseConfidenceScore", 0)
                    return {
                        "confidence": confidence,
                        "risk_score": round(confidence / 10, 1),
                        "total_reports": d.get("totalReports", 0),
                        "country": d.get("countryCode", ""),
                        "isp": d.get("isp", ""),
                        "categories": d.get("reports", [])[:3] if d.get("reports") else [],
                    }
        except Exception as e:
            print(f"[AbuseIPDB Error] {e}")
        return {"confidence": 0, "risk_score": 0}

    async def _check_otx_ip(self, ip: str) -> dict:
        """Check AlienVault OTX for IP threat data."""
        session = await self._get_session()
        try:
            headers = {"X-OTX-API-KEY": OTX_KEY}
            # OTX is frequently slow (10-15s); override the 8s session-wide
            # timeout so a slow-but-valid response isn't dropped to 0 pulses.
            async with session.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    return {
                        "pulse_count": pulse_count,
                        # Gentle scaling: shared cloud IPs (Anthropic, AWS, Azure,
                        # Google) almost always appear in a few OTX pulses. A
                        # handful of mentions should be low risk; only many pulses
                        # (a genuinely notorious IP) approach the max.
                        "risk_score": min(10, round(pulse_count * 0.5, 1)),
                        "reputation": data.get("reputation", 0),
                    }
        except Exception as e:
            print(f"[OTX Error] {e!r}")
        return {"pulse_count": 0, "risk_score": 0}

    def _mock_abuseipdb(self, ip: str) -> dict:
        """Deterministic mock based on IP hash - for demo without API key."""
        seed = int(hashlib.md5(ip.encode()).hexdigest()[:4], 16)
        random.seed(seed)
        # ~10% of IPs flagged as suspicious in demo
        confidence = random.choices(
            [0, random.randint(10, 40), random.randint(60, 100)],
            weights=[70, 20, 10]
        )[0]
        random.seed()  # Reset seed
        return {
            "confidence": confidence,
            "risk_score": round(confidence / 10, 1),
            "total_reports": confidence // 5,
            "country": random.choice(["US", "CN", "RU", "DE", "NL"]),
            "isp": "Demo ISP",
            "categories": ["Port Scan", "Brute Force"] if confidence > 50 else [],
        }

    def _mock_otx(self, ip: str) -> dict:
        seed = int(hashlib.md5((ip + "otx").encode()).hexdigest()[:4], 16)
        random.seed(seed)
        pulses = random.choices([0, 1, random.randint(3, 15)], weights=[75, 15, 10])[0]
        random.seed()
        return {"pulse_count": pulses, "risk_score": min(10, round(pulses * 0.5, 1))}

    def _combine_risk(self, results: dict) -> float:
        """Combine scores from multiple sources into unified 0-10 risk score.
        If Google Safe Browsing flags the domain, score is forced to at least 8
        regardless of what AbuseIPDB/OTX say — GSB catches new threats that
        haven't yet been reported to community databases."""
        scores = []
        weights = []

        # AbuseIPDB is the primary, most reliable abuse signal (direct abuse
        # reports). OTX is corroborating context — weighted lower so a few
        # threat-feed mentions of a shared cloud IP can't drive a high score on
        # their own.
        if "abuseipdb" in results:
            scores.append(results["abuseipdb"].get("risk_score", 0))
            weights.append(0.65)

        if "otx" in results:
            scores.append(results["otx"].get("risk_score", 0))
            weights.append(0.25)

        if not scores:
            return 0.0

        combined = sum(s * w for s, w in zip(scores, weights)) / sum(weights)

        # GSB confirmation: if Google flags the domain, escalate score to min 8
        if results.get("gsb", {}).get("malicious", False):
            combined = max(combined, 8.0)
            scores.append(8.0)

        return round(min(10, combined), 1)

    # ─── URL / Domain Checking ────────────────────────────────────────

    async def check_url(self, url: str) -> dict:
        """Check URL against URLhaus, ThreatFox, and Google Safe Browsing."""
        cache_key = f"url:{url}"
        cached = _url_cache.get(cache_key)
        if cached and time.time() - cached.get("_ts", 0) < CACHE_TTL:
            return cached

        results = {}

        # URLhaus check (free, no key needed)
        if AIOHTTP_AVAILABLE:
            results["urlhaus"] = await self._check_urlhaus(url)
        else:
            results["urlhaus"] = {"malicious": False, "source": "mock", "available": False}

        # Google Safe Browsing
        if GOOGLE_SAFE_BROWSING_KEY and AIOHTTP_AVAILABLE:
            results["gsb"] = await self._check_google_safe_browsing(url)
        else:
            results["gsb"] = self._mock_gsb(url)

        heuristic = self._score_url_heuristics(url)
        is_listed = (
            results.get("urlhaus", {}).get("malicious", False) or
            results.get("gsb", {}).get("malicious", False)
        )
        risk_score = max(
            10 if is_listed else 0,
            heuristic["risk_score"],
        )
        is_malicious = is_listed
        if risk_score >= 7:
            classification = "malicious"
        elif risk_score >= 3:
            classification = "risky"
        else:
            classification = "safe"

        result = {
            "url": url,
            "malicious": is_malicious,
            "risk_score": risk_score,
            "safe": classification == "safe",
            "heuristic": heuristic,
            "classification": classification,
            "urlhaus": results.get("urlhaus", {}),
            "google_safe_browsing": results.get("gsb", {}),
            "_ts": time.time(),
        }
        _url_cache[cache_key] = result
        return result

    async def _check_urlhaus(self, url: str) -> dict:
        """Check URL against URLhaus. abuse.ch requires a free Auth-Key header;
        without it the API returns 401. ``available`` lets callers tell a real
        "clean" result apart from a failed lookup."""
        if not URLHAUS_KEY:
            return {"malicious": False, "status": "no_key", "available": False}
        session = await self._get_session()
        try:
            async with session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": URLHAUS_KEY},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # The single-URL lookup returns query_status "ok" when the URL
                    # IS in the URLhaus database, or "no_results" when it isn't.
                    # (There is no "is_listed" value for this endpoint.)
                    query_status = data.get("query_status", "")
                    return {
                        "malicious": query_status == "ok",
                        "status": query_status,
                        "available": True,
                        "threat": data.get("threat", ""),
                        "url_status": data.get("url_status", ""),
                        "tags": data.get("tags", []),
                    }
                return {"malicious": False, "status": f"http_{resp.status}", "available": False}
        except Exception as e:
            print(f"[URLhaus Error] {e}")
        return {"malicious": False, "status": "error", "available": False}

    async def _check_google_safe_browsing(self, url: str) -> dict:
        """Check URL with Google Safe Browsing API."""
        session = await self._get_session()
        try:
            payload = {
                "client": {"clientId": "netguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            async with session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
                json=payload
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    matches = data.get("matches", [])
                    return {
                        "malicious": len(matches) > 0,
                        "threat_type": matches[0].get("threatType", "") if matches else "",
                    }
        except Exception as e:
            print(f"[GSB Error] {e}")
        return {"malicious": False}

    def _mock_gsb(self, url: str) -> dict:
        """Mock GSB for demo mode."""
        suspicious_keywords = ["phish", "malware", "hack", "bot", "free-money", "login-verify"]
        malicious = any(kw in url.lower() for kw in suspicious_keywords)
        return {"malicious": malicious, "threat_type": "SOCIAL_ENGINEERING" if malicious else ""}

    def _score_url_heuristics(self, url: str) -> dict:
        """Assign a lightweight risk score for suspicious URL patterns."""
        parsed = url.lower()
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
        except Exception:
            parsed_url = None
        score = 0
        reasons = []

        host = (parsed_url.hostname or "").lower() if parsed_url else ""
        path = (parsed_url.path or "").lower() if parsed_url else ""

        if any(token in parsed for token in ("torrent", "proxy", "pirate", "crack", "warez")):
            score += 4
            reasons.append("high-risk keyword")

        if any(token in host for token in ("blogspot", "wordpress", "free", "click", "track")):
            score += 1
            reasons.append("host pattern")

        if any(token in parsed for token in ("download", "setup", "install", "free", "bonus", "gift", "login")):
            score += 2
            reasons.append("download/login lure")

        if parsed.startswith("http://") and "localhost" not in parsed and "127.0.0.1" not in parsed:
            score += 2
            reasons.append("plain http")

        if parsed.count(".") >= 3:
            score += 1
            reasons.append("deep subdomain")

        if path and path not in ("/", ""):
            score += 1
            reasons.append("non-root path")

        if "-" in path or "_" in path:
            score += 1
            reasons.append("suspicious path naming")

        if any(token in parsed for token in ("@", "//")) and parsed.count("/") > 3:
            score += 1
            reasons.append("odd path structure")

        return {
            "risk_score": min(10, score),
            "reasons": reasons,
        }

    # ─── ThreatFox IoC Check ──────────────────────────────────────────

    async def check_ioc(self, indicator: str) -> dict:
        """Check indicator against ThreatFox database."""
        if not AIOHTTP_AVAILABLE:
            return {"found": False, "source": "mock"}
        session = await self._get_session()
        try:
            payload = {"query": "search_ioc", "search_term": indicator}
            async with session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    query_status = data.get("query_status", "")
                    return {
                        "found": query_status == "ok" and data.get("data"),
                        "malware": data.get("data", [{}])[0].get("malware", "") if data.get("data") else "",
                        "confidence": data.get("data", [{}])[0].get("confidence_level", 0) if data.get("data") else 0,
                    }
        except Exception as e:
            print(f"[ThreatFox Error] {e}")
        return {"found": False}
