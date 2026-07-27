"""
local_ai.py
Local LLM integration for NetGuard via Ollama (http://localhost:11434).

Runs fully offline — no API keys, no quota. Produces accurate, strictly
fact-grounded, concise summaries of security alerts and the overall monitoring
picture. Falls back to a built-in text summary when Ollama/model is unavailable.

One-time setup:
    1. Install Ollama:  https://ollama.com/download
    2. Pull the model:  ollama pull llama3.2:3b
"""

import asyncio
import json
import time
from pathlib import Path

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import urllib.request
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False

# NetGuard's identity + strict accuracy rules, injected as the system prompt so
# answers are grounded in what the app does and never invent facts.
BASE_SYSTEM = (
    "You are the built-in assistant for NetGuard, a real-time network-security "
    "and parental-control monitor for Windows. NetGuard tracks per-app bandwidth, "
    "checks each connection's IP/domain against threat intelligence (AbuseIPDB, "
    "OTX, Google Safe Browsing), assigns a 0-10 risk score, and can block domains "
    "or apps via the hosts file and Windows Firewall.\n"
    "STRICT RULES: Use ONLY the facts given in the user's message. Never invent "
    "IP addresses, numbers, domains, or report counts. If the evidence is thin, "
    "say so briefly. Answer in 2-3 short plain-English sentences. No markdown, no "
    "bullet lists, no preamble, no repeating the raw data back."
)


def _clean(value, limit: int = 120) -> str:
    """Coerce to a short, safe single-line string for prompts."""
    s = str(value if value is not None else "").replace("\n", " ").strip()
    return s[:limit]


class LocalAI:
    def __init__(self, db=None):
        # Optional Database handle — explanations are cached in SQLite so they
        # survive restarts and aren't regenerated for IPs we've already seen.
        self.db = db
        config = self._load_config()

        self.ollama_url = (config.get("ollama_url", "") or "http://localhost:11434").rstrip("/")
        self.model_name = config.get("llm_model", "") or "llama3.2:3b"

        # Per-task generation limits (strict optimization). Configurable.
        self.tok_alert = int(config.get("llm_max_tokens_alert", 100) or 100)
        self.tok_summary = int(config.get("llm_max_tokens_summary", 160) or 160)
        self.tok_chat = int(config.get("llm_max_tokens_chat", 140) or 140)
        self.temp_factual = float(config.get("llm_temperature_factual", 0.2) or 0.2)
        self.temp_chat = float(config.get("llm_temperature", 0.3) or 0.3)

        # In-memory cache: key -> (timestamp, text). 1-hour TTL.
        self._cache: dict = {}
        self._cache_ttl = 3600
        # Single-flight: key -> asyncio.Future of an in-progress generation.
        self._inflight: dict = {}

        self.available = self._check_available()
        if not self.available:
            print("[WARN] Local AI (Ollama) not available. NetGuard will use "
                  "built-in text summaries. To enable AI: install Ollama from "
                  f"https://ollama.com/download and run: ollama pull {self.model_name}")

    # ─── setup / availability ────────────────────────────────────────────

    def _load_config(self) -> dict:
        config_file = Path(__file__).parent / "config.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _check_available(self) -> bool:
        """Ping Ollama's /api/tags and confirm the configured model is present."""
        if not URLLIB_AVAILABLE:
            return False
        try:
            with urllib.request.urlopen(f"{self.ollama_url}/api/tags", timeout=2) as resp:
                data = json.loads(resp.read())
            models = [m.get("name", "") for m in data.get("models", [])]
            base = self.model_name.split(":")[0]
            if any(self.model_name == m or m.startswith(base) for m in models):
                return True
            print(f"[WARN] Ollama is running but model '{self.model_name}' is not "
                  f"installed. Run: ollama pull {self.model_name}")
            return False
        except Exception:
            return False

    # ─── alert explanation (type-aware, grounded) ────────────────────────

    def _fallback_alert(self, alert: dict) -> str:
        msg = _clean(alert.get("message", ""), 200)
        return msg or f"{alert.get('type', 'alert')} event for {alert.get('process', 'a process')}."

    def _alert_prompt(self, alert: dict) -> str:
        """Build a fact-only, type-specific prompt from an alert dict."""
        atype = (alert.get("type") or "").lower()
        process = _clean(alert.get("process", "unknown"))
        risk = alert.get("risk_score", 0)

        if atype in ("malicious_ip", "packet_malicious_ip", "suspicious_connection"):
            ip = _clean(alert.get("ip", ""))
            domain = _clean(alert.get("domain", "") or "")
            ts = alert.get("threat_summary", {}) or {}
            facts = [f"Alert: suspicious network connection.",
                     f"Process: {process}",
                     f"Remote IP: {ip}",
                     f"Resolved domain: {domain or 'unknown'}",
                     f"Risk score: {risk}/10"]
            if ts:
                if ts.get("abuse_confidence") is not None:
                    facts.append(f"AbuseIPDB confidence: {ts.get('abuse_confidence')}% "
                                 f"({ts.get('abuse_reports', 0)} reports)")
                if ts.get("country"):
                    facts.append(f"Country: {_clean(ts.get('country'), 8)}")
                if ts.get("isp"):
                    facts.append(f"ISP: {_clean(ts.get('isp'), 40)}")
                if ts.get("otx_pulses") is not None:
                    facts.append(f"OTX threat pulses: {ts.get('otx_pulses')}")
                if ts.get("gsb_flagged"):
                    facts.append(f"Google Safe Browsing: flagged as "
                                 f"{_clean(ts.get('gsb_threat_type', 'threat'), 40)}")
            facts.append("Explain in plain terms why this connection was flagged and "
                         "whether the user should be concerned.")
            return "\n".join(facts)

        if atype in ("bandwidth_threshold", "bandwidth_cap"):
            usage = alert.get("total_kbps") or alert.get("usage_kbps")
            cap = alert.get("cap_kbps")
            action = _clean(alert.get("action_taken", "alerted"))
            facts = [f"Alert: high network data usage (this is about bandwidth, not "
                     f"necessarily malware).",
                     f"Process: {process}",
                     f"Usage: {usage} KB/s" if usage is not None else f"Message: {_clean(alert.get('message',''),160)}"]
            if cap is not None:
                facts.append(f"Configured limit/cap: {cap} KB/s")
            facts.append(f"Action taken: {action}")
            facts.append("Explain what this likely means (e.g. download, streaming, "
                         "update, cloud sync) and what the user might check.")
            return "\n".join(facts)

        if atype == "parental_control":
            domain = _clean(alert.get("domain", "") or alert.get("ip", ""))
            facts = [f"Alert: a blocked website was accessed (parental control).",
                     f"Process: {process}",
                     f"Domain: {domain or 'unknown'}",
                     "Explain that this domain is blocked by a parental rule/category "
                     "and what that means for the user."]
            return "\n".join(facts)

        # Generic fallback prompt
        return (f"Alert type: {atype or 'unknown'}\n"
                f"Process: {process}\n"
                f"Details: {_clean(alert.get('message',''), 200)}\n"
                "Explain in plain terms what this means.")

    def _alert_cache_key(self, alert: dict) -> str:
        atype = (alert.get("type") or "").lower()
        if atype in ("malicious_ip", "packet_malicious_ip", "suspicious_connection"):
            ip = (alert.get("ip") or "").lower()
            if ip:
                return f"ip:{ip}"
        return f"alert:{alert.get('id', '')}"

    async def explain_alert_dict(self, alert: dict) -> str:
        """Generate a grounded, type-specific explanation for an alert dict."""
        if not self.available:
            return self._fallback_alert(alert)

        key = self._alert_cache_key(alert)
        cached = self._get_cached(key)
        if cached:
            return cached
        # Persistent cache for IP-keyed alerts.
        if key.startswith("ip:") and self.db is not None:
            persisted = self.db.get_gemini_explanation(key[3:])
            if persisted:
                self._set_cached(key, persisted)
                return persisted

        prompt = self._alert_prompt(alert)
        text = await self._run_single_flight(
            key, prompt, max_tokens=self.tok_alert, temperature=self.temp_factual
        )
        if not text:
            return self._fallback_alert(alert)
        if key.startswith("ip:") and self.db is not None:
            self.db.save_gemini_explanation(key[3:], text)
        return text

    async def explain_alert(self, process: str, ip: str = "", domain: str = None,
                            risk_score: int = 0, threat_data: dict = None) -> str:
        """Back-compat wrapper — builds a minimal alert dict."""
        return await self.explain_alert_dict({
            "type": "malicious_ip", "process": process, "ip": ip,
            "domain": domain, "risk_score": risk_score,
            "threat_summary": threat_data or {},
        })

    # ─── activity summary ─────────────────────────────────────────────────

    async def summarize_activity(self, snapshot: dict) -> str:
        """2-3 sentence situational summary from a compact monitoring snapshot."""
        if not self.available:
            return self._fallback_summary(snapshot)

        prompt = (
            "Summarize the current state of this machine's network monitoring for a "
            "home user. Facts:\n"
            f"- Active alerts: {snapshot.get('total_alerts', 0)} "
            f"(high severity: {snapshot.get('high_risk', 0)})\n"
            f"- Alert types seen: {_clean(snapshot.get('alert_types', 'none'), 120)}\n"
            f"- Active connections: {snapshot.get('active_connections', 0)}\n"
            f"- Blocked apps: {snapshot.get('blocked_apps', 0)}\n"
            f"- Top bandwidth apps: {_clean(snapshot.get('top_apps', 'none'), 120)}\n"
            f"- Safe Mode: {'on' if snapshot.get('safe_mode') else 'off'}\n"
            "Say whether things look normal or need attention, and why."
        )
        text = await self._run_single_flight(
            "summary:live", prompt, max_tokens=self.tok_summary,
            temperature=self.temp_factual, cache=False
        )
        return text or self._fallback_summary(snapshot)

    def _fallback_summary(self, snapshot: dict) -> str:
        return (f"{snapshot.get('total_alerts', 0)} active alerts "
                f"({snapshot.get('high_risk', 0)} high severity), "
                f"{snapshot.get('active_connections', 0)} active connections, "
                f"{snapshot.get('blocked_apps', 0)} blocked apps. "
                "Local AI is unavailable for a detailed summary.")

    # ─── free-form chat (snapshot-grounded) ──────────────────────────────

    async def explain_free(self, text: str, snapshot: str = None) -> str:
        """Answer a free-form question, optionally grounded in a live snapshot."""
        if not self.available:
            return ("Local AI is not running. Install Ollama "
                    f"(https://ollama.com/download) and run: ollama pull {self.model_name}")
        question = _clean(text, 400)
        if snapshot:
            prompt = (f"Current NetGuard state: {_clean(snapshot, 200)}\n\n"
                      f"User question: {question}")
        else:
            prompt = question
        try:
            answer = await self._generate(prompt, max_tokens=self.tok_chat,
                                          temperature=self.temp_chat)
            return answer or "No response from the local model."
        except Exception as e:
            return f"Local AI error: {e}"

    # ─── cache + single-flight helpers ───────────────────────────────────

    def _get_cached(self, key: str):
        item = self._cache.get(key)
        if item and (time.time() - item[0]) < self._cache_ttl:
            return item[1]
        return None

    def _set_cached(self, key: str, text: str):
        self._cache[key] = (time.time(), text)

    async def _run_single_flight(self, key: str, prompt: str, max_tokens: int,
                                 temperature: float, cache: bool = True) -> str:
        """Generate text, deduplicating concurrent calls for the same key and
        caching the result in memory."""
        if cache:
            hit = self._get_cached(key)
            if hit:
                return hit
        existing = self._inflight.get(key)
        if existing is not None:
            return await existing

        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        self._inflight[key] = fut
        try:
            text = await self._generate(prompt, max_tokens=max_tokens, temperature=temperature)
            if cache and text:
                self._set_cached(key, text)
            if not fut.done():
                fut.set_result(text)
            return text
        except Exception as e:
            print(f"[WARN] Local AI generation failed: {e}")
            if not fut.done():
                fut.set_result("")
            return ""
        finally:
            self._inflight.pop(key, None)

    # ─── ollama call ──────────────────────────────────────────────────────

    async def _generate(self, prompt: str, max_tokens: int = 120,
                        temperature: float = 0.2, system: str = BASE_SYSTEM) -> str:
        """Call Ollama's /api/generate. keep_alive keeps the model warm; num_predict
        caps length so answers stay short and fast."""
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp is not installed")

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "keep_alive": "10m",
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"{self.ollama_url}/api/generate", json=payload) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(f"Ollama HTTP {resp.status}: {body[:200]}")
                data = await resp.json()
                return (data.get("response", "") or "").strip()
