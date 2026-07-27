"""
parental_control.py
Parental controls for blocking domains and applications
"""

import os
import platform
import re
import sqlite3
import socket
import subprocess
import ipaddress
from pathlib import Path
from typing import List
from urllib.parse import urlparse

class ParentalControl:
    def __init__(self, db):
        self.db = db
        self.safe_mode = False
        self.blocked_domains = self._load_blocked_domains()
        self.blocked_apps = self._load_blocked_apps()
    
    def _load_blocked_domains(self) -> List[str]:
        """Load blocked domains from database"""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.execute('SELECT domain FROM blocked_domains')
                return [row[0] for row in cursor.fetchall()]
        except Exception:
            return []
    
    def _load_blocked_apps(self) -> List[str]:
        """Load blocked apps from database"""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.execute('SELECT process FROM blocked_apps')
                return [row[0] for row in cursor.fetchall()]
        except Exception:
            return []

    def get_blocked_domains(self) -> List[str]:
        """Return blocked domains"""
        return self.blocked_domains

    def get_blocked_apps(self) -> List[str]:
        """Return blocked apps"""
        return self.blocked_apps

    def _normalize_domain(self, value: str) -> str:
        """Accept plain domains or full URLs and normalize them to a hostname."""
        value = (value or "").strip().lower()
        if not value:
            return ""

        candidate = value if "://" in value else f"http://{value}"
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").strip(".").lower()
        if not host:
            return ""
        return host

    def _hosts_file_path(self) -> Path:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"

    def _host_variants(self, domain: str) -> List[str]:
        """Block both the literal host and a common www/non-www counterpart."""
        domain = self._normalize_domain(domain)
        if not domain:
            return []
        variants = {domain}
        if domain.startswith("www."):
            variants.add(domain[4:])
        else:
            variants.add(f"www.{domain}")
        return sorted(variants)

    def batch_block_domains(self, domains: list, remove: bool = False) -> dict:
        """Add or remove many domains in one hosts-file write.
        Skips per-domain DNS lookups and firewall rules — used by category toggles
        where the hosts file is the primary enforcement and N firewall rules would
        be far too slow."""
        if platform.system() != "Windows":
            return {"ok": False, "error": "Hosts-file domain blocking is only implemented for Windows."}

        all_variants = set()
        normalized_list = []
        for d in domains:
            normalized = self._normalize_domain(d)
            if not normalized:
                continue
            normalized_list.append(normalized)
            for v in self._host_variants(normalized):
                all_variants.add(v)
        if not all_variants:
            return {"ok": False, "error": "No valid domains provided."}

        hosts_path = self._hosts_file_path()
        marker = "# NetGuard block"
        marker_low = marker.lower()
        try:
            existing = hosts_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            return {"ok": False, "error": f"Could not read hosts file: {e}"}

        # Drop any prior NetGuard entries for any of these hosts
        kept_lines = []
        for line in existing:
            low = line.lower()
            if marker_low in low and any(host in low for host in all_variants):
                continue
            kept_lines.append(line)

        if not remove:
            for host in sorted(all_variants):
                kept_lines.append(f"127.0.0.1 {host} {marker}")
                kept_lines.append(f"::1 {host} {marker}")

        content = "\n".join(kept_lines).rstrip() + "\n"
        hosts_warning = ""
        try:
            hosts_path.write_text(content, encoding="utf-8")
        except PermissionError:
            # Adding without the hosts write means the block isn't enforced, so fail.
            # Removing is different: the DB/list cleanup below is what the user sees,
            # so we downgrade this to a warning instead of orphaning the DB rows.
            if not remove:
                return {"ok": False, "error": "Administrator privileges are required to update the Windows hosts file."}
            hosts_warning = "Hosts file not updated (administrator privileges required); blocklist cleaned."
        except Exception as e:
            if not remove:
                return {"ok": False, "error": f"Could not update hosts file: {e}"}
            hosts_warning = f"Hosts file not updated ({e}); blocklist cleaned."

        # Update in-memory list + DB in one transaction
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                if remove:
                    for d in normalized_list:
                        conn.execute('DELETE FROM blocked_domains WHERE domain = ?', (d,))
                        if d in self.blocked_domains:
                            self.blocked_domains.remove(d)
                else:
                    for d in normalized_list:
                        conn.execute(
                            'INSERT OR REPLACE INTO blocked_domains (domain, added_date) VALUES (?, datetime("now"))',
                            (d,)
                        )
                        if d not in self.blocked_domains:
                            self.blocked_domains.append(d)
        except Exception as e:
            return {"ok": False, "error": f"DB update failed: {e}"}

        result = {"ok": True, "applied": len(normalized_list)}
        if hosts_warning:
            result["warning"] = hosts_warning
        return result

    def _sync_hosts_block(self, domain: str, remove: bool = False) -> dict:
        """Add or remove hosts-file block entries for a domain."""
        if platform.system() != "Windows":
            return {"ok": False, "error": "Hosts-file domain blocking is only implemented for Windows."}

        normalized = self._normalize_domain(domain)
        if not normalized:
            return {"ok": False, "error": "A valid domain or URL is required."}

        hosts_path = self._hosts_file_path()
        marker = "# NetGuard block"
        variants = self._host_variants(normalized)

        try:
            existing = hosts_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            return {"ok": False, "error": f"Could not read hosts file: {e}"}

        kept_lines = []
        for line in existing:
            lower_line = line.lower()
            if marker.lower() in lower_line and any(host in lower_line for host in variants):
                continue
            kept_lines.append(line)

        if not remove:
            for host in variants:
                kept_lines.append(f"127.0.0.1 {host} {marker}")
                kept_lines.append(f"::1 {host} {marker}")

        content = "\n".join(kept_lines).rstrip() + "\n"
        try:
            hosts_path.write_text(content, encoding="utf-8")
        except PermissionError:
            return {"ok": False, "error": "Administrator privileges are required to update the Windows hosts file."}
        except Exception as e:
            return {"ok": False, "error": f"Could not update hosts file: {e}"}

        return {"ok": True, "domain": normalized, "hosts_path": str(hosts_path)}

    def _firewall_rule_name(self, process: str) -> str:
        """Use a stable Windows Firewall rule name for each blocked process."""
        return f"NetGuard Block {process}"

    def _has_invalid_netsh_chars(self, *values: str) -> bool:
        for value in values:
            if any(char in (value or "") for char in ('"', "\n", ";")):
                return True
        return False

    def _domain_firewall_rule_name(self, domain: str) -> str:
        normalized = self._normalize_domain(domain)
        return f"NetGuard Domain Block {normalized}"

    def _domain_firewall_rule_name_for_family(self, domain: str, family: str) -> str:
        normalized = self._normalize_domain(domain)
        return f"NetGuard Domain Block {normalized} ({family})"

    def _run_netsh(self, args: List[str]) -> dict:
        """Run a Windows Firewall netsh command and return a structured result."""
        if platform.system() != "Windows":
            return {"ok": False, "error": "OS-level app blocking is only implemented for Windows."}

        try:
            completed = subprocess.run(
                ["netsh", *args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as e:
            return {"ok": False, "error": str(e)}

        output = (completed.stdout or completed.stderr or "").strip()
        return {
            "ok": completed.returncode == 0,
            "error": "" if completed.returncode == 0 else output,
            "output": output,
        }

    def _add_firewall_block(self, process: str, executable_path: str) -> dict:
        """Create a Windows Firewall outbound block rule for an executable path."""
        if not executable_path:
            return {"ok": False, "error": "Executable path is required for Windows Firewall blocking."}
        if self._has_invalid_netsh_chars(process, executable_path):
            return {"ok": False, "error": "Invalid characters in process name or path."}
        if not os.path.exists(executable_path):
            return {"ok": False, "error": f"Executable path not found: {executable_path}"}
        if not os.path.isfile(executable_path):
            return {"ok": False, "error": f"Executable path is a folder, not a file. Did you forget the .exe filename at the end? Path: {executable_path}"}
        if not executable_path.lower().endswith(".exe"):
            return {"ok": False, "error": f"Executable path must end in .exe (got: {executable_path}). Windows Firewall blocks programs by their .exe file path, not by folder or shortcut."}

        rule_name = self._firewall_rule_name(process)
        self._delete_firewall_block(process)
        return self._run_netsh([
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"program={executable_path}",
            "enable=yes",
        ])

    def _delete_firewall_block(self, process: str) -> dict:
        """Remove the Windows Firewall block rule for a process."""
        if self._has_invalid_netsh_chars(process):
            return {"ok": False, "error": "Invalid characters in process name or path."}
        return self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name={self._firewall_rule_name(process)}",
        ])

    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolve a domain to a deduplicated list of IPs for firewall rules."""
        normalized = self._normalize_domain(domain)
        if not normalized:
            return []

        resolved = set()
        for host in self._host_variants(normalized):
            try:
                for result in socket.getaddrinfo(host, None):
                    ip = result[4][0]
                    if not ip:
                        continue
                    try:
                        # Keep only literal public-ish IPs that netsh accepts.
                        ip_obj = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if ip_obj.is_loopback or ip_obj.is_unspecified:
                        continue
                    resolved.add(ip)
            except socket.gaierror:
                continue
        if resolved:
            return sorted(resolved)
        return self._resolve_domain_ips_via_nslookup(normalized)

    def _resolve_domain_ips_via_nslookup(self, domain: str) -> List[str]:
        """Fallback DNS resolution that bypasses hosts-file rewrites on Windows."""
        resolved = set()
        for host in self._host_variants(domain):
            try:
                completed = subprocess.run(
                    ["nslookup", host],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except Exception:
                continue

            output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
            for match in re.findall(r"Address:\s*([^\s]+)", output, flags=re.IGNORECASE):
                try:
                    ip_obj = ipaddress.ip_address(match.strip())
                except ValueError:
                    continue
                if ip_obj.is_loopback or ip_obj.is_unspecified:
                    continue
                resolved.add(str(ip_obj))
        return sorted(resolved)

    def _add_domain_firewall_block(self, domain: str, ips: List[str] = None) -> dict:
        """Create a Windows Firewall rule for the currently resolved domain IPs."""
        normalized = self._normalize_domain(domain)
        if not normalized:
            return {"ok": False, "error": "A valid domain or URL is required."}

        ips = list(ips) if ips is not None else self._resolve_domain_ips(normalized)
        if not ips:
            return {
                "ok": False,
                "error": (
                    f"Could not resolve any valid IP addresses for {normalized}. "
                    "Windows Firewall requires literal IPs for this rule."
                ),
            }

        ipv4_ips = []
        ipv6_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip_obj.version == 4:
                ipv4_ips.append(ip)
            else:
                ipv6_ips.append(ip)

        if not ipv4_ips and not ipv6_ips:
            return {
                "ok": False,
                "error": f"No valid IPv4 or IPv6 addresses remained for {normalized}.",
            }

        self._delete_domain_firewall_block(normalized)
        family_results = []
        for family, family_ips in (("IPv4", ipv4_ips), ("IPv6", ipv6_ips)):
            if not family_ips:
                continue
            family_results.append(
                self._run_netsh([
                    "advfirewall", "firewall", "add", "rule",
                    f"name={self._domain_firewall_rule_name_for_family(normalized, family)}",
                    "dir=out",
                    "action=block",
                    "enable=yes",
                    f"remoteip={','.join(family_ips)}",
                ])
            )

        ok = all(result.get("ok") for result in family_results)
        errors = [result.get("error", "") for result in family_results if not result.get("ok")]
        return {
            "ok": ok,
            "error": "\n".join(error for error in errors if error),
            "ips": ips,
            "ipv4_ips": ipv4_ips,
            "ipv6_ips": ipv6_ips,
            "results": family_results,
        }

    def _delete_domain_firewall_block(self, domain: str) -> dict:
        normalized = self._normalize_domain(domain)
        outputs = []
        for rule_name in (
            self._domain_firewall_rule_name(normalized),
            self._domain_firewall_rule_name_for_family(normalized, "IPv4"),
            self._domain_firewall_rule_name_for_family(normalized, "IPv6"),
        ):
            outputs.append(self._run_netsh([
                "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ]))
        ok = any(result.get("ok") for result in outputs)
        errors = [result.get("error", "") for result in outputs if result.get("error")]
        return {"ok": ok, "error": "\n".join(errors), "results": outputs}

    def set_safe_mode(self, enabled: bool):
        """Enable or disable safe mode"""
        self.safe_mode = bool(enabled)

    def block_app(self, process: str, executable_path: str = "") -> dict:
        """Block a process/application"""
        if not process:
            return {"ok": False, "error": "Process name is required."}

        firewall_result = self._add_firewall_block(process, executable_path)
        if process not in self.blocked_apps:
            self.blocked_apps.append(process)
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    'INSERT OR REPLACE INTO blocked_apps (process, executable_path, added_date) VALUES (?, ?, datetime("now"))',
                    (process, executable_path)
                )
        except Exception as e:
            print(f"Error blocking app: {e}")
            return {"ok": False, "error": str(e), "firewall": firewall_result}
        return {"ok": firewall_result.get("ok", False), "process": process, "firewall": firewall_result}

    def unblock_app(self, process: str) -> dict:
        """Unblock a process/application"""
        firewall_result = self._delete_firewall_block(process)
        if process in self.blocked_apps:
            self.blocked_apps.remove(process)
            try:
                with sqlite3.connect(self.db.db_path) as conn:
                    conn.execute('DELETE FROM blocked_apps WHERE process = ?', (process,))
            except Exception as e:
                print(f"Error unblocking app: {e}")
                return {"ok": False, "error": str(e), "firewall": firewall_result}
        return {"ok": firewall_result.get("ok", False), "process": process, "firewall": firewall_result}
    
    def is_blocked_domain(self, domain: str) -> bool:
        """Check if domain is blocked"""
        normalized = self._normalize_domain(domain)
        if not normalized:
            return False
        blocked = {self._normalize_domain(d) for d in self.blocked_domains}
        if normalized in blocked:
            return True
        if normalized.startswith("www.") and normalized[4:] in blocked:
            return True
        return f"www.{normalized}" in blocked
    
    def block_domain(self, domain: str) -> dict:
        """Block a domain"""
        normalized = self._normalize_domain(domain)
        if not normalized:
            return {"ok": False, "error": "A valid domain or URL is required."}

        # Resolve before touching hosts so DNS lookups are not redirected to loopback.
        resolved_ips = self._resolve_domain_ips(normalized)
        firewall_result = self._add_domain_firewall_block(normalized, resolved_ips)

        hosts_result = self._sync_hosts_block(normalized, remove=False)
        if not hosts_result.get("ok"):
            if firewall_result.get("ok"):
                self._delete_domain_firewall_block(normalized)
            return hosts_result

        # Hosts-file blocking is the primary enforcement path here, so do not fail the
        # whole action if firewall enrichment could not be added for this domain.
        if not firewall_result.get("ok"):
            hosts_result["warning"] = firewall_result.get(
                "error",
                "Hosts-file block succeeded, but the Windows Firewall domain rule could not be created.",
            )

        if normalized not in self.blocked_domains:
            self.blocked_domains.append(normalized)
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    'INSERT OR REPLACE INTO blocked_domains (domain, added_date) VALUES (?, datetime("now"))',
                    (normalized,)
                )
        except Exception as e:
            print(f"Error blocking domain: {e}")
            return {"ok": False, "error": str(e), "hosts": hosts_result, "firewall": firewall_result}
        return {"ok": True, "domain": normalized, "hosts": hosts_result, "firewall": firewall_result}
    
    def unblock_domain(self, domain: str) -> dict:
        """Unblock a domain"""
        normalized = self._normalize_domain(domain)
        if not normalized:
            return {"ok": False, "error": "A valid domain or URL is required."}

        hosts_result = self._sync_hosts_block(normalized, remove=True)
        if not hosts_result.get("ok"):
            return hosts_result

        firewall_result = self._delete_domain_firewall_block(normalized)

        if normalized in self.blocked_domains:
            self.blocked_domains.remove(normalized)
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute('DELETE FROM blocked_domains WHERE domain = ?', (normalized,))
        except Exception as e:
            print(f"Error unblocking domain: {e}")
            return {"ok": False, "error": str(e), "hosts": hosts_result, "firewall": firewall_result}
        return {"ok": True, "domain": normalized, "hosts": hosts_result, "firewall": firewall_result}
