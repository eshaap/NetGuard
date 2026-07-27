"""
port_checker.py
Heuristic detection based on destination port numbers.

Some ports are almost exclusively used by malware, attack frameworks,
or hacking tools. If any application on the system connects to one of
these ports, that connection is flagged as suspicious regardless of
what the IP reputation databases say.

This works WITHOUT any external API — it is pure local logic.
"""

# ── Known suspicious / malware-associated ports ───────────────────────
# Each entry: port → (short label, reason)
SUSPICIOUS_PORTS: dict[int, tuple[str, str]] = {
    # Attack frameworks
    4444:  ("Metasploit",        "Default Metasploit reverse-shell listener"),
    4445:  ("Metasploit alt",    "Alternate Metasploit shell port"),
    5555:  ("Android ADB/RAT",   "Android Debug Bridge or Remote Access Trojan"),
    5554:  ("Android ADB",       "Android Debug Bridge"),

    # Hacker culture / script-kiddie tools
    1337:  ("Leet port",         "Common hacker/backdoor port"),
    31337: ("Elite backdoor",    "Classic Back Orifice / backdoor port"),
    12345: ("NetBus RAT",        "NetBus Remote Access Trojan"),
    54321: ("Back Orifice 2000", "Back Orifice 2000 RAT"),

    # IRC-based botnets
    6667:  ("IRC botnet",        "Unencrypted IRC — used by botnets for C2"),
    6668:  ("IRC botnet",        "IRC botnet command-and-control channel"),
    6669:  ("IRC botnet",        "IRC botnet command-and-control channel"),
    7000:  ("IRC botnet alt",    "Alternate IRC botnet port"),

    # Remote access / RATs
    1099:  ("Java RMI",          "Java Remote Method Invocation — exploited by RATs"),
    2222:  ("RAT / alt SSH",     "Common RAT or non-standard SSH port"),
    3700:  ("RAT",               "Known RAT communication port"),
    9999:  ("RAT / backdoor",    "Common backdoor / RAT port"),
    8888:  ("RAT / C2",          "Common malware C2 port"),

    # Coinminer / cryptojacking
    3333:  ("Coinminer pool",    "Monero/crypto mining pool port"),
    4444:  ("Coinminer pool",    "Crypto mining pool (also Metasploit)"),
    5000:  ("Coinminer pool",    "Crypto mining pool port"),
    14444: ("Coinminer pool",    "Monero mining pool port"),
    45700: ("Coinminer pool",    "Crypto mining pool port"),

    # TOR / anonymization
    9001:  ("TOR relay",         "TOR network relay port"),
    9030:  ("TOR directory",     "TOR directory authority port"),
    9050:  ("TOR SOCKS",         "TOR SOCKS proxy — traffic anonymization"),
    9051:  ("TOR control",       "TOR control port"),

    # Notorious malware families
    1234:  ("Sub7 / misc RAT",   "Sub7 RAT and various malware"),
    5900:  ("VNC",               "VNC remote desktop — often exploited"),
    65000: ("Malware C2",        "High port used by various malware families"),
    65535: ("Malware C2",        "Maximum port — used by some malware"),
}

# Ports that are suspicious ONLY if used by unexpected processes.
# These are legitimate services that malware also abuses.
CONTEXT_SUSPICIOUS: dict[int, str] = {
    23:   "Telnet — unencrypted, obsolete, often used by IoT malware",
    25:   "SMTP — if non-mail app uses this, could be spam bot",
    445:  "SMB — EternalBlue/WannaCry exploit port",
    135:  "Windows RPC — commonly exploited",
    139:  "NetBIOS — legacy, commonly exploited",
    3389: "RDP — Remote Desktop, brute-forced constantly",
}


def check_port(remote_port: int, process: str = "") -> dict:
    """
    Check a single port and return a result dict.

    Returns:
        {
            "suspicious": True/False,
            "port": int,
            "label": str,       # short name e.g. "Metasploit"
            "reason": str,      # explanation
            "severity": str,    # "high" or "medium"
            "risk_boost": int,  # how much to add to the IP risk score
        }
    """
    if remote_port in SUSPICIOUS_PORTS:
        label, reason = SUSPICIOUS_PORTS[remote_port]
        return {
            "suspicious": True,
            "port": remote_port,
            "label": label,
            "reason": reason,
            "severity": "high",
            "risk_boost": 4,    # adds 4 to the combined risk score
        }

    if remote_port in CONTEXT_SUSPICIOUS:
        reason = CONTEXT_SUSPICIOUS[remote_port]
        return {
            "suspicious": True,
            "port": remote_port,
            "label": f"Port {remote_port}",
            "reason": reason,
            "severity": "medium",
            "risk_boost": 2,
        }

    return {
        "suspicious": False,
        "port": remote_port,
        "label": "",
        "reason": "",
        "severity": "none",
        "risk_boost": 0,
    }


# Known P2P / torrent client process names (case-insensitive).
# These are flagged regardless of which port they use, because any external
# connection from a torrent client is intentional P2P file sharing.
KNOWN_P2P_PROCESSES: set[str] = {
    "utorrent.exe",
    "bittorrent.exe",
    "qbittorrent.exe",
    "transmission.exe",
    "transmission-qt.exe",
    "deluge.exe",
    "vuze.exe",
    "bitcomet.exe",
    "bitlord.exe",
    "frostwire.exe",
    "limewire.exe",
    "emule.exe",
    "shareaza.exe",
}


def check_connection(conn: dict) -> dict:
    """
    Convenience wrapper — pass a full connection dict from
    network_monitor.get_active_connections() and get back a port result.

    conn dict keys used:  remote_port, process
    """
    port = conn.get("remote_port") or 0
    process = (conn.get("process") or "").strip().lower()

    # Process-name detection: flag known torrent/P2P clients by name
    if process in KNOWN_P2P_PROCESSES:
        return {
            "suspicious": True,
            "port": port,
            "label": "P2P / Torrent client",
            "reason": f"{conn.get('process', process)} is a known torrent/P2P application — may violate network policies or expose the system to untrusted peers",
            "severity": "high",
            "risk_boost": 4,
        }

    return check_port(port, process)
