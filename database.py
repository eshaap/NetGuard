"""
database.py
SQLite database operations
"""

import sqlite3
import json
from datetime import datetime, timedelta

class Database:
    def __init__(self, db_path="data/netguard.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    type TEXT,
                    severity TEXT,
                    process TEXT,
                    ip TEXT,
                    domain TEXT,
                    message TEXT,
                    timestamp TEXT,
                    risk_score INTEGER,
                    action_taken TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS checked_ips (
                    ip TEXT PRIMARY KEY,
                    last_checked TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_domains (
                    domain TEXT PRIMARY KEY,
                    added_date TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_apps (
                    process TEXT PRIMARY KEY,
                    executable_path TEXT,
                    added_date TEXT
                )
            ''')
            cursor = conn.execute('PRAGMA table_info(blocked_apps)')
            columns = [row[1] for row in cursor.fetchall()]
            if 'executable_path' not in columns:
                conn.execute('ALTER TABLE blocked_apps ADD COLUMN executable_path TEXT')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    target TEXT,
                    timestamp TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_categories (
                    category TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 0,
                    last_applied TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS app_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process TEXT NOT NULL,
                    executable_path TEXT,
                    start_minute INTEGER NOT NULL,
                    end_minute INTEGER NOT NULL,
                    days TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    currently_blocked INTEGER DEFAULT 0,
                    created TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS parental_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    target TEXT,
                    timestamp TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS gemini_cache (
                    ip TEXT PRIMARY KEY,
                    explanation TEXT,
                    cached_at TEXT
                )
            ''')
    
    def save_alert(self, alert: dict):
        """Save alert to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO alerts 
                (id, type, severity, process, ip, domain, message, timestamp, risk_score, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['id'], alert['type'], alert['severity'], alert['process'],
                alert['ip'], alert['domain'], alert['message'], alert['timestamp'],
                alert['risk_score'], alert.get('action_taken', '')
            ))
    
    def recently_checked_port(self, ip: str, port: int, minutes: int = 30) -> bool:
        """Return True if a port alert for this ip:port was already raised recently.
        Uses an in-memory dict — no DB table needed since it resets on restart."""
        if not hasattr(self, "_port_alert_times"):
            self._port_alert_times = {}
        key = f"{ip}:{port}"
        cutoff = datetime.now() - timedelta(minutes=minutes)
        last = self._port_alert_times.get(key)
        if last and last > cutoff:
            return True
        self._port_alert_times[key] = datetime.now()
        return False

    def recently_checked(self, ip: str, minutes: int = 5) -> bool:
        """Check if IP was recently checked"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT last_checked FROM checked_ips WHERE ip = ?',
                (ip,)
            )
            result = cursor.fetchone()

            if result:
                last_checked = datetime.fromisoformat(result[0])
                if last_checked > cutoff:
                    return True
                conn.execute(
                    'INSERT OR REPLACE INTO checked_ips (ip, last_checked) VALUES (?, ?)',
                    (ip, datetime.now().isoformat())
                )
                return False
            else:
                conn.execute(
                    'INSERT OR REPLACE INTO checked_ips (ip, last_checked) VALUES (?, ?)',
                    (ip, datetime.now().isoformat())
                )
                return False

    def get_alerts(self, limit: int = 100):
        """Retrieve recent alerts from the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT id, type, severity, process, ip, domain, message, timestamp, risk_score, action_taken FROM alerts ORDER BY timestamp DESC LIMIT ?',
                (limit,)
            )
            rows = cursor.fetchall()
        return [
            {
                'id': row[0],
                'type': row[1],
                'severity': row[2],
                'process': row[3],
                'ip': row[4],
                'domain': row[5],
                'message': row[6],
                'timestamp': row[7],
                'risk_score': row[8],
                'action_taken': row[9],
            }
            for row in rows
        ]

    def log_action(self, action: str, target: str = ""):
        """Log a user or system action"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO logs (action, target, timestamp) VALUES (?, ?, ?)',
                (action, target, datetime.now().isoformat())
            )

    def get_logs(self, limit: int = 100):
        """Retrieve activity logs"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT action, target, timestamp FROM logs ORDER BY id DESC LIMIT ?',
                (limit,)
            )
            return [
                {'action': row[0], 'target': row[1], 'timestamp': row[2]}
                for row in cursor.fetchall()
            ]

    def log_parental_event(self, event_type: str, target: str = ""):
        """Record a parental-control event (block, schedule trigger, etc.)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO parental_events (event_type, target, timestamp) VALUES (?, ?, ?)',
                (event_type, target, datetime.now().isoformat())
            )

    def get_gemini_explanation(self, ip: str, max_age_days: int = 7):
        """Return cached Gemini explanation for an IP, or None if missing/stale."""
        if not ip:
            return None
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    'SELECT explanation, cached_at FROM gemini_cache WHERE ip = ?',
                    (ip.lower(),)
                ).fetchone()
            if not row:
                return None
            try:
                cached_at = datetime.fromisoformat(row[1])
            except Exception:
                return None
            if datetime.now() - cached_at > timedelta(days=max_age_days):
                return None
            return row[0]
        except Exception:
            return None

    def save_gemini_explanation(self, ip: str, explanation: str):
        """Persist a Gemini explanation for an IP so future sessions reuse it."""
        if not ip or not explanation:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'INSERT OR REPLACE INTO gemini_cache (ip, explanation, cached_at) '
                    'VALUES (?, ?, ?)',
                    (ip.lower(), explanation, datetime.now().isoformat())
                )
        except Exception:
            pass
