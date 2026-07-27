"""
frontend/main_window.py
NetGuard - Main PyQt5 Application Window
Modern split-theme UI: dark sidebar + light content area.
"""

import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from collections import deque

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QFrame, QTableWidget, QTableWidgetItem,
        QTabWidget, QStackedWidget, QSplitter, QListWidget, QListWidgetItem,
        QLineEdit, QMessageBox, QHeaderView, QScrollArea, QTextEdit, QFileDialog,
        QCheckBox, QProgressBar, QSizePolicy, QGridLayout, QComboBox,
        QSystemTrayIcon, QAction, QMenu
    )
    from PyQt5.QtCore import QItemSelectionModel, Qt, QTimer, QThread, pyqtSignal, QSize
    from PyQt5.QtGui import QColor, QFont, QIcon, QPalette, QBrush, QPainter, QPixmap
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    print("[FATAL] PyQt5 not installed. Run: pip install PyQt5")
    sys.exit(1)

try:
    import pyqtgraph as pg
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False
    print("[WARN] pyqtgraph not available, charts disabled")

API_BASE = "http://127.0.0.1:8765/api"

# ─── Responsive Scale ─────────────────────────────────────────────────
_SCALE: float = 1.0  # set by main() from screen geometry before any widget is created

# Global font-size multiplier. Bump this single number to make ALL text in the
# app bigger (or smaller). 1.0 = original size, 1.25 = 25% larger, etc.
_FONT_SCALE: float = 1.25

def s(px: int) -> int:
    """Scale a pixel value proportionally to the current screen resolution."""
    return max(1, int(px * _SCALE))

def fp(px: int) -> int:
    """Scale a FONT pixel value: screen scale × global font multiplier.
    All font sizes in the app should go through this so a single constant
    controls the project-wide text size."""
    return max(1, int(px * _SCALE * _FONT_SCALE))

# ─── Color Palette ────────────────────────────────────────────────────
COLORS = {
    # Light content area
    "bg_dark":      "#f1f5f9",   # main content background (light)
    "bg_panel":     "#f8fafc",   # secondary panel bg
    "bg_card":      "#ffffff",   # card background
    "border":       "#e2e8f0",   # light gray border

    # Text (light content area)
    "text_primary": "#0f172a",   # dark text
    "text_muted":   "#64748b",   # medium gray

    # Accents
    "accent_blue":  "#3b82f6",
    "accent_green": "#10b981",
    "accent_red":   "#ef4444",
    "accent_amber": "#f59e0b",

    # Risk colors
    "high_risk":    "#ef4444",
    "med_risk":     "#f59e0b",
    "low_risk":     "#10b981",

    # Dark sidebar
    "sidebar_bg":       "#0b1120",
    "sidebar_hover":    "#1a2440",
    "sidebar_active":   "#1e3a5f",
    "sidebar_accent":   "#3b82f6",
    "sidebar_text":     "#6b7a99",
    "sidebar_text_act": "#e2e8f0",
    "sidebar_logo":     "#60a5fa",

    # Header
    "header_bg":     "#ffffff",
    "header_border": "#e2e8f0",

    # Status badges
    "online_bg":    "#dcfce7",
    "online_text":  "#16a34a",
    "offline_bg":   "#fef2f2",
    "offline_text": "#dc2626",
    "warn_bg":      "#fef3c7",
    "warn_text":    "#d97706",
}

def _build_stylesheet() -> str:
    fs = lambda base: f"{fp(base)}px"
    return f"""
QMainWindow, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: 'Segoe UI', 'Arial', sans-serif;
    font-size: {fs(12)};
}}
QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    background: {COLORS['bg_panel']};
}}
QTabBar::tab {{
    background: {COLORS['bg_card']};
    color: {COLORS['text_muted']};
    padding: {fs(8)} {fs(20)};
    border: 1px solid {COLORS['border']};
    font-size: {fs(12)};
    font-weight: bold;
    letter-spacing: 1px;
}}
QTabBar::tab:selected {{
    background: {COLORS['bg_panel']};
    color: {COLORS['accent_blue']};
    border-bottom: 2px solid {COLORS['accent_blue']};
}}
QTableWidget {{
    background: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    gridline-color: {COLORS['border']};
    color: {COLORS['text_primary']};
    font-size: {fs(12)};
    selection-background-color: #eff6ff;
    alternate-background-color: {COLORS['bg_panel']};
}}
QTableWidget::item {{
    padding: {fs(6)};
    border-bottom: 1px solid {COLORS['border']};
    color: {COLORS['text_primary']};
}}
QTableWidget::item:selected {{
    background-color: {COLORS['accent_blue']};
    color: #ffffff;
}}
QHeaderView::section {{
    background: {COLORS['bg_panel']};
    color: {COLORS['text_muted']};
    padding: {fs(8)};
    border: none;
    border-bottom: 1px solid {COLORS['border']};
    font-size: {fs(11)};
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QPushButton {{
    background: {COLORS['bg_card']};
    color: {COLORS['accent_blue']};
    border: 1px solid {COLORS['border']};
    padding: {fs(6)} {fs(16)};
    font-size: {fs(11)};
    font-weight: bold;
    border-radius: {fs(6)};
    letter-spacing: 0.5px;
}}
QPushButton:hover {{
    background: #eff6ff;
    border-color: {COLORS['accent_blue']};
    color: {COLORS['accent_blue']};
}}
QPushButton.danger {{
    color: {COLORS['accent_red']};
    border-color: {COLORS['accent_red']};
}}
QPushButton.danger:hover {{
    background: #fef2f2;
    color: {COLORS['accent_red']};
}}
QPushButton.success {{
    color: {COLORS['accent_green']};
    border-color: {COLORS['accent_green']};
}}
QLineEdit {{
    background: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    color: {COLORS['text_primary']};
    padding: {fs(7)} {fs(12)};
    font-size: {fs(12)};
    border-radius: {fs(6)};
}}
QLineEdit:focus {{
    border-color: {COLORS['accent_blue']};
}}
QTextEdit {{
    background: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    color: {COLORS['text_primary']};
    font-size: {fs(12)};
    padding: {fs(8)};
    border-radius: {fs(6)};
}}
QScrollBar:vertical {{
    background: {COLORS['bg_panel']};
    width: {fs(6)};
    border-radius: {fs(3)};
}}
QScrollBar::handle:vertical {{
    background: #cbd5e1;
    border-radius: {fs(3)};
}}
QScrollBar::handle:vertical:hover {{
    background: #94a3b8;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QLabel {{
    color: {COLORS['text_primary']};
}}
QListWidget {{
    border: none;
    outline: none;
}}
QCheckBox {{
    color: {COLORS['text_primary']};
    spacing: {fs(8)};
}}
QCheckBox::indicator {{
    width: {fs(16)};
    height: {fs(16)};
    border: 2px solid {COLORS['border']};
    background: {COLORS['bg_card']};
    border-radius: {fs(3)};
}}
QCheckBox::indicator:checked {{
    background: {COLORS['accent_blue']};
    border-color: {COLORS['accent_blue']};
}}
"""

STYLESHEET = _build_stylesheet()


# ─── API Helper ──────────────────────────────────────────────────────

def api_get(endpoint: str) -> dict:
    try:
        url = f"{API_BASE}{endpoint}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def api_post(endpoint: str, data: dict, timeout: int = 5) -> dict:
    try:
        url = f"{API_BASE}{endpoint}"
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


# ─── Tray Icon Factory ───────────────────────────────────────────────

def _create_tray_icon(paused: bool = False) -> QIcon:
    """
    Build a 64×64 tray icon at runtime — no external .ico file needed.
    Blue circle + 'N' when monitoring; red tint when paused.
    """
    size = 64
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    bg_col     = QColor("#1e3a5f") if not paused else QColor("#3b0f0f")
    border_col = QColor("#3b82f6") if not paused else QColor("#ef4444")
    text_col   = QColor("#60a5fa") if not paused else QColor("#fca5a5")

    painter.setBrush(bg_col)
    painter.setPen(border_col)
    painter.drawEllipse(3, 3, size - 6, size - 6)

    painter.setPen(text_col)
    font = QFont("Arial", size // 3, QFont.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignCenter, "N")
    painter.end()
    return QIcon(pixmap)


# ─── Worker Thread ───────────────────────────────────────────────────

class DataFetcher(QThread):
    """Background thread that polls the API and emits data."""
    bandwidth_updated = pyqtSignal(dict)
    processes_updated = pyqtSignal(list)
    alerts_updated = pyqtSignal(list)
    stats_updated = pyqtSignal(dict)

    def run(self):
        self._running = True
        while self._running:
            try:
                bw = api_get("/bandwidth")
                if bw:
                    self.bandwidth_updated.emit(bw)

                procs = api_get("/processes")
                if isinstance(procs, list):
                    self.processes_updated.emit(procs)

                alerts = api_get("/alerts")
                if isinstance(alerts, list):
                    self.alerts_updated.emit(alerts)

                stats = api_get("/stats")
                if stats:
                    self.stats_updated.emit(stats)
            except Exception:
                pass

            self.msleep(1000)  # Poll every 1 second

    def stop(self):
        self._running = False


class _AIWorker(QThread):
    """Runs a single AI POST request off the UI thread (local LLM can take a few
    seconds). Emits done(dict)."""
    done = pyqtSignal(dict)

    def __init__(self, endpoint: str, payload: dict, timeout: int = 60):
        super().__init__()
        self._endpoint = endpoint
        self._payload = payload
        self._timeout = timeout

    def run(self):
        result = api_post(self._endpoint, self._payload, timeout=self._timeout)
        self.done.emit(result if isinstance(result, dict) else {"error": "no response"})


# ─── Stat Card Widget ────────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, title: str, value: str, color: str = COLORS['accent_blue']):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-left: 3px solid {color};
                border-radius: 8px;
                padding: 2px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(s(14), s(10), s(14), s(10))
        layout.setSpacing(s(4))

        self.title_lbl = QLabel(title.upper())
        self.title_lbl.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(10)}px; font-weight: 600; "
            f"letter-spacing: 1px; border: none; background: transparent;"
        )

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(
            f"color: {color}; font-size: {fp(22)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )

        layout.addWidget(self.title_lbl)
        layout.addWidget(self.value_lbl)

    def update_value(self, value: str):
        self.value_lbl.setText(value)


# ─── Alert Item Widget ───────────────────────────────────────────────

def severity_color(severity: str) -> str:
    return {
        "high": COLORS["high_risk"],
        "medium": COLORS["med_risk"],
        "low": COLORS["low_risk"],
    }.get(severity, COLORS["text_muted"])


# ─── Dashboard Tab ───────────────────────────────────────────────────

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self._bw_history_up = deque([0.0] * 60, maxlen=60)
        self._bw_history_down = deque([0.0] * 60, maxlen=60)
        self._daily_download_kb = 0.0
        self._daily_upload_kb = 0.0
        self._last_bandwidth_ts = None
        self._top_process_rows = []
        self._demo_alerts = [
            {
                "id": "demo_alert_001",
                "type": "malicious_ip",
                "severity": "high",
                "process": "svchost.exe",
                "ip": "192.168.1.1",
                "domain": "malicious-c2.ru",
                "message": "Backdoor.Win32.Agent detected",
                "timestamp": "2026-04-27 23:53:03",
                "risk_score": 9,
                "action_taken": "blocked",
            },
            {
                "id": "demo_alert_002",
                "type": "suspicious_domain",
                "severity": "medium",
                "process": "chrome.exe",
                "ip": "203.0.113.45",
                "domain": "Suspicious Domain Request",
                "message": "Suspicious Domain Request detected",
                "timestamp": "2026-04-27 23:51:33",
                "risk_score": 6,
                "action_taken": "monitored",
            },
            {
                "id": "demo_alert_003",
                "type": "malicious_ip",
                "severity": "high",
                "process": "unknown_pkg_92",
                "ip": "198.51.100.89",
                "domain": "Outbound Port Scanning",
                "message": "Outbound Port Scanning detected",
                "timestamp": "2026-04-27 23:49:33",
                "risk_score": 8,
                "action_taken": "terminated",
            },
        ]
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(f"background: {COLORS['bg_dark']};")
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 20, 24, 20)

        # ── Page Title ──
        title_lbl = QLabel("Network Overview")
        title_lbl.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(26)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        subtitle_lbl = QLabel("Real-time intelligence from your primary node.")
        subtitle_lbl.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(13)}px; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_lbl)
        layout.addWidget(subtitle_lbl)

        # ── Stat Cards: 2 rows of 4 ──
        self.card_download = StatCard("Download", "0.0 KB/s", COLORS["accent_blue"])
        self.card_upload = StatCard("Upload", "0.0 KB/s", COLORS["accent_blue"])
        self.card_alerts = StatCard("Active Alerts", "0", COLORS["accent_red"])
        self.card_connections = StatCard("Connections", "0", COLORS["text_muted"])
        self.card_blocked = StatCard("Restricted Apps", "0", COLORS["accent_blue"])
        self.card_adaptive = StatCard("High Usage Events", "0", COLORS["accent_blue"])
        self.card_daily_down = StatCard("Today Download", "0.0 MB", COLORS["accent_green"])
        self.card_daily_up = StatCard("Today Upload", "0.0 MB", COLORS["accent_blue"])

        stats_grid = QGridLayout()
        stats_grid.setSpacing(12)
        row1 = [self.card_download, self.card_upload, self.card_alerts, self.card_connections]
        row2 = [self.card_blocked, self.card_adaptive, self.card_daily_down, self.card_daily_up]
        for col, card in enumerate(row1):
            stats_grid.addWidget(card, 0, col)
        for col, card in enumerate(row2):
            stats_grid.addWidget(card, 1, col)
        layout.addLayout(stats_grid)

        # ── Bandwidth Chart Card ──
        chart_card = QFrame()
        chart_card.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        chart_card_layout = QVBoxLayout(chart_card)
        chart_card_layout.setContentsMargins(16, 12, 16, 12)
        chart_card_layout.setSpacing(8)

        chart_header = QHBoxLayout()

        chart_dot = QLabel("●")
        chart_dot.setStyleSheet(
            f"color: {COLORS['accent_green']}; font-size: {fp(10)}px; border: none; background: transparent;"
        )
        chart_label = QLabel(" BANDWIDTH MONITOR")
        chart_label.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(11)}px; font-weight: bold; "
            f"letter-spacing: 1px; border: none; background: transparent;"
        )
        chart_header.addWidget(chart_dot)
        chart_header.addWidget(chart_label)
        chart_header.addStretch()

        # Inline legend
        for line_color, legend_text in [(COLORS['accent_green'], "Download"), (COLORS['accent_blue'], "Upload")]:
            line_lbl = QLabel("—")
            line_lbl.setStyleSheet(
                f"color: {line_color}; font-size: {fp(14)}px; border: none; background: transparent;"
            )
            text_lbl = QLabel(legend_text)
            text_lbl.setStyleSheet(
                f"color: {COLORS['text_muted']}; font-size: {fp(10)}px; border: none; background: transparent;"
            )
            chart_header.addWidget(line_lbl)
            chart_header.addWidget(text_lbl)
            chart_header.addSpacing(8)

        chart_header.addStretch()
        chart_subtitle = QLabel("Real-time throughput analytics (last 60s)")
        chart_subtitle.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(9)}px; border: none; background: transparent;"
        )
        chart_header.addWidget(chart_subtitle)
        chart_card_layout.addLayout(chart_header)

        if PYQTGRAPH_AVAILABLE:
            pg.setConfigOption('background', COLORS['bg_card'])
            pg.setConfigOption('foreground', COLORS['text_muted'])
            self.chart = pg.PlotWidget()
            self.chart.setMinimumHeight(s(200))
            self.chart.showGrid(x=True, y=True, alpha=0.15)
            self.chart.setLabel('left', 'KB/s')
            self.chart.setLabel('bottom', 'seconds ago')
            self.chart.setXRange(-60, 0)
            self.chart.addLegend()
            self.plot_down = self.chart.plot(pen=pg.mkPen(COLORS['accent_green'], width=2), name='Download')
            self.plot_up = self.chart.plot(pen=pg.mkPen(COLORS['accent_blue'], width=2), name='Upload')
            chart_card_layout.addWidget(self.chart)
        else:
            self.chart_fallback = QTextEdit()
            self.chart_fallback.setMaximumHeight(s(150))
            self.chart_fallback.setReadOnly(True)
            self.chart_fallback.setPlaceholderText("Bandwidth chart (install pyqtgraph for visual chart)")
            chart_card_layout.addWidget(self.chart_fallback)
            self.chart = None

        layout.addWidget(chart_card)

        # ── Top Data Consuming Apps Card ──
        top_card = QFrame()
        top_card.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        top_card_layout = QVBoxLayout(top_card)
        top_card_layout.setContentsMargins(16, 12, 16, 12)
        top_card_layout.setSpacing(8)

        top_header = QHBoxLayout()
        top_label = QLabel("TOP DATA CONSUMING APPS")
        top_label.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(11)}px; font-weight: bold; "
            f"letter-spacing: 1px; border: none; background: transparent;"
        )
        top_header.addWidget(top_label)
        top_header.addStretch()
        top_note = QLabel("Top 5 apps by total bandwidth")
        top_note.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(9)}px; border: none; background: transparent;"
        )
        top_header.addWidget(top_note)
        top_card_layout.addLayout(top_header)

        self.top_apps_table = QTableWidget()
        self.top_apps_table.setColumnCount(5)
        self.top_apps_table.setHorizontalHeaderLabels(["#", "PROCESS", "UPLOAD", "DOWNLOAD", "TOTAL"])
        self.top_apps_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.top_apps_table.setColumnWidth(0, s(36))
        self.top_apps_table.setColumnWidth(2, s(80))
        self.top_apps_table.setColumnWidth(3, s(90))
        self.top_apps_table.setColumnWidth(4, s(80))
        self.top_apps_table.setMinimumHeight(s(220))
        self.top_apps_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.top_apps_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.top_apps_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.top_apps_table.setStyleSheet("border: none; border-radius: 0px;")
        top_card_layout.addWidget(self.top_apps_table)

        layout.addWidget(top_card)

        # ── Recent Security Events Card ──
        events_card = QFrame()
        events_card.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        events_card_layout = QVBoxLayout(events_card)
        events_card_layout.setContentsMargins(16, 12, 16, 12)
        events_card_layout.setSpacing(8)

        events_header = QHBoxLayout()

        events_dot = QLabel("●")
        events_dot.setStyleSheet(
            f"color: {COLORS['accent_red']}; font-size: {fp(10)}px; border: none; background: transparent;"
        )
        events_label = QLabel(" RECENT SECURITY EVENTS")
        events_label.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(11)}px; font-weight: bold; "
            f"letter-spacing: 1px; border: none; background: transparent;"
        )
        events_subtitle = QLabel("   last 24 hours of firewall activity")
        events_subtitle.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(9)}px; border: none; background: transparent;"
        )
        events_header.addWidget(events_dot)
        events_header.addWidget(events_label)
        events_header.addWidget(events_subtitle)
        events_header.addStretch()

        demo_toggle_btn = QPushButton()
        demo_toggle_btn.setCheckable(True)
        demo_toggle_btn.setChecked(True)
        demo_toggle_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {COLORS['text_muted']};
                border: 1px solid {COLORS['border']};
                padding: 5px 12px;
                font-size: {fp(10)}px;
                font-weight: bold;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: {COLORS['bg_panel']};
                color: {COLORS['accent_blue']};
                border-color: {COLORS['accent_blue']};
            }}
            QPushButton:checked {{
                background: #eff6ff;
                color: {COLORS['accent_blue']};
                border-color: {COLORS['accent_blue']};
            }}
        """)
        demo_toggle_btn.clicked.connect(self._toggle_demo_alerts)
        self.demo_toggle_btn = demo_toggle_btn
        self._set_demo_toggle_state(True)
        events_header.addWidget(demo_toggle_btn)

        export_btn = QPushButton("EXPORT LOGS")
        export_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {COLORS['text_muted']};
                border: 1px solid {COLORS['border']};
                padding: 5px 12px;
                font-size: {fp(10)}px;
                font-weight: bold;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: {COLORS['bg_panel']};
                color: {COLORS['accent_blue']};
                border-color: {COLORS['accent_blue']};
            }}
        """)
        export_btn.clicked.connect(self._export_logs)
        events_header.addWidget(export_btn)

        events_card_layout.addLayout(events_header)

        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(["TIME", "LEVEL", "PROCESS", "DETAIL", "ACTION"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.alerts_table.setMinimumHeight(s(220))
        self.alerts_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.alerts_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.alerts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alerts_table.setStyleSheet("border: none; border-radius: 0px;")
        events_card_layout.addWidget(self.alerts_table)

        # Use a QLabel instead of QTextEdit so it never shows an inner scrollbar —
        # it grows with its content and the page-level scroll handles overflow.
        self.adaptive_status = QLabel("High usage status will appear here.")
        self.adaptive_status.setWordWrap(True)
        self.adaptive_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.adaptive_status.setStyleSheet(f"""
            QLabel {{
                background: {COLORS['bg_panel']};
                border: none;
                border-top: 1px solid {COLORS['border']};
                color: {COLORS['text_muted']};
                font-size: {fp(11)}px;
                padding: 8px 12px;
                border-radius: 0px;
            }}
        """)
        events_card_layout.addWidget(self.adaptive_status)

        layout.addWidget(events_card)

        self._sync_demo_toggle_state()

    def update_bandwidth(self, data: dict):
        up = data.get("upload_kbps", 0)
        down = data.get("download_kbps", 0)
        now = time.time()
        if self._last_bandwidth_ts is not None:
            elapsed = max(0.0, now - self._last_bandwidth_ts)
            self._daily_upload_kb += max(0.0, float(up)) * elapsed
            self._daily_download_kb += max(0.0, float(down)) * elapsed
        self._last_bandwidth_ts = now
        self._bw_history_up.append(up)
        self._bw_history_down.append(down)

        self.card_upload.update_value(f"{up:.1f} KB/s")
        self.card_download.update_value(f"{down:.1f} KB/s")
        self.card_daily_up.update_value(f"{self._daily_upload_kb / 1024:.1f} MB")
        self.card_daily_down.update_value(f"{self._daily_download_kb / 1024:.1f} MB")

        if PYQTGRAPH_AVAILABLE and self.chart:
            x = list(range(-59, 1))
            self.plot_up.setData(x, list(self._bw_history_up))
            self.plot_down.setData(x, list(self._bw_history_down))
        else:
            bar_up = "▓" * min(int(up / 10), 30)
            bar_down = "▓" * min(int(down / 10), 30)
            self.chart_fallback.setText(f"↑ {up:.1f} KB/s  {bar_up}\n↓ {down:.1f} KB/s  {bar_down}")

    def update_stats(self, stats: dict):
        self.card_alerts.update_value(str(stats.get("total_alerts", 0)))
        self.card_connections.update_value(str(stats.get("active_connections", 0)))
        self.card_blocked.update_value(str(stats.get("blocked_apps", 0)))
        adaptive = api_get("/adaptive/status")
        if isinstance(adaptive, dict):
            recent = adaptive.get("recent_actions", []) or []
            blocked = adaptive.get("blocked_processes", []) or []
            self.card_adaptive.update_value(str(len(recent)))
            lines = [
                f"Enabled: {adaptive.get('enabled', False)}",
                f"Threshold: {adaptive.get('threshold_kbps', 0)} KB/s",
                f"Auto block: {adaptive.get('auto_block', False)}",
                f"Cooldown: {adaptive.get('cooldown_seconds', 0)} s",
                f"Blocked processes: {len(blocked)}",
            ]
            if not adaptive.get("auto_block", False):
                lines.append("Mode: alerts only, no automatic blocking")
            if recent:
                lines.append("Recent hits:")
                for action in recent[:5]:
                    lines.append(
                        f"- {action.get('process', 'unknown')} "
                        f"up {action.get('upload_kbps', 0)} down {action.get('download_kbps', 0)} "
                        f"total {action.get('total_kbps', 0)} KB/s -> {action.get('action_taken', 'alert')}"
                    )
            else:
                lines.append("Recent hits: none yet")
            self.adaptive_status.setText("\n".join(lines))

    def update_top_apps(self, procs: list):
        rows = []
        for proc in procs or []:
            name = proc.get("process", "unknown")
            up = float(proc.get("upload_kbps", 0) or 0)
            down = float(proc.get("download_kbps", 0) or 0)
            total = up + down
            rows.append((name, up, down, total))

        rows.sort(key=lambda item: item[3], reverse=True)
        self._top_process_rows = rows[:5]

        self.top_apps_table.setRowCount(0)
        if not self._top_process_rows:
            self.top_apps_table.setRowCount(1)
            self.top_apps_table.setItem(0, 0, QTableWidgetItem("-"))
            self.top_apps_table.setItem(0, 1, QTableWidgetItem("No recent usage yet"))
            self.top_apps_table.setItem(0, 2, QTableWidgetItem("-"))
            self.top_apps_table.setItem(0, 3, QTableWidgetItem("-"))
            self.top_apps_table.setItem(0, 4, QTableWidgetItem("-"))
            return

        for idx, (name, up, down, total) in enumerate(self._top_process_rows):
            row = self.top_apps_table.rowCount()
            self.top_apps_table.insertRow(row)
            num_item = QTableWidgetItem(str(idx + 1))
            num_item.setTextAlignment(Qt.AlignCenter)
            self.top_apps_table.setItem(row, 0, num_item)
            self.top_apps_table.setItem(row, 1, QTableWidgetItem(name))
            self.top_apps_table.setItem(row, 2, QTableWidgetItem(f"{up:.1f} KB/s"))
            self.top_apps_table.setItem(row, 3, QTableWidgetItem(f"{down:.1f} KB/s"))
            self.top_apps_table.setItem(row, 4, QTableWidgetItem(f"{total:.1f} KB/s"))

    def update_alerts(self, alerts: list):
        combined = list(alerts)
        existing_ids = {alert.get("id") for alert in combined}
        # Use the local toggle state. The previous version re-hit
        # /alerts/demo-status synchronously on every refresh, and any transient
        # network blip would drop demos from the table.
        show_demo = bool(self.demo_toggle_btn.isChecked()) if hasattr(self, "demo_toggle_btn") else False
        if show_demo:
            for demo_alert in self._demo_alerts:
                if demo_alert["id"] not in existing_ids:
                    combined.append(demo_alert)

        self.alerts_table.setRowCount(0)
        for alert in combined[:10]:
            row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row)

            ts = alert.get("timestamp", "")[:19].replace("T", " ")
            sev = alert.get("severity", "low").upper()
            proc = alert.get("process", "unknown")
            msg = alert.get("message", "")
            action = alert.get("action_taken", "-")

            if alert.get("type") == "packet_malicious_ip":
                msg = "Suspicious network activity detected"
            elif alert.get("type") == "bandwidth_threshold":
                msg = "High internet usage detected"
            elif alert.get("type") == "malicious_ip":
                msg = "Suspicious internet activity detected"

            self.alerts_table.setItem(row, 0, QTableWidgetItem(ts))
            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(QColor(severity_color(alert.get("severity", "low"))))
            self.alerts_table.setItem(row, 1, sev_item)
            self.alerts_table.setItem(row, 2, QTableWidgetItem(proc))
            self.alerts_table.setItem(row, 3, QTableWidgetItem(msg))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(action))

    def _set_demo_toggle_state(self, show_demo: bool):
        self.demo_toggle_btn.blockSignals(True)
        self.demo_toggle_btn.setChecked(show_demo)
        self.demo_toggle_btn.setText("HIDE DEMO" if show_demo else "SHOW DEMO")
        self.demo_toggle_btn.blockSignals(False)

    def _sync_demo_toggle_state(self):
        result = api_get("/alerts/demo-status")
        if isinstance(result, dict) and "show_demo_alerts" in result:
            self._set_demo_toggle_state(bool(result["show_demo_alerts"]))

    def _toggle_demo_alerts(self, checked: bool):
        """Toggle demo alerts visibility."""
        try:
            result = api_post("/alerts/toggle-demo", {"show_demo": checked})
            if result and "show_demo_alerts" in result:
                show_demo = bool(result["show_demo_alerts"])
                self._set_demo_toggle_state(show_demo)
                alerts = api_get("/alerts")
                if isinstance(alerts, list):
                    self.update_alerts(alerts)
            else:
                self._sync_demo_toggle_state()
                QMessageBox.warning(self, "Demo Toggle Failed", "Could not update demo alert visibility.")
        except Exception as e:
            self._sync_demo_toggle_state()
            QMessageBox.warning(self, "Demo Toggle Failed", f"Error toggling demo alerts:\n\n{e}")

    def _export_logs(self):
        """Export backend logs to a CSV file chosen by the user."""
        logs = api_get("/logs")
        if not isinstance(logs, list) or not logs:
            QMessageBox.information(self, "Export Logs", "No logs are available to export yet.")
            return

        default_name = f"netguard-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Logs",
            default_name,
            "CSV Files (*.csv);;All Files (*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write("timestamp,action,target\n")
                for log in logs:
                    timestamp = str(log.get("timestamp", "")).replace('"', '""')
                    action = str(log.get("action", "")).replace('"', '""')
                    target = str(log.get("target", "")).replace('"', '""')
                    f.write(f'"{timestamp}","{action}","{target}"\n')
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Could not export logs:\n\n{e}")
            return

        QMessageBox.information(self, "Export Complete", f"Logs exported to:\n{file_path}")


# ─── Processes Tab ───────────────────────────────────────────────────

class ProcessesTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # Page title
        title_lbl = QLabel("Processes")
        title_lbl.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(26)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_lbl)

        # Search bar
        search_layout = QHBoxLayout()
        search_lbl = QLabel("FILTER:")
        search_lbl.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: {fp(11)}px; border: none; background: transparent;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by process name...")
        self.search_input.textChanged.connect(self._filter_table)
        search_layout.addWidget(search_lbl)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)

        # Process table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["PROCESS", "PID", "EST. UPLOAD", "EST. DOWNLOAD", "CONNECTIONS", "STATUS"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self.table)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.btn_block = QPushButton("⛔  BLOCK SELECTED")
        self.btn_block.setStyleSheet(
            f"color: {COLORS['accent_red']}; border-color: {COLORS['accent_red']};"
        )
        self.btn_block.clicked.connect(self._block_selected)

        self.btn_unblock = QPushButton("✓  UNBLOCK SELECTED")
        self.btn_unblock.setStyleSheet(
            f"color: {COLORS['accent_green']}; border-color: {COLORS['accent_green']};"
        )
        self.btn_unblock.clicked.connect(self._unblock_selected)

        btn_layout.addWidget(self.btn_block)
        btn_layout.addWidget(self.btn_unblock)
        btn_layout.addStretch()

        self.mode_toggle = QCheckBox("Accurate Mode (Windows Only)")
        self.mode_toggle.setChecked(False)
        self.mode_toggle.stateChanged.connect(self._toggle_mode)
        btn_layout.addWidget(self.mode_toggle)

        info_lbl = QLabel("Double-click a process for details")
        info_lbl.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(11)}px; border: none; background: transparent;"
        )
        btn_layout.addWidget(info_lbl)
        layout.addLayout(btn_layout)

        # ── Bandwidth Caps Card ──
        caps_card = QFrame()
        caps_card.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        caps_card_layout = QVBoxLayout(caps_card)
        caps_card_layout.setContentsMargins(16, 12, 16, 12)
        caps_card_layout.setSpacing(8)

        caps_header = QHBoxLayout()
        caps_title = QLabel("BANDWIDTH CAPS")
        caps_title.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(11)}px; font-weight: bold; "
            f"letter-spacing: 1px; border: none; background: transparent;"
        )
        caps_subtitle = QLabel("Alert or block when a process exceeds its limit")
        caps_subtitle.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(9)}px; border: none; background: transparent;"
        )
        caps_header.addWidget(caps_title)
        caps_header.addSpacing(10)
        caps_header.addWidget(caps_subtitle)
        caps_header.addStretch()

        caps_refresh_btn = QPushButton("↻")
        caps_refresh_btn.setFixedSize(fp(26), fp(26))
        caps_refresh_btn.setToolTip("Refresh caps")
        caps_refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                color: {COLORS['text_muted']};
                font-size: {fp(13)}px;
                padding: 0px;
            }}
            QPushButton:hover {{ background: {COLORS['bg_dark']}; color: {COLORS['accent_blue']}; }}
        """)
        caps_refresh_btn.clicked.connect(self._refresh_caps)
        caps_header.addWidget(caps_refresh_btn)
        caps_card_layout.addLayout(caps_header)

        # Add-cap form row
        add_row = QHBoxLayout()
        add_row.setSpacing(6)

        self.cap_process_input = QLineEdit()
        self.cap_process_input.setPlaceholderText("Process name (e.g. chrome.exe)")
        self.cap_process_input.setFixedHeight(fp(28))

        self.cap_limit_input = QLineEdit()
        self.cap_limit_input.setPlaceholderText("Limit KB/s")
        self.cap_limit_input.setFixedWidth(fp(90))
        self.cap_limit_input.setFixedHeight(fp(28))

        self.cap_action_combo = QComboBox()
        self.cap_action_combo.addItem("Alert only", "alert")
        self.cap_action_combo.addItem("Auto-block", "block")
        self.cap_action_combo.setFixedHeight(fp(28))
        self.cap_action_combo.setStyleSheet(f"""
            QComboBox {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                color: {COLORS['text_primary']};
                padding: 2px 8px;
                border-radius: 6px;
                font-size: {fp(11)}px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 18px;
            }}
            QComboBox QAbstractItemView {{
                background: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 4px;
                outline: none;
            }}
            QComboBox QAbstractItemView::item {{
                background: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                padding: 6px 10px;
                min-height: 22px;
                border-radius: 4px;
            }}
            QComboBox QAbstractItemView::item:hover {{
                background: #eff6ff;
                color: {COLORS['accent_blue']};
            }}
            QComboBox QAbstractItemView::item:selected {{
                background: #eff6ff;
                color: {COLORS['accent_blue']};
            }}
        """)

        add_cap_btn = QPushButton("+ ADD CAP")
        add_cap_btn.setFixedHeight(fp(28))
        add_cap_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['accent_blue']};
                color: #ffffff;
                border: none;
                border-radius: 6px;
                font-size: {fp(11)}px;
                font-weight: bold;
                padding: 0px 12px;
            }}
            QPushButton:hover {{ background: #2563eb; }}
        """)
        add_cap_btn.clicked.connect(self._add_cap)

        add_row.addWidget(self.cap_process_input)
        add_row.addWidget(self.cap_limit_input)
        add_row.addWidget(self.cap_action_combo)
        add_row.addWidget(add_cap_btn)
        caps_card_layout.addLayout(add_row)

        # Caps table
        self.caps_table = QTableWidget()
        self.caps_table.setColumnCount(4)
        self.caps_table.setHorizontalHeaderLabels(["PROCESS", "LIMIT (KB/s)", "ACTION", "REMOVE"])
        self.caps_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.caps_table.setColumnWidth(1, 110)
        self.caps_table.setColumnWidth(2, 90)
        self.caps_table.setColumnWidth(3, 80)
        self.caps_table.setMaximumHeight(140)
        self.caps_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.caps_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.caps_table.setStyleSheet("border: none; border-radius: 0px;")
        caps_card_layout.addWidget(self.caps_table)

        layout.addWidget(caps_card)

        self._all_data = []
        self._selected_pid = None
        self._sync_mode()
        self._refresh_caps()

    def _refresh_caps(self):
        """Fetch caps from the backend and repopulate the caps table."""
        caps = api_get("/caps")
        if not isinstance(caps, list):
            return
        self.caps_table.setRowCount(0)
        for cap in caps:
            row = self.caps_table.rowCount()
            self.caps_table.insertRow(row)
            self.caps_table.setItem(row, 0, QTableWidgetItem(cap.get("process", "")))
            self.caps_table.setItem(row, 1, QTableWidgetItem(f"{cap.get('cap_kbps', 0):.0f}"))
            action = cap.get("action", "alert")
            action_item = QTableWidgetItem("Auto-block" if action == "block" else "Alert only")
            action_item.setForeground(
                QColor(COLORS["accent_red"]) if action == "block" else QColor(COLORS["accent_amber"])
            )
            self.caps_table.setItem(row, 2, action_item)

            remove_btn = QPushButton("✕ Remove")
            remove_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {COLORS['accent_red']};
                    border: 1px solid {COLORS['accent_red']};
                    border-radius: 4px;
                    font-size: {fp(10)}px;
                    padding: 2px 6px;
                }}
                QPushButton:hover {{ background: #fef2f2; }}
            """)
            process_name = cap.get("process", "")
            remove_btn.clicked.connect(lambda _, p=process_name: self._remove_cap(p))
            self.caps_table.setCellWidget(row, 3, remove_btn)

    def _add_cap(self):
        """Read the form inputs and POST a new cap to the backend."""
        process = self.cap_process_input.text().strip()
        limit_text = self.cap_limit_input.text().strip()
        if not process:
            QMessageBox.warning(self, "Missing Process", "Enter a process name (e.g. chrome.exe).")
            return
        try:
            cap_kbps = float(limit_text)
            if cap_kbps <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Limit", "Enter a positive number for the KB/s limit.")
            return
        action = self.cap_action_combo.currentData()
        result = api_post("/caps", {"process": process, "cap_kbps": cap_kbps, "action": action})
        if result.get("ok"):
            self.cap_process_input.clear()
            self.cap_limit_input.clear()
            self._refresh_caps()
        else:
            QMessageBox.warning(self, "Failed", result.get("error", "Could not set cap."))

    def _remove_cap(self, process_name: str):
        """Delete a per-process cap via the backend API."""
        try:
            url = f"{API_BASE}/caps/{urllib.parse.quote(process_name)}"
            req = urllib.request.Request(url, method="DELETE")
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())
        except Exception as e:
            result = {"ok": False, "error": str(e)}
        if result.get("ok"):
            self._refresh_caps()
        else:
            QMessageBox.warning(self, "Failed", result.get("error", "Could not remove cap."))

    def update_processes(self, procs: list):
        self._all_data = procs
        query = self.search_input.text().strip().lower()
        if query:
            filtered = [p for p in self._all_data
                        if query in (p.get("process") or "").lower()
                        or query in str(p.get("pid", ""))]
            self._render(filtered)
        else:
            self._render(procs)

    def _render(self, procs: list):
        previous_pid = self._selected_pid
        rows = self.table.selectionModel().selectedRows()
        if rows:
            pid_item = self.table.item(rows[0].row(), 1)
            previous_pid = int(pid_item.text()) if pid_item and pid_item.text().isdigit() else previous_pid

        self.table.setRowCount(0)
        blocked_apps = api_get("/processes/blocked")
        blocked_set = set()
        if isinstance(blocked_apps, dict):
            for key in ("manual_blocks", "adaptive_blocks"):
                for entry in blocked_apps.get(key, []) or []:
                    if isinstance(entry, dict):
                        blocked_set.add((entry.get("process") or "").strip())
                    else:
                        blocked_set.add(str(entry).strip())
        elif isinstance(blocked_apps, list):
            for entry in blocked_apps:
                if isinstance(entry, dict):
                    blocked_set.add((entry.get("process") or "").strip())
                else:
                    blocked_set.add(str(entry).strip())
        row_to_restore = None

        for proc in procs:
            row = self.table.rowCount()
            self.table.insertRow(row)

            name = proc.get("process", "unknown")
            pid = str(proc.get("pid", "-"))
            up = f"{proc.get('upload_kbps', 0):.1f} KB/s"
            down = f"{proc.get('download_kbps', 0):.1f} KB/s"
            conns = str(proc.get("active_connections", 0))
            status = "BLOCKED" if name in blocked_set else "ALLOWED"

            self.table.setItem(row, 0, QTableWidgetItem(name))
            self.table.setItem(row, 1, QTableWidgetItem(pid))
            self.table.setItem(row, 2, QTableWidgetItem(up))
            self.table.setItem(row, 3, QTableWidgetItem(down))
            self.table.setItem(row, 4, QTableWidgetItem(conns))

            status_item = QTableWidgetItem(status)
            color = COLORS["accent_red"] if status == "BLOCKED" else COLORS["accent_green"]
            status_item.setForeground(QColor(color))
            self.table.setItem(row, 5, status_item)
            if previous_pid is not None and str(previous_pid) == pid:
                row_to_restore = row

        if row_to_restore is not None:
            self.table.selectRow(row_to_restore)
            self._selected_pid = previous_pid

    def _filter_table(self, text: str):
        query = text.strip().lower()
        if not query:
            self._render(self._all_data)
            return

        filtered = [p for p in self._all_data
                    if query in (p.get("process") or "").lower()
                    or query in str(p.get("pid", ""))]
        self._render(filtered)

    def _sync_mode(self):
        result = api_get("/processes/mode")
        accurate = isinstance(result, dict) and result.get("mode") == "accurate"
        # Reflect the real backend mode without re-triggering _toggle_mode.
        self.mode_toggle.blockSignals(True)
        self.mode_toggle.setChecked(accurate)
        self.mode_toggle.blockSignals(False)
        self._apply_mode_headers(accurate)

    def _apply_mode_headers(self, accurate: bool):
        """Headers tell the truth: plain labels for measured (accurate) data,
        'EST.' prefix when the numbers are estimated."""
        up = "UPLOAD" if accurate else "EST. UPLOAD"
        down = "DOWNLOAD" if accurate else "EST. DOWNLOAD"
        self.table.setHorizontalHeaderLabels(
            ["PROCESS", "PID", up, down, "CONNECTIONS", "STATUS"]
        )

    def _toggle_mode(self, state: int):
        mode = "accurate" if state else "estimation"
        result = api_post("/processes/mode", {"mode": mode})
        if isinstance(result, dict) and result.get("ok"):
            self._sync_mode()
        else:
            self.mode_toggle.blockSignals(True)
            self.mode_toggle.setChecked(False)
            self.mode_toggle.blockSignals(False)
            self._apply_mode_headers(False)
            detail = result.get("error") if isinstance(result, dict) else None
            QMessageBox.warning(
                self,
                "Accurate Mode",
                "Accurate mode could not be enabled, so NetGuard stayed in "
                "estimation mode.\n\n"
                + (detail or "Run NetGuard as administrator to enable it."),
            )

    def _get_selected_process(self) -> dict:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return {}
        pid_item = self.table.item(rows[0].row(), 1)
        if not pid_item:
            return {}
        selected_pid = int(pid_item.text())
        self._selected_pid = selected_pid
        for proc in self._all_data:
            if proc.get("pid") == selected_pid:
                return proc
        return {"process": self.table.item(rows[0].row(), 0).text(), "pid": selected_pid}

    def _block_selected(self):
        proc = self._get_selected_process()
        if not proc:
            QMessageBox.warning(self, "No Process Selected", "Click a process row first, then choose Block Selected.")
            return
        name = proc.get("process", "")
        result = api_post("/processes/block", {"process": name, "exe": proc.get("exe", "")})
        if result.get("error"):
            QMessageBox.warning(self, "Backend Offline", f"Could not contact NetGuard backend:\n\n{result.get('error')}")
            return
        if result.get("ok"):
            QMessageBox.information(self, "Blocked", f"'{name}' has been blocked from internet access.")
        else:
            error = result.get("error") or result.get("firewall", {}).get("error") or "Firewall rule could not be created."
            QMessageBox.warning(self, "Block Failed", f"'{name}' was saved in NetGuard, but Windows Firewall blocking failed:\n\n{error}")
        self._render(self._all_data)

    def _unblock_selected(self):
        proc = self._get_selected_process()
        if not proc:
            QMessageBox.warning(self, "No Process Selected", "Click a process row first, then choose Unblock Selected.")
            return
        name = proc.get("process", "")
        result = api_post("/processes/unblock", {"process": name})
        if result.get("error"):
            QMessageBox.warning(self, "Backend Offline", f"Could not contact NetGuard backend:\n\n{result.get('error')}")
            return
        if result.get("ok"):
            QMessageBox.information(self, "Unblocked", f"'{name}' has been unblocked.")
        else:
            error = result.get("error") or result.get("firewall", {}).get("error") or "Firewall rule could not be removed."
            QMessageBox.warning(self, "Unblock Warning", f"'{name}' was removed from NetGuard, but Windows Firewall cleanup reported:\n\n{error}")
        self._render(self._all_data)

    def _on_double_click(self, index):
        row = index.row()
        name    = (self.table.item(row, 0) or QTableWidgetItem("")).text()
        pid     = (self.table.item(row, 1) or QTableWidgetItem("")).text()
        upload  = (self.table.item(row, 2) or QTableWidgetItem("")).text()
        download= (self.table.item(row, 3) or QTableWidgetItem("")).text()
        conns   = (self.table.item(row, 4) or QTableWidgetItem("")).text()
        status  = (self.table.item(row, 5) or QTableWidgetItem("")).text()

        details = (
            f"Process:      {name}\n"
            f"PID:          {pid}\n"
            f"Upload:       {upload}\n"
            f"Download:     {download}\n"
            f"Connections:  {conns}\n"
            f"Status:       {status}"
        )
        QMessageBox.information(self, f"Process Details — {name}", details)


# ─── Alerts Tab ──────────────────────────────────────────────────────

class AlertsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # Page title
        title_lbl = QLabel("Alerts")
        title_lbl.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(26)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_lbl)

        # Header
        header = QHBoxLayout()
        title = QLabel("THREAT ALERTS")
        title.setStyleSheet(
            f"color: {COLORS['accent_red']}; font-size: {fp(13)}px; font-weight: bold; "
            f"letter-spacing: 2px; border: none; background: transparent;"
        )
        self.alert_count = QLabel("0 alerts")
        self.alert_count.setStyleSheet(
            f"color: {COLORS['text_muted']}; border: none; background: transparent;"
        )
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.alert_count)
        layout.addLayout(header)

        # Alerts table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["TIME", "SEVERITY", "PROCESS", "IP / DOMAIN", "RISK", "MESSAGE", "ACTIONS"])
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Fixed)
        self.table.setColumnWidth(6, 200)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.clicked.connect(self._show_details)
        layout.addWidget(self.table)

        # AI Explanation box
        ai_label = QLabel("AI EXPLANATION  (local AI — click an alert)")
        ai_label.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(ai_label)

        self.ai_box = QTextEdit()
        self.ai_box.setReadOnly(True)
        self.ai_box.setMaximumHeight(s(120))
        self.ai_box.setPlaceholderText("Select an alert to see AI-powered explanation...")
        layout.addWidget(self.ai_box)

        self._alerts_data = []

    def _action_button_style(self, background: str, hover: str, pressed: str) -> str:
        return f"""
            QPushButton {{
                color: #ffffff;
                background: {background};
                border: 1px solid {background};
                padding: 0px 12px;
                font-size: {fp(11)}px;
                font-weight: 600;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: {hover};
                border-color: {hover};
            }}
            QPushButton:pressed {{
                background: {pressed};
                border-color: {pressed};
            }}
        """

    def _alert_target_domain(self, alert: dict) -> str:
        domain = (alert.get("domain") or "").strip()
        if not domain:
            return ""
        if domain == alert.get("ip"):
            return ""
        return domain

    def _find_process_exe(self, process_name: str) -> str:
        process_name = (process_name or "").strip().lower()
        if not process_name:
            return ""

        processes = api_get("/processes")
        if not isinstance(processes, list):
            return ""

        for proc in processes:
            if (proc.get("process") or "").strip().lower() == process_name and proc.get("exe"):
                return proc.get("exe", "")
        return ""

    def _supports_alert_controls(self, alert: dict) -> bool:
        if not isinstance(alert, dict):
            return False
        if alert.get("type") not in {"malicious_ip", "packet_malicious_ip", "parental_control"}:
            return False
        return bool(self._alert_target_domain(alert) or alert.get("process"))

    def _block_from_alert(self, alert: dict):
        if not isinstance(alert, dict):
            return

        domain = self._alert_target_domain(alert)
        process = (alert.get("process") or "").strip()

        if domain:
            result = api_post("/parental/domains/block", {"domain": domain})
            if result.get("ok"):
                QMessageBox.information(self, "Blocked", f"'{result.get('domain', domain)}' is now blocked.")
            else:
                QMessageBox.warning(self, "Block Failed", result.get("error", "Could not block that domain."))
            return

        if not process:
            QMessageBox.warning(self, "Block Failed", "No blockable process or domain was found for this alert.")
            return

        exe_path = self._find_process_exe(process)
        result = api_post("/processes/block", {"process": process, "exe": exe_path})
        if result.get("ok"):
            QMessageBox.information(self, "Blocked", f"'{process}' is now blocked from internet access.")
        else:
            error = result.get("error") or result.get("firewall", {}).get("error", "Could not block that process.")
            QMessageBox.warning(self, "Block Failed", error)

    def _unblock_from_alert(self, alert: dict):
        if not isinstance(alert, dict):
            return

        domain = self._alert_target_domain(alert)
        process = (alert.get("process") or "").strip()

        if domain:
            result = api_post("/parental/domains/unblock", {"domain": domain})
            if result.get("ok"):
                QMessageBox.information(self, "Unblocked", f"'{result.get('domain', domain)}' has been unblocked.")
            else:
                QMessageBox.warning(self, "Unblock Failed", result.get("error", "Could not unblock that domain."))
            return

        if not process:
            QMessageBox.warning(self, "Unblock Failed", "No unblockable process or domain was found for this alert.")
            return

        result = api_post("/processes/unblock", {"process": process})
        if result.get("ok"):
            QMessageBox.information(self, "Unblocked", f"'{process}' has been unblocked.")
        else:
            error = result.get("error") or result.get("firewall", {}).get("error", "Could not unblock that process.")
            QMessageBox.warning(self, "Unblock Failed", error)

    def update_alerts(self, alerts: list):
        live_alerts = [
            alert for alert in alerts
            if not str(alert.get("id", "")).startswith("demo_alert_")
        ]
        self._alerts_data = live_alerts
        self.alert_count.setText(f"{len(live_alerts)} alerts")
        self.table.setRowCount(0)

        for alert in live_alerts:
            row = self.table.rowCount()
            self.table.insertRow(row)

            ts = alert.get("timestamp", "")[:19].replace("T", " ")
            sev = alert.get("severity", "low").upper()
            proc = alert.get("process", "unknown")
            domain = alert.get("domain") or alert.get("ip", "-")
            risk = f"{alert.get('risk_score', 0):.1f}"
            msg = alert.get("message", "")

            self.table.setItem(row, 0, QTableWidgetItem(ts))
            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(QColor(severity_color(alert.get("severity", "low"))))
            self.table.setItem(row, 1, sev_item)
            self.table.setItem(row, 2, QTableWidgetItem(proc))
            self.table.setItem(row, 3, QTableWidgetItem(domain))

            risk_item = QTableWidgetItem(risk)
            risk_score = alert.get("risk_score", 0)
            if risk_score >= 7:
                risk_item.setForeground(QColor(COLORS["high_risk"]))
            elif risk_score >= 5:
                risk_item.setForeground(QColor(COLORS["med_risk"]))
            else:
                risk_item.setForeground(QColor(COLORS["low_risk"]))
            self.table.setItem(row, 4, risk_item)
            self.table.setItem(row, 5, QTableWidgetItem(msg))

            actions_widget = QWidget()
            actions_widget.setMinimumWidth(190)
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(6, 4, 6, 4)
            actions_layout.setSpacing(6)

            risk_score = alert.get("risk_score", 0)
            if risk_score >= 7:
                if alert.get("type") == "bandwidth_threshold":
                    allow_btn = QPushButton("Allow")
                    allow_btn.setMinimumWidth(s(64))
                    allow_btn.setFixedHeight(s(28))
                    allow_btn.setCursor(Qt.PointingHandCursor)
                    allow_btn.setStyleSheet(self._action_button_style(COLORS['accent_green'], "#0d9488", "#0a7c72"))
                    allow_btn.clicked.connect(lambda _, a=alert: self._decide_on_alert(a, "allow"))
                    block_btn = QPushButton("Block")
                    block_btn.setMinimumWidth(s(64))
                    block_btn.setFixedHeight(s(28))
                    block_btn.setCursor(Qt.PointingHandCursor)
                    block_btn.setStyleSheet(self._action_button_style(COLORS['accent_red'], "#dc2626", "#b91c1c"))
                    block_btn.clicked.connect(lambda _, a=alert: self._decide_on_alert(a, "block"))
                    actions_layout.addWidget(allow_btn)
                    actions_layout.addWidget(block_btn)
                elif self._supports_alert_controls(alert):
                    block_btn = QPushButton("Block")
                    block_btn.setMinimumWidth(s(64))
                    block_btn.setFixedHeight(s(28))
                    block_btn.setCursor(Qt.PointingHandCursor)
                    block_btn.setStyleSheet(self._action_button_style(COLORS['accent_red'], "#dc2626", "#b91c1c"))
                    block_btn.clicked.connect(lambda _, a=alert: self._block_from_alert(a))
                    actions_layout.addWidget(block_btn)
                    if alert.get("action_taken") == "blocked":
                        unblock_btn = QPushButton("Unblock")
                        unblock_btn.setMinimumWidth(s(74))
                        unblock_btn.setFixedHeight(s(28))
                        unblock_btn.setCursor(Qt.PointingHandCursor)
                        unblock_btn.setStyleSheet(self._action_button_style(COLORS['accent_blue'], "#2563eb", "#1d4ed8"))
                        unblock_btn.clicked.connect(lambda _, a=alert: self._unblock_from_alert(a))
                        actions_layout.addWidget(unblock_btn)

            actions_layout.addStretch()
            self.table.setCellWidget(row, 6, actions_widget)
            self.table.setRowHeight(row, s(38))

    def _decide_on_alert(self, alert: dict, decision: str):
        """Allow or block a high-usage alert directly from the alert row."""
        if not isinstance(alert, dict):
            return
        if alert.get("type") != "bandwidth_threshold":
            QMessageBox.information(self, "Adaptive Control", "This action only applies to high-usage alerts.")
            return

        process = alert.get("process", "")
        exe_path = alert.get("exe", "")
        result = api_post("/adaptive/decision", {"process": process, "exe": exe_path, "decision": decision})
        if result.get("ok"):
            QMessageBox.information(self, "Adaptive Control", f"'{process}' was marked as {decision}.")
        else:
            QMessageBox.warning(self, "Adaptive Control", result.get("error", "Could not apply that decision."))

    def _show_details(self, index):
        row = index.row()
        if row >= len(self._alerts_data):
            return
        alert = self._alerts_data[row]

        if not hasattr(self, "_ai_cache"):
            self._ai_cache = {}
            self._ai_workers = []

        alert_id = alert.get("id", "")
        # Instant if we've already explained this alert this session.
        if alert_id in self._ai_cache:
            self.ai_box.setText(f"AI Analysis:\n\n{self._ai_cache[alert_id]}")
            return
        # Or if it was generated eagerly server-side (legacy alerts).
        if alert.get("ai_explanation"):
            self.ai_box.setText(f"AI Analysis:\n\n{alert['ai_explanation']}")
            return

        self.ai_box.setText("Analyzing… (local AI, first answer after idle can take a few seconds)")
        worker = _AIWorker("/ai/explain-alert", alert, timeout=60)
        worker.done.connect(lambda result, aid=alert_id, w=worker:
                            self._on_explain_done(result, aid, w))
        self._ai_workers.append(worker)
        worker.start()

    def _on_explain_done(self, result, alert_id, worker):
        text = result.get("explanation", "") if isinstance(result, dict) else ""
        err = result.get("error", "") if isinstance(result, dict) else ""
        if text:
            self._ai_cache[alert_id] = text
            self.ai_box.setText(f"AI Analysis:\n\n{text}")
        else:
            self.ai_box.setText(
                "AI analysis unavailable. Make sure the local AI (Ollama) is running."
                + (f"\n\n{err}" if err else "")
            )
        try:
            self._ai_workers.remove(worker)
        except (AttributeError, ValueError):
            pass


# ─── Threat Check Tab ────────────────────────────────────────────────

class ThreatCheckTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Page title
        title_lbl = QLabel("Threat Check")
        title_lbl.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(26)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_lbl)

        section_title = QLabel("MANUAL THREAT CHECKER")
        section_title.setStyleSheet(
            f"color: {COLORS['accent_amber']}; font-size: {fp(13)}px; font-weight: bold; "
            f"letter-spacing: 2px; border: none; background: transparent;"
        )
        layout.addWidget(section_title)

        # IP Check
        ip_frame = QFrame()
        ip_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        ip_layout = QVBoxLayout(ip_frame)
        ip_layout.setContentsMargins(16, 12, 16, 12)
        ip_layout.setSpacing(8)

        ip_lbl = QLabel("CHECK IP REPUTATION")
        ip_lbl.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        ip_layout.addWidget(ip_lbl)

        ip_input_row = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address (e.g. 8.8.8.8)")
        self.ip_check_btn = QPushButton("CHECK IP")
        self.ip_check_btn.clicked.connect(self._check_ip)
        ip_input_row.addWidget(self.ip_input)
        ip_input_row.addWidget(self.ip_check_btn)
        ip_layout.addLayout(ip_input_row)

        self.ip_result = QTextEdit()
        self.ip_result.setReadOnly(True)
        self.ip_result.setMaximumHeight(s(120))
        ip_layout.addWidget(self.ip_result)
        layout.addWidget(ip_frame)

        # URL Check
        url_frame = QFrame()
        url_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        url_layout = QVBoxLayout(url_frame)
        url_layout.setContentsMargins(16, 12, 16, 12)
        url_layout.setSpacing(8)

        url_lbl = QLabel("CHECK URL / DOMAIN")
        url_lbl.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        url_layout.addWidget(url_lbl)

        url_input_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL (e.g. https://example.com)")
        self.url_check_btn = QPushButton("CHECK URL")
        self.url_check_btn.clicked.connect(self._check_url)
        url_input_row.addWidget(self.url_input)
        url_input_row.addWidget(self.url_check_btn)
        url_layout.addLayout(url_input_row)

        self.url_result = QTextEdit()
        self.url_result.setReadOnly(True)
        self.url_result.setMaximumHeight(s(120))
        url_layout.addWidget(self.url_result)
        layout.addWidget(url_frame)

        # Gemini Ask
        ai_frame = QFrame()
        ai_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        ai_layout = QVBoxLayout(ai_frame)
        ai_layout.setContentsMargins(16, 12, 16, 12)
        ai_layout.setSpacing(8)


        ai_input_row = QHBoxLayout()
        self.ai_input = QLineEdit()
        self.ai_input.setPlaceholderText("Ask about your network, or 'is everything ok right now?'")
        self.ai_btn = QPushButton("ASK AI")
        self.ai_btn.clicked.connect(self._ask_ai)
        self.summary_btn = QPushButton("SUMMARIZE ACTIVITY")
        self.summary_btn.clicked.connect(self._summarize_activity)
        ai_input_row.addWidget(self.ai_input)
        ai_input_row.addWidget(self.ai_btn)
        ai_input_row.addWidget(self.summary_btn)
        ai_layout.addLayout(ai_input_row)
        self._ai_workers = []

        self.ai_result = QTextEdit()
        self.ai_result.setReadOnly(True)
        self.ai_result.setMaximumHeight(s(120))
        ai_layout.addWidget(self.ai_result)
        layout.addWidget(ai_frame)

        layout.addStretch()

    def _check_ip(self):
        ip = self.ip_input.text().strip()
        if not ip:
            return
        self.ip_result.setText("Checking... (live API lookups can take up to ~15s)")
        # OTX in particular can take 10-15s, so give the request a generous
        # timeout — a short one silently falls back to a misleading 0/10.
        result = api_post(f"/check/ip/{ip}", {}, timeout=25)
        if result and "error" not in result:
            risk = result.get("risk_score", 0)
            safe = result.get("safe", True)
            conf = result.get("confidence", 0)
            pulses = result.get("otx_pulses", 0)
            live_sources = ", ".join(result.get("live_sources", [])) or "none"
            simulated_sources = ", ".join(result.get("simulated_sources", [])) or "none"
            source_note = (
                "Real API data is being used."
                if result.get("source") == "apis"
                else "Demo mode: add AbuseIPDB/OTX keys in config.json for real results."
            )
            status = "SAFE" if safe else "SUSPICIOUS CONNECTION"
            self.ip_result.setText(
                f"IP: {ip}\n"
                f"Status: {status}\n"
                f"Threat Level: {risk}/10\n"
                f"Abuse Confidence: {conf}%\n"
                f"OTX Threat Pulses: {pulses}\n"
                f"Source: {result.get('source', 'simulated')}\n"
                f"Live APIs: {live_sources}\n"
                f"Simulated APIs: {simulated_sources}\n"
                f"Note: {source_note}"
            )
        else:
            err = result.get("error", "unknown error") if result else "no response"
            self.ip_result.setText(
                f"Could not reach backend API.\nError: {err}"
            )

    def _check_url(self):
        url = self.url_input.text().strip()
        if not url:
            return
        self.url_result.setText("Checking... (live API lookups can take a few seconds)")
        result = api_post("/check/url", {"url": url}, timeout=25)
        if result and "error" not in result:
            classification = result.get("classification", "safe")
            risk = result.get("risk_score", 0)
            if classification == "malicious":
                status = "MALICIOUS"
            elif classification == "risky":
                status = "RISKY"
            else:
                status = "SAFE"
            urlhaus = result.get("urlhaus", {})
            gsb = result.get("google_safe_browsing", {})
            heuristic = result.get("heuristic", {})
            reasons = ", ".join(heuristic.get("reasons", [])) or "none"

            # Don't report a failed/unconfigured lookup as "Clean" — that would
            # hide the fact that the feed never actually ran.
            if urlhaus.get("malicious"):
                urlhaus_str = "Listed (malicious)"
            elif urlhaus.get("available"):
                urlhaus_str = "Clean"
            elif urlhaus.get("status") == "no_key":
                urlhaus_str = "Unavailable (no abuse.ch key)"
            else:
                urlhaus_str = "Unavailable (lookup failed)"

            self.url_result.setText(
                f"URL: {url}\n"
                f"Status: {status}\n"
                f"Threat Score: {risk}/10\n"
                f"URLhaus: {urlhaus_str}\n"
                f"Google Safe Browsing: {'Flagged' if gsb.get('malicious') else 'Clean'}\n"
                f"Threat Type: {gsb.get('threat_type', 'None')}\n"
                f"Heuristic Reasons: {reasons}"
            )
        else:
            self.url_result.setText("Could not connect to backend API.")

    def _ask_ai(self):
        text = self.ai_input.text().strip()
        if not text:
            return
        self.ai_result.setText("Thinking... (local AI, first answer after idle can take a few seconds)")
        self._run_ai("/gemini/explain", {"text": text}, "explanation")

    def _summarize_activity(self):
        self.ai_result.setText("Summarizing current activity...")
        self._run_ai("/ai/summary", {}, "summary")

    def _run_ai(self, endpoint: str, payload: dict, result_key: str):
        """Run an AI request on a background worker so the UI stays responsive."""
        self.ai_btn.setEnabled(False)
        self.summary_btn.setEnabled(False)
        worker = _AIWorker(endpoint, payload, timeout=60)
        worker.done.connect(lambda result, k=result_key, w=worker: self._on_ai_done(result, k, w))
        self._ai_workers.append(worker)
        worker.start()

    def _on_ai_done(self, result, result_key, worker):
        self.ai_btn.setEnabled(True)
        self.summary_btn.setEnabled(True)
        if isinstance(result, dict) and result.get(result_key):
            self.ai_result.setText(result[result_key])
        else:
            err = result.get("error", "") if isinstance(result, dict) else ""
            self.ai_result.setText(
                "AI service unavailable. Make sure the local AI (Ollama) is running."
                + (f"\n\n{err}" if err else "")
            )
        try:
            self._ai_workers.remove(worker)
        except (AttributeError, ValueError):
            pass


# ─── Parental Control Tab ────────────────────────────────────────────

class _ParentalRefreshWorker(QThread):
    """Fetch all parental-tab data off the UI thread so the panel doesn't freeze."""
    done = pyqtSignal(dict)

    def run(self):
        payload = {
            "pause": api_get("/parental/pause"),
            "safemode": api_get("/parental/safemode"),
            "categories": api_get("/parental/categories"),
            "schedules": api_get("/parental/schedules"),
            "domains": api_get("/parental/domains/blocked"),
            "apps": api_get("/processes/blocked"),
        }
        self.done.emit(payload)


class _ParentalActionWorker(QThread):
    """Run a single api_post on a background thread to keep the UI responsive."""
    done = pyqtSignal(dict)

    def __init__(self, endpoint: str, data: dict, timeout: int = 30):
        super().__init__()
        self._endpoint = endpoint
        self._data = data
        self._timeout = timeout

    def run(self):
        try:
            url = f"{API_BASE}{self._endpoint}"
            body = json.dumps(self._data).encode()
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                result = json.loads(resp.read())
        except Exception as e:
            result = {"error": str(e)}
        self.done.emit(result)


class ParentalTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(f"background: {COLORS['bg_dark']};")
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Page title
        title_lbl = QLabel("Parental Controls")
        title_lbl.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(26)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_lbl)

        section_title = QLabel("PARENTAL CONTROLS")
        section_title.setStyleSheet(
            f"color: {COLORS['accent_amber']}; font-size: {fp(13)}px; font-weight: bold; "
            f"letter-spacing: 2px; border: none; background: transparent;"
        )
        layout.addWidget(section_title)

        # Pause Internet (big visible toggle)
        pause_frame = QFrame()
        pause_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        pause_layout = QHBoxLayout(pause_frame)
        pause_layout.setContentsMargins(16, 12, 16, 12)
        pause_lbl = QLabel("PAUSE INTERNET  (instantly block all outbound traffic on this PC)")
        pause_lbl.setStyleSheet(f"color: {COLORS['text_primary']}; border: none; background: transparent;")
        self.pause_btn = QPushButton("PAUSE INTERNET")
        self.pause_btn.setStyleSheet(
            f"color: {COLORS['accent_red']}; border-color: {COLORS['accent_red']};"
        )
        self.pause_btn.clicked.connect(self._toggle_pause)
        self._paused = False
        pause_layout.addWidget(pause_lbl)
        pause_layout.addStretch()
        pause_layout.addWidget(self.pause_btn)
        layout.addWidget(pause_frame)

        # Safe mode toggle
        safe_frame = QFrame()
        safe_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        safe_layout = QHBoxLayout(safe_frame)
        safe_layout.setContentsMargins(16, 12, 16, 12)
        safe_lbl = QLabel("SAFE MODE  (master switch — applies your category selections + auto-blocks malicious IPs)")
        safe_lbl.setStyleSheet(f"color: {COLORS['text_primary']}; border: none; background: transparent;")
        self.safe_mode_btn = QPushButton("ENABLE SAFE MODE")
        self.safe_mode_btn.setStyleSheet(
            f"color: {COLORS['accent_green']}; border-color: {COLORS['accent_green']};"
        )
        self.safe_mode_btn.clicked.connect(self._toggle_safe_mode)
        self._safe_mode_enabled = False
        safe_layout.addWidget(safe_lbl)
        safe_layout.addStretch()
        safe_layout.addWidget(self.safe_mode_btn)
        layout.addWidget(safe_frame)

        # Category Blocking
        cat_frame = QFrame()
        cat_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        cat_layout = QVBoxLayout(cat_frame)
        cat_layout.setContentsMargins(16, 12, 16, 12)
        cat_layout.setSpacing(8)
        cat_lbl = QLabel("CATEGORY BLOCKING")
        cat_lbl.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        cat_layout.addWidget(cat_lbl)
        cat_hint = QLabel("Pick the categories to block. Nothing is enforced until Safe Mode is ON.")
        cat_hint.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(11)}px; border: none; background: transparent;"
        )
        cat_hint.setWordWrap(True)
        self.cat_hint = cat_hint
        cat_layout.addWidget(cat_hint)

        self.category_grid = QGridLayout()
        self.category_grid.setSpacing(8)
        self._category_checkboxes = {}
        cat_layout.addLayout(self.category_grid)
        layout.addWidget(cat_frame)

        # App Schedules
        sched_frame = QFrame()
        sched_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        sched_layout = QVBoxLayout(sched_frame)
        sched_layout.setContentsMargins(16, 12, 16, 12)
        sched_layout.setSpacing(8)
        sched_lbl = QLabel("APP SCHEDULES")
        sched_lbl.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        sched_layout.addWidget(sched_lbl)
        sched_hint = QLabel("Block an app on this PC during the chosen time window.")
        sched_hint.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(11)}px; border: none; background: transparent;"
        )
        sched_layout.addWidget(sched_hint)

        form_row1 = QHBoxLayout()
        self.sched_process = QLineEdit()
        self.sched_process.setPlaceholderText("Process name (e.g. chrome.exe)")
        self.sched_exe = QLineEdit()
        self.sched_exe.setPlaceholderText("Executable path (required by Windows Firewall)")
        form_row1.addWidget(self.sched_process)
        form_row1.addWidget(self.sched_exe, 2)
        sched_layout.addLayout(form_row1)

        form_row2 = QHBoxLayout()
        self.sched_start = QLineEdit()
        self.sched_start.setPlaceholderText("Start HH:MM")
        self.sched_start.setMaximumWidth(s(110))
        self.sched_end = QLineEdit()
        self.sched_end.setPlaceholderText("End HH:MM")
        self.sched_end.setMaximumWidth(s(110))
        form_row2.addWidget(QLabel("From"))
        form_row2.addWidget(self.sched_start)
        form_row2.addWidget(QLabel("to"))
        form_row2.addWidget(self.sched_end)
        form_row2.addSpacing(s(12))

        self._day_checkboxes = []
        for label, idx in [("Mon", 0), ("Tue", 1), ("Wed", 2), ("Thu", 3),
                             ("Fri", 4), ("Sat", 5), ("Sun", 6)]:
            cb = QCheckBox(label)
            cb.setProperty("day_index", idx)
            form_row2.addWidget(cb)
            self._day_checkboxes.append(cb)
        form_row2.addStretch()
        add_sched_btn = QPushButton("+ ADD SCHEDULE")
        add_sched_btn.clicked.connect(self._add_schedule)
        form_row2.addWidget(add_sched_btn)
        sched_layout.addLayout(form_row2)

        self.schedule_list = QListWidget()
        self.schedule_list.setMinimumHeight(s(120))
        self.schedule_list.setSizeAdjustPolicy(QListWidget.AdjustToContents)
        self.schedule_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        sched_layout.addWidget(self.schedule_list)

        remove_sched_btn = QPushButton("REMOVE SELECTED SCHEDULE")
        remove_sched_btn.setStyleSheet(
            f"color: {COLORS['accent_red']}; border-color: {COLORS['accent_red']};"
        )
        remove_sched_btn.clicked.connect(self._remove_schedule)
        sched_layout.addWidget(remove_sched_btn)
        layout.addWidget(sched_frame)

        # Block domain
        domain_frame = QFrame()
        domain_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        domain_layout = QVBoxLayout(domain_frame)
        domain_layout.setContentsMargins(16, 12, 16, 12)
        domain_layout.setSpacing(8)
        domain_lbl = QLabel("BLOCKED DOMAINS")
        domain_lbl.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        domain_layout.addWidget(domain_lbl)

        add_row = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain to block (e.g. example.com)")
        self.add_domain_btn = QPushButton("+ ADD")
        self.add_domain_btn.clicked.connect(self._add_domain)
        add_row.addWidget(self.domain_input)
        add_row.addWidget(self.add_domain_btn)
        domain_layout.addLayout(add_row)

        self.domain_list = QListWidget()
        self.domain_list.setMinimumHeight(s(120))
        self.domain_list.setSizeAdjustPolicy(QListWidget.AdjustToContents)
        self.domain_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        domain_layout.addWidget(self.domain_list)

        remove_btn = QPushButton("REMOVE SELECTED")
        remove_btn.setStyleSheet(
            f"color: {COLORS['accent_red']}; border-color: {COLORS['accent_red']};"
        )
        remove_btn.clicked.connect(self._remove_domain)
        domain_layout.addWidget(remove_btn)
        layout.addWidget(domain_frame)

        # Blocked apps
        apps_frame = QFrame()
        apps_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        apps_layout = QVBoxLayout(apps_frame)
        apps_layout.setContentsMargins(16, 12, 16, 12)
        apps_layout.setSpacing(8)
        apps_lbl = QLabel("BLOCKED APPLICATIONS")
        apps_lbl.setStyleSheet(
            f"color: {COLORS['accent_blue']}; font-size: {fp(11)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        apps_layout.addWidget(apps_lbl)

        self.apps_list = QListWidget()
        self.apps_list.setMinimumHeight(s(100))
        self.apps_list.setSizeAdjustPolicy(QListWidget.AdjustToContents)
        self.apps_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        apps_layout.addWidget(self.apps_list)
        unblock_app_btn = QPushButton("UNBLOCK SELECTED APP")
        unblock_app_btn.setStyleSheet(
            f"color: {COLORS['accent_green']}; border-color: {COLORS['accent_green']};"
        )
        unblock_app_btn.clicked.connect(self._unblock_app)
        apps_layout.addWidget(unblock_app_btn)

        refresh_btn = QPushButton("REFRESH")
        refresh_btn.clicked.connect(self._refresh)
        apps_layout.addWidget(refresh_btn)
        layout.addWidget(apps_frame)

        layout.addStretch()
        self._refresh()

    def _toggle_safe_mode(self):
        target = not self._safe_mode_enabled
        self.safe_mode_btn.setEnabled(False)
        self.safe_mode_btn.setText("Working…")
        worker = _ParentalActionWorker(
            "/parental/safemode", {"enabled": target}, timeout=30
        )
        worker.done.connect(lambda result, t=target, w=worker:
                             self._on_safe_mode_done(result, t, w))
        worker.start()
        self._safe_mode_worker = worker

    def _on_safe_mode_done(self, result, target, worker):
        self.safe_mode_btn.setEnabled(True)
        if not isinstance(result, dict) or result.get("error"):
            QMessageBox.warning(self, "Safe Mode Failed",
                                str((result or {}).get("error", "Could not toggle safe mode.")))
            self._refresh_safe_mode_button()
            return
        self._safe_mode_enabled = bool(result.get("safe_mode", target))
        self._refresh_safe_mode_button()

    def _refresh_safe_mode_button(self):
        if self._safe_mode_enabled:
            self.safe_mode_btn.setText("SAFE MODE ON")
            self.safe_mode_btn.setStyleSheet(
                f"background: {COLORS['accent_green']}; color: #ffffff; border-color: {COLORS['accent_green']};"
            )
        else:
            self.safe_mode_btn.setText("ENABLE SAFE MODE")
            self.safe_mode_btn.setStyleSheet(
                f"color: {COLORS['accent_green']}; border-color: {COLORS['accent_green']};"
            )
        self._update_category_lock()

    def _toggle_pause(self):
        target = not self._paused
        self.pause_btn.setEnabled(False)
        self.pause_btn.setText("Working…")
        worker = _ParentalActionWorker("/parental/pause", {"paused": target}, timeout=25)
        worker.done.connect(lambda result, t=target, w=worker: self._on_pause_done(result, t, w))
        worker.start()
        self._pause_worker = worker  # keep a ref so it isn't garbage collected

    def _on_pause_done(self, result, target, worker):
        self.pause_btn.setEnabled(True)
        if not isinstance(result, dict) or result.get("error"):
            QMessageBox.warning(self, "Pause Failed",
                                str((result or {}).get("error", "Could not toggle pause.")))
            self._refresh_pause_button()
            return
        self._paused = bool(result.get("paused", target))
        self._refresh_pause_button()

    def _refresh_pause_button(self):
        if self._paused:
            self.pause_btn.setText("RESUME INTERNET")
            self.pause_btn.setStyleSheet(
                f"background: {COLORS['accent_red']}; color: #ffffff; border-color: {COLORS['accent_red']};"
            )
        else:
            self.pause_btn.setText("PAUSE INTERNET")
            self.pause_btn.setStyleSheet(
                f"color: {COLORS['accent_red']}; border-color: {COLORS['accent_red']};"
            )

    def _toggle_category(self, key: str, checkbox: QCheckBox):
        checkbox.setEnabled(False)
        worker = _ParentalActionWorker(
            "/parental/categories",
            {"category": key, "enabled": checkbox.isChecked()},
            timeout=30,
        )
        worker.done.connect(lambda result, cb=checkbox, w=worker:
                             self._on_category_done(result, cb, w))
        worker.start()
        if not hasattr(self, "_category_workers"):
            self._category_workers = []
        self._category_workers.append(worker)

    def _on_category_done(self, result, checkbox, worker):
        checkbox.setEnabled(True)
        if isinstance(result, dict) and result.get("error"):
            QMessageBox.warning(self, "Category Block Failed",
                                str(result.get("error")))
        try:
            self._category_workers.remove(worker)
        except (AttributeError, ValueError):
            pass

    def _add_schedule(self):
        process = self.sched_process.text().strip()
        exe = self.sched_exe.text().strip()
        start_time = self.sched_start.text().strip()
        end_time = self.sched_end.text().strip()
        days = [cb.property("day_index") for cb in self._day_checkboxes if cb.isChecked()]
        result = api_post("/parental/schedules", {
            "process": process,
            "executable_path": exe,
            "start_time": start_time,
            "end_time": end_time,
            "days": days,
        })
        if not isinstance(result, dict) or not result.get("ok"):
            QMessageBox.warning(self, "Schedule Failed",
                                str((result or {}).get("error", "Could not add schedule.")))
            return
        self.sched_process.clear()
        self.sched_exe.clear()
        self.sched_start.clear()
        self.sched_end.clear()
        for cb in self._day_checkboxes:
            cb.setChecked(False)
        self._refresh(force=True)

    def _remove_schedule(self):
        item = self.schedule_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No Schedule Selected", "Pick a schedule to remove.")
            return
        sched_id = item.data(Qt.UserRole)
        if sched_id is None:
            return
        url = f"{API_BASE}/parental/schedules/{sched_id}"
        try:
            req = urllib.request.Request(url, method="DELETE")
            with urllib.request.urlopen(req, timeout=5) as resp:
                json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            QMessageBox.warning(self, "Remove Failed", str(e))
            return
        self._refresh(force=True)

    def _add_domain(self):
        domain = self.domain_input.text().strip()
        if domain:
            result = api_post("/parental/domains/block", {"domain": domain})
            if result.get("ok"):
                self.domain_input.clear()
                self._refresh(force=True)
                QMessageBox.information(self, "Domain Blocked", f"'{result.get('domain', domain)}' will now be blocked.")
            else:
                QMessageBox.warning(
                    self,
                    "Domain Block Failed",
                    result.get("error", "Could not block that domain. On Windows, domain blocking needs administrator privileges to update the hosts file."),
                )

    def _remove_domain(self):
        item = self.domain_list.currentItem()
        if item:
            domain = item.text()
            result = api_post("/parental/domains/unblock", {"domain": domain})
            if result.get("ok"):
                self._refresh(force=True)
            else:
                QMessageBox.warning(self, "Unblock Failed", result.get("error", "Could not remove that domain block."))

    def _unblock_app(self):
        item = self.apps_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No App Selected", "Select a blocked app first.")
            return

        payload = item.data(Qt.UserRole) or {}
        process = payload.get("process") or item.text()
        source = payload.get("source", "manual")
        result = api_post("/processes/unblock", {"process": process, "source": source})
        if result.get("error"):
            QMessageBox.warning(self, "Backend Offline", f"Could not contact NetGuard backend:\n\n{result.get('error')}")
        elif result.get("ok"):
            QMessageBox.information(self, "Unblocked", f"'{process}' has been unblocked.")
        else:
            error = result.get("firewall", {}).get("error") or "Firewall rule could not be removed."
            QMessageBox.warning(self, "Unblock Warning", f"'{process}' was removed from NetGuard, but Windows Firewall cleanup reported:\n\n{error}")
        self._refresh(force=True)

    def _refresh(self, force: bool = False):
        """Kick off a background refresh so the UI doesn't freeze.
        ``force=True`` queues another refresh even if one is in flight, so the
        UI catches up after user actions like Add/Remove."""
        if not force and getattr(self, "_refresh_thread", None) and self._refresh_thread.isRunning():
            return
        worker = _ParentalRefreshWorker()
        worker.done.connect(self._apply_refresh)
        # Keep a list of active workers so they aren't garbage-collected mid-run
        if not hasattr(self, "_refresh_workers"):
            self._refresh_workers = []
        self._refresh_workers.append(worker)
        worker.finished.connect(lambda w=worker: self._refresh_workers.remove(w)
                                 if w in self._refresh_workers else None)
        self._refresh_thread = worker
        worker.start()

    def _apply_refresh(self, payload: dict):
        pause = payload.get("pause") or {}
        if isinstance(pause, dict) and "paused" in pause:
            self._paused = bool(pause.get("paused"))
            self._refresh_pause_button()

        safemode = payload.get("safemode") or {}
        if isinstance(safemode, dict) and "safe_mode" in safemode:
            self._safe_mode_enabled = bool(safemode.get("safe_mode"))
            self._refresh_safe_mode_button()

        self._apply_categories(payload.get("categories"))
        self._apply_schedules(payload.get("schedules"))
        domains = payload.get("domains")
        self.domain_list.clear()
        if isinstance(domains, list):
            for d in domains:
                self.domain_list.addItem(d if isinstance(d, str) else str(d))

        apps = payload.get("apps")
        self.apps_list.clear()
        app_entries = []
        if isinstance(apps, dict):
            for source in ("manual_blocks", "adaptive_blocks"):
                for entry in apps.get(source, []) or []:
                    if isinstance(entry, dict):
                        app_entries.append({
                            "process": entry.get("process", ""),
                            "exe": entry.get("exe", ""),
                            "source": source.replace("_blocks", ""),
                        })
                    else:
                        app_entries.append({
                            "process": str(entry),
                            "exe": "",
                            "source": source.replace("_blocks", ""),
                        })
        elif isinstance(apps, list):
            for entry in apps:
                if isinstance(entry, dict):
                    app_entries.append({
                        "process": entry.get("process", ""),
                        "exe": entry.get("exe", ""),
                        "source": entry.get("source", "manual"),
                    })
                else:
                    app_entries.append({
                        "process": str(entry),
                        "exe": "",
                        "source": "manual",
                    })

        for entry in app_entries:
            label = entry["process"]
            if entry.get("source") == "adaptive":
                label = f"{label} [adaptive]"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, entry)
            self.apps_list.addItem(item)

    def _apply_categories(self, cats):
        while self.category_grid.count():
            item = self.category_grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._category_checkboxes = {}
        if not isinstance(cats, list):
            return
        for idx, cat in enumerate(cats):
            key = cat.get("key", "")
            label = cat.get("label", key)
            cb = QCheckBox(label)
            cb.setChecked(bool(cat.get("enabled", False)))
            cb.toggled.connect(lambda _checked, k=key, c=cb: self._toggle_category(k, c))
            self._category_checkboxes[key] = cb
            self.category_grid.addWidget(cb, idx // 2, idx % 2)
        self._update_category_lock()

    def _update_category_lock(self):
        """Category selections can only be changed while Safe Mode is ON.
        When it's OFF, grey out the checkboxes so they can't be toggled."""
        unlocked = bool(getattr(self, "_safe_mode_enabled", False))
        for cb in getattr(self, "_category_checkboxes", {}).values():
            cb.setEnabled(unlocked)
        hint = getattr(self, "cat_hint", None)
        if hint is not None:
            if unlocked:
                hint.setText("Pick the categories to block. Changes apply immediately while Safe Mode is ON.")
            else:
                hint.setText("Enable Safe Mode to choose categories to block.")

    def _apply_schedules(self, schedules):
        self.schedule_list.clear()
        if not isinstance(schedules, list):
            return
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        for sched in schedules:
            days = sched.get("days", []) or []
            day_str = ",".join(day_names[d] for d in days if 0 <= d <= 6)
            status = " [BLOCKED NOW]" if sched.get("currently_blocked") else ""
            label = (
                f"{sched.get('process','?')}  "
                f"{sched.get('start_time','??:??')}–{sched.get('end_time','??:??')}  "
                f"({day_str}){status}"
            )
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, sched.get("id"))
            self.schedule_list.addItem(item)

# ─── Logs Tab ────────────────────────────────────────────────────────

class _LogsWorker(QThread):
    """Fetch activity logs off the UI thread so REFRESH never freezes the window."""
    done = pyqtSignal(object)

    def run(self):
        self.done.emit(api_get("/logs"))


class LogsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # Page title
        title_lbl = QLabel("Logs")
        title_lbl.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: {fp(26)}px; font-weight: bold; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_lbl)

        header = QHBoxLayout()
        title = QLabel("ACTIVITY LOGS")
        title.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(13)}px; font-weight: bold; "
            f"letter-spacing: 2px; border: none; background: transparent;"
        )
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(11)}px; "
            f"border: none; background: transparent;"
        )
        self.refresh_btn = QPushButton("REFRESH")
        self.refresh_btn.clicked.connect(self._refresh)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.status_lbl)
        header.addWidget(self.refresh_btn)
        layout.addLayout(header)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["TIMESTAMP", "ACTION", "TARGET"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        self._refresh()

    def _refresh(self):
        # Fetch on a background thread so the window never freezes mid-click.
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Refreshing…")
        worker = _LogsWorker()
        worker.done.connect(lambda logs, w=worker: self._on_logs_done(logs, w))
        if not hasattr(self, "_logs_workers"):
            self._logs_workers = []
        self._logs_workers.append(worker)
        worker.start()

    def _on_logs_done(self, logs, worker):
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("REFRESH")
        try:
            self._logs_workers.remove(worker)
        except (AttributeError, ValueError):
            pass

        now = datetime.now().strftime("%H:%M:%S")
        if not isinstance(logs, list):
            # Backend unreachable/errored — keep the existing rows instead of
            # blanking the table, and say so.
            self.status_lbl.setText(f"Could not reach backend · {now}")
            return

        self.table.setRowCount(0)
        for log in logs:
            row = self.table.rowCount()
            self.table.insertRow(row)
            ts = log.get("timestamp", "")[:19].replace("T", " ")
            self.table.setItem(row, 0, QTableWidgetItem(ts))
            self.table.setItem(row, 1, QTableWidgetItem(log.get("action", "")))
            self.table.setItem(row, 2, QTableWidgetItem(log.get("target", "")))
        self.status_lbl.setText(f"Updated {now} · {len(logs)} entries")


# ─── Main Window ─────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetGuard — Real-Time Network Security Monitor")
        self.setMinimumSize(s(800), s(560))
        self.setStyleSheet(STYLESHEET)

        self._tray_first_hide = True   # show "running in background" only once
        self._monitoring_paused = False

        self._setup_ui()
        self._start_data_fetcher()
        self._check_backend()
        self._setup_tray()             # tray created last so window already exists

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Header bar ──
        header = QFrame()
        header.setFixedHeight(s(52))
        header.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['header_bg']};
                border-bottom: 1px solid {COLORS['header_border']};
            }}
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        header_layout.setSpacing(10)

        # System status section
        status_prefix = QLabel("System Status:")
        status_prefix.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(12)}px; "
            f"background: transparent; border: none;"
        )
        header_layout.addWidget(status_prefix)

        self.status_label = QLabel("● CONNECTING...")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['warn_text']};
            background: {COLORS['warn_bg']};
            font-size: {fp(11)}px;
            font-weight: bold;
            padding: 3px 10px;
            border-radius: 10px;
            border: none;
        """)
        header_layout.addWidget(self.status_label)

        sep = QLabel("|")
        sep.setStyleSheet(
            f"color: {COLORS['border']}; background: transparent; border: none; padding: 0 4px;"
        )
        header_layout.addWidget(sep)

        self.uptime_label = QLabel("UPTIME: 00:00:00")
        self.uptime_label.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: {fp(12)}px; "
            f"background: transparent; border: none;"
        )
        header_layout.addWidget(self.uptime_label)
        header_layout.addStretch()

        main_layout.addWidget(header)

        # ── Tab instances ──
        self.dashboard = DashboardTab()
        self.processes = ProcessesTab()
        self.alerts_tab = AlertsTab()
        self.threat_check = ThreatCheckTab()
        self.parental = ParentalTab()
        self.logs_tab = LogsTab()

        # ── Sidebar ──
        sidebar = QFrame()
        self._sidebar = sidebar
        sidebar.setMinimumWidth(s(180))
        sidebar.setMaximumWidth(s(280))
        sidebar.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['sidebar_bg']};
                border: none;
                border-right: 1px solid #1a2440;
            }}
        """)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Logo section
        logo_frame = QFrame()
        logo_frame.setFixedHeight(s(70))
        logo_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLORS['sidebar_bg']};
                border: none;
                border-bottom: 1px solid #1a2440;
            }}
        """)
        logo_layout = QVBoxLayout(logo_frame)
        logo_layout.setContentsMargins(s(20), s(14), s(20), s(14))
        logo_layout.setSpacing(2)

        logo_lbl = QLabel("NetGuard")
        logo_lbl.setStyleSheet(
            f"color: {COLORS['sidebar_logo']}; font-size: {s(18)}px; font-weight: bold; "
            f"letter-spacing: 0.5px; background: transparent; border: none;"
        )
        logo_sub = QLabel("Network Intelligence")
        logo_sub.setStyleSheet(
            f"color: {COLORS['sidebar_text']}; font-size: {s(10)}px; "
            f"background: transparent; border: none;"
        )
        logo_layout.addWidget(logo_lbl)
        logo_layout.addWidget(logo_sub)
        sidebar_layout.addWidget(logo_frame)

        # Navigation list
        self.nav_list = QListWidget()
        nav_items = [
            "  Dashboard",
            "  Processes",
            "  Alerts",
            "  Threat Check",
            "  Parental Controls",
            "  Logs",
        ]
        for item_text in nav_items:
            self.nav_list.addItem(item_text)

        self.nav_list.setSpacing(2)
        self.nav_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_list.setStyleSheet(f"""
            QListWidget {{
                background: {COLORS['sidebar_bg']};
                border: none;
                padding: 10px 0px;
                outline: none;
            }}
            QListWidget::item {{
                padding: {s(12)}px {s(20)}px;
                color: {COLORS['sidebar_text']};
                border-left: 3px solid transparent;
                font-size: {s(13)}px;
                border-radius: 0px;
            }}
            QListWidget::item:selected {{
                background: {COLORS['sidebar_active']};
                color: {COLORS['sidebar_text_act']};
                border-left: 3px solid {COLORS['sidebar_accent']};
                font-weight: bold;
            }}
            QListWidget::item:hover:!selected {{
                background: {COLORS['sidebar_hover']};
                color: {COLORS['sidebar_text_act']};
            }}
        """)
        sidebar_layout.addWidget(self.nav_list)
        sidebar_layout.addStretch()

        # ── Stack ──
        self.stack = QStackedWidget()
        self.stack.addWidget(self.dashboard)
        self.stack.addWidget(self.processes)
        self.stack.addWidget(self.alerts_tab)
        self.stack.addWidget(self.threat_check)
        self.stack.addWidget(self.parental)
        self.stack.addWidget(self.logs_tab)

        self.nav_list.currentRowChanged.connect(self._switch_page)
        self.nav_list.setCurrentRow(0)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(0)
        content_layout.addWidget(sidebar)
        content_layout.addWidget(self.stack, 1)
        main_layout.addLayout(content_layout)

        # ── Status bar removed — no footer shown in the UI ──
        self.statusBar().hide()

    def _switch_page(self, index: int):
        if index >= 0 and index < self.stack.count():
            self.stack.setCurrentIndex(index)

    def _start_data_fetcher(self):
        self.fetcher = DataFetcher()
        self.fetcher.bandwidth_updated.connect(self.dashboard.update_bandwidth)
        self.fetcher.processes_updated.connect(self.processes.update_processes)
        self.fetcher.processes_updated.connect(self.dashboard.update_top_apps)
        self.fetcher.alerts_updated.connect(self.dashboard.update_alerts)
        self.fetcher.alerts_updated.connect(self.alerts_tab.update_alerts)
        self.fetcher.stats_updated.connect(self.dashboard.update_stats)
        self.fetcher.stats_updated.connect(self._refresh_top_apps_fallback)
        self.fetcher.stats_updated.connect(self._update_uptime)
        self.fetcher.start()

    def _refresh_top_apps_fallback(self, stats: dict):
        """Refresh the top-apps table on the stats tick as a fallback."""
        procs = api_get("/processes")
        if isinstance(procs, list):
            self.dashboard.update_top_apps(procs)

    def _check_backend(self):
        """Check if backend is reachable."""
        QTimer.singleShot(1500, self._do_backend_check)

    def _do_backend_check(self):
        result = api_get("/stats")
        if result:
            self.status_label.setText("● ONLINE")
            self.status_label.setStyleSheet(f"""
                color: {COLORS['online_text']};
                background: {COLORS['online_bg']};
                font-size: {fp(11)}px;
                font-weight: bold;
                padding: 3px 10px;
                border-radius: 10px;
                border: none;
            """)
        else:
            self.status_label.setText("● OFFLINE")
            self.status_label.setStyleSheet(f"""
                color: {COLORS['offline_text']};
                background: {COLORS['offline_bg']};
                font-size: {fp(11)}px;
                font-weight: bold;
                padding: 3px 10px;
                border-radius: 10px;
                border: none;
            """)
            QMessageBox.warning(self, "Backend Offline",
                                "Cannot connect to NetGuard backend (http://127.0.0.1:8765).\n\n"
                                "Please start the backend first:\n"
                                "  cd backend\n"
                                "  python main.py")

    def _update_uptime(self, stats: dict):
        uptime = stats.get("uptime", "00:00:00")
        self.uptime_label.setText(f"UPTIME: {uptime}")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        w = event.size().width()
        sidebar_w = max(s(180), min(s(280), int(w * 0.17)))
        self._sidebar.setFixedWidth(sidebar_w)

    # ── System Tray ──────────────────────────────────────────────────

    def _setup_tray(self):
        """Create and show the system tray icon with its context menu."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self._tray = QSystemTrayIcon(self)
        self._tray.setIcon(_create_tray_icon(paused=False))
        self._tray.setToolTip("NetGuard — Network Security Monitor\nMonitoring active")

        menu = QMenu()

        open_action = QAction("Open Dashboard", self)
        open_action.triggered.connect(self._open_dashboard)
        menu.addAction(open_action)

        menu.addSeparator()

        self._pause_action = QAction("Pause Monitoring", self)
        self._pause_action.triggered.connect(self._pause_monitoring)
        menu.addAction(self._pause_action)

        self._resume_action = QAction("Resume Monitoring", self)
        self._resume_action.triggered.connect(self._resume_monitoring)
        self._resume_action.setVisible(False)
        menu.addAction(self._resume_action)

        menu.addSeparator()

        self._autostart_action = QAction("", self)
        self._autostart_action.triggered.connect(self._toggle_autostart)
        menu.addAction(self._autostart_action)
        self._refresh_autostart_label()

        menu.addSeparator()

        exit_action = QAction("Exit NetGuard", self)
        exit_action.triggered.connect(self._exit_netguard)
        menu.addAction(exit_action)

        self._tray.setContextMenu(menu)
        # Double-click reopens the dashboard
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self._open_dashboard()

    def _open_dashboard(self):
        """Restore and bring the main window to the front."""
        self.showMaximized()
        self.raise_()
        self.activateWindow()

    def _pause_monitoring(self):
        """Tell the backend to pause its monitoring loop."""
        api_post("/monitoring/toggle", {"active": False})
        self._monitoring_paused = True
        self._pause_action.setVisible(False)
        self._resume_action.setVisible(True)
        self._tray.setIcon(_create_tray_icon(paused=True))
        self._tray.setToolTip("NetGuard — Network Security Monitor\nMonitoring PAUSED")

    def _resume_monitoring(self):
        """Tell the backend to resume its monitoring loop."""
        api_post("/monitoring/toggle", {"active": True})
        self._monitoring_paused = False
        self._resume_action.setVisible(False)
        self._pause_action.setVisible(True)
        self._tray.setIcon(_create_tray_icon(paused=False))
        self._tray.setToolTip("NetGuard — Network Security Monitor\nMonitoring active")

    def _refresh_autostart_label(self):
        """Update the auto-start menu item text to reflect current state."""
        if not hasattr(self, "_autostart_action"):
            return
        try:
            from autostart import is_autostart_enabled
            enabled = is_autostart_enabled()
        except Exception:
            enabled = False
        self._autostart_action.setText(
            "Disable Auto-Start on Boot" if enabled else "Enable Auto-Start on Boot"
        )

    def _toggle_autostart(self):
        """Enable or disable Windows startup shortcut and refresh label."""
        try:
            from autostart import is_autostart_enabled, enable_autostart, disable_autostart
            if is_autostart_enabled():
                result = disable_autostart()
                verb = "disabled"
            else:
                result = enable_autostart()
                verb = "enabled"
            if result.get("ok"):
                self._refresh_autostart_label()
                QMessageBox.information(
                    self, "Auto-Start",
                    f"Auto-Start has been {verb}.\n"
                    + ("NetGuard will launch minimized to tray on Windows boot."
                       if verb == "enabled" else
                       "NetGuard will no longer start automatically.")
                )
            else:
                QMessageBox.warning(
                    self, "Auto-Start Error",
                    f"Could not {verb[:-1]} auto-start:\n{result.get('error', 'Unknown error')}"
                )
        except Exception as exc:
            QMessageBox.warning(self, "Auto-Start Error", str(exc))

    def _exit_netguard(self):
        """
        Clean shutdown sequence:
        1. Stop the DataFetcher polling thread.
        2. Ask the backend to shut down gracefully (closes aiohttp, stops loops).
        3. Hide and destroy the tray icon.
        4. Quit the Qt application.
        """
        # 1. Stop the background polling thread
        self.fetcher.stop()
        self.fetcher.wait(2000)

        # 2. Ask the backend to shut down (best-effort — ignore if already down)
        try:
            api_post("/shutdown", {})
        except Exception:
            pass

        # 3. Remove tray icon
        if hasattr(self, "_tray"):
            self._tray.hide()

        # 4. Exit the Qt event loop
        QApplication.quit()

    # ── Close-to-tray ────────────────────────────────────────────────

    def closeEvent(self, event):
        """Hide to tray instead of quitting; show a one-time balloon message."""
        if hasattr(self, "_tray") and self._tray.isVisible():
            event.ignore()        # don't close — just hide
            self.hide()
            if self._tray_first_hide:
                self._tray_first_hide = False
                self._tray.showMessage(
                    "NetGuard is still running",
                    "Monitoring continues in the background.\n"
                    "Right-click the tray icon to pause or exit.",
                    QSystemTrayIcon.Information,
                    4000,
                )
        else:
            # Tray not available: do a clean exit
            self._exit_netguard()
            event.accept()


# ─── Entry Point ──────────────────────────────────────────────────────

def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setApplicationName("NetGuard")
    # Prevent Qt from quitting when the last window is hidden (tray mode)
    app.setQuitOnLastWindowClosed(False)

    global _SCALE, STYLESHEET
    screen = app.primaryScreen()
    if screen:
        geom = screen.availableGeometry()
        _SCALE = max(0.8, min(1.5, min(geom.width() / 1920, geom.height() / 1080)))
    STYLESHEET = _build_stylesheet()

    window = MainWindow()

    # --minimized: launched from Windows startup shortcut → go straight to tray
    if "--minimized" in sys.argv:
        window._tray_first_hide = False   # suppress the balloon on auto-start
    else:
        window.showMaximized()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
