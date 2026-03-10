"""
fim/alerter.py - Alert system for GuardianFIM
"""

from enum import IntEnum


class AlertLevel(IntEnum):
    ALL = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


SEVERITY_LEVEL = {
    "CRITICAL": AlertLevel.CRITICAL,
    "HIGH": AlertLevel.HIGH,
    "MEDIUM": AlertLevel.MEDIUM,
    "LOW": AlertLevel.ALL,
}

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # Red
    "HIGH": "\033[93m",       # Yellow
    "MEDIUM": "\033[94m",     # Blue
    "LOW": "\033[92m",        # Green
    "RESET": "\033[0m"
}


class Alerter:
    """Handles real-time alert output for detected file changes."""

    def __init__(self):
        self.alert_count = 0

    def alert(self, finding: dict, min_level: str = "all"):
        """
        Print an alert if the finding meets the minimum severity threshold.

        Args:
            finding: Dict with keys: severity, type, path, detail
            min_level: Minimum alert level string ('all', 'medium', 'high', 'critical')
        """
        level_map = {
            "all": AlertLevel.ALL,
            "medium": AlertLevel.MEDIUM,
            "high": AlertLevel.HIGH,
            "critical": AlertLevel.CRITICAL,
        }
        min_alert = level_map.get(min_level.lower(), AlertLevel.ALL)
        finding_level = SEVERITY_LEVEL.get(finding["severity"], AlertLevel.ALL)

        if finding_level >= min_alert:
            self.alert_count += 1
            self._print_alert(finding)

    def _print_alert(self, finding: dict):
        sev = finding["severity"]
        color = SEVERITY_COLOR.get(sev, "")
        reset = SEVERITY_COLOR["RESET"]

        icons = {
            "MODIFIED": "⚡",
            "DELETED": "🗑 ",
            "NEW_FILE": "📄",
            "PERMISSION_CHANGED": "🔐",
            "UNREADABLE": "🚫",
        }
        icon = icons.get(finding["type"], "⚠ ")

        print(f"  {color}[ALERT] {icon} {sev} — {finding['type']}{reset}")
        print(f"         Path: {finding['path']}")
        print(f"         {finding['detail']}")
