"""
fim/config.py - Configuration management for GuardianFIM
"""

import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    "default_algorithm": "sha256",
    "default_baseline": "baseline.json",
    "watch_interval": 30,
    "log_file": "logs/guardian.log",
    "report_dir": "reports",
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "from": "guardian@example.com",
        "to": "admin@example.com",
        "username": "your_email@gmail.com",
        "password": "your_app_password",
    }
}

CONFIG_FILE = "config.yaml"


class Config:
    def __init__(self, config_path: str = CONFIG_FILE):
        self.path = config_path
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            with open(self.path) as f:
                loaded = yaml.safe_load(f) or {}
            # Deep merge with defaults
            return self._merge(DEFAULT_CONFIG, loaded)
        return DEFAULT_CONFIG.copy()

    def _merge(self, base: dict, override: dict) -> dict:
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def show(self):
        print("\n[GuardianFIM Configuration]")
        print(f"  Config file: {Path(self.path).resolve()}")
        print(f"  Algorithm  : {self.data.get('default_algorithm')}")
        print(f"  Baseline   : {self.data.get('default_baseline')}")
        print(f"  Interval   : {self.data.get('watch_interval')}s")
        print(f"  Log file   : {self.data.get('log_file')}")
        print(f"  Report dir : {self.data.get('report_dir')}")
        email = self.data.get("email", {})
        print(f"  Email alerts: {'enabled' if email.get('enabled') else 'disabled'}")
        if email.get("enabled"):
            print(f"    SMTP: {email.get('smtp_host')}:{email.get('smtp_port')}")
            print(f"    To  : {email.get('to')}")
        print()
