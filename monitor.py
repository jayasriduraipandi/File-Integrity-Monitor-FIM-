"""
fim/monitor.py - Core File Integrity Monitor logic
"""

import json
import os
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from fim.hasher import hash_file, get_file_metadata, collect_files
from fim.alerter import Alerter, AlertLevel


class FileIntegrityMonitor:
    def __init__(self, config):
        self.config = config
        self.alerter = Alerter()

    # ─────────────────────────────────────────────────────────────────
    # BASELINE
    # ─────────────────────────────────────────────────────────────────

    def create_baseline(self, paths: list, output: str, algo: str = "sha256", exclude: list = None):
        """
        Create a cryptographic baseline of all files in the given paths.
        """
        print(f"\n[*] Creating baseline with algorithm: {algo.upper()}")
        print(f"[*] Scanning paths: {paths}")
        if exclude:
            print(f"[*] Excluding patterns: {exclude}")
        print()

        files = collect_files(paths, exclude_patterns=exclude)
        total = len(files)
        print(f"[+] Found {total} files to hash...\n")

        baseline = {
            "meta": {
                "created_at": datetime.utcnow().isoformat() + "Z",
                "algorithm": algo,
                "paths": paths,
                "exclude": exclude or [],
                "total_files": total,
                "tool": "GuardianFIM v1.0",
            },
            "files": {}
        }

        failed = 0
        for i, filepath in enumerate(files, 1):
            digest = hash_file(filepath, algo)
            if digest is None:
                print(f"  [!] SKIP (unreadable): {filepath}")
                failed += 1
                continue

            metadata = get_file_metadata(filepath)
            baseline["files"][filepath] = {
                "hash": digest,
                "size": metadata.get("size"),
                "permissions": metadata.get("permissions"),
                "modified": metadata.get("modified"),
            }

            bar = self._progress_bar(i, total)
            print(f"\r  {bar} {i}/{total}", end="", flush=True)

        print(f"\n\n[+] Hashed {total - failed} files ({failed} skipped)")

        # Save baseline
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(baseline, f, indent=2)

        print(f"[✔] Baseline saved to: {output_path.resolve()}")
        print(f"[i] Algorithm: {algo.upper()} | Files: {total - failed} | Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

    # ─────────────────────────────────────────────────────────────────
    # SCAN
    # ─────────────────────────────────────────────────────────────────

    def scan(self, baseline_path: str, alert_level: str = "all") -> dict:
        """
        Compare current file state against a baseline.
        Returns a structured results dict with all findings.
        """
        print(f"\n[*] Loading baseline: {baseline_path}")
        baseline = self._load_baseline(baseline_path)
        if not baseline:
            return {}

        algo = baseline["meta"]["algorithm"]
        paths = baseline["meta"]["paths"]
        exclude = baseline["meta"].get("exclude", [])

        print(f"[*] Algorithm: {algo.upper()} | Baseline date: {baseline['meta']['created_at']}")
        print(f"[*] Paths: {paths}\n")

        # Collect current state
        current_files = set(collect_files(paths, exclude_patterns=exclude))
        baseline_files = set(baseline["files"].keys())

        results = {
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "baseline_time": baseline["meta"]["created_at"],
            "algorithm": algo,
            "summary": {
                "modified": 0,
                "added": 0,
                "deleted": 0,
                "permission_changed": 0,
                "unchanged": 0,
            },
            "findings": []
        }

        # Check existing baseline files
        for filepath in sorted(baseline_files):
            base_entry = baseline["files"][filepath]

            if filepath not in current_files:
                # File was deleted
                results["summary"]["deleted"] += 1
                finding = {
                    "severity": "HIGH",
                    "type": "DELETED",
                    "path": filepath,
                    "detail": "File was deleted since baseline was created",
                    "baseline_hash": base_entry["hash"],
                    "current_hash": None,
                }
                results["findings"].append(finding)
                self.alerter.alert(finding, alert_level)
            else:
                # File exists — compare hash
                current_hash = hash_file(filepath, algo)
                current_meta = get_file_metadata(filepath)

                if current_hash is None:
                    finding = {
                        "severity": "MEDIUM",
                        "type": "UNREADABLE",
                        "path": filepath,
                        "detail": "File exists but cannot be read",
                        "baseline_hash": base_entry["hash"],
                        "current_hash": None,
                    }
                    results["findings"].append(finding)
                    self.alerter.alert(finding, alert_level)
                elif current_hash != base_entry["hash"]:
                    results["summary"]["modified"] += 1
                    finding = {
                        "severity": "CRITICAL",
                        "type": "MODIFIED",
                        "path": filepath,
                        "detail": "File hash mismatch — content changed",
                        "baseline_hash": base_entry["hash"],
                        "current_hash": current_hash,
                        "baseline_size": base_entry.get("size"),
                        "current_size": current_meta.get("size"),
                    }
                    results["findings"].append(finding)
                    self.alerter.alert(finding, alert_level)
                else:
                    # Hash matches — check permission changes
                    if (base_entry.get("permissions") and
                            current_meta.get("permissions") and
                            base_entry["permissions"] != current_meta["permissions"]):
                        results["summary"]["permission_changed"] += 1
                        finding = {
                            "severity": "MEDIUM",
                            "type": "PERMISSION_CHANGED",
                            "path": filepath,
                            "detail": f"Permissions changed: {base_entry['permissions']} → {current_meta['permissions']}",
                            "baseline_hash": base_entry["hash"],
                            "current_hash": current_hash,
                        }
                        results["findings"].append(finding)
                        self.alerter.alert(finding, alert_level)
                    else:
                        results["summary"]["unchanged"] += 1

        # Check for new files
        new_files = current_files - baseline_files
        for filepath in sorted(new_files):
            results["summary"]["added"] += 1
            current_hash = hash_file(filepath, algo)
            finding = {
                "severity": "HIGH",
                "type": "NEW_FILE",
                "path": filepath,
                "detail": "New file found that was not in baseline",
                "baseline_hash": None,
                "current_hash": current_hash,
            }
            results["findings"].append(finding)
            self.alerter.alert(finding, alert_level)

        self._print_scan_summary(results)
        return results

    # ─────────────────────────────────────────────────────────────────
    # WATCH (Continuous Monitoring)
    # ─────────────────────────────────────────────────────────────────

    def watch(self, baseline_path: str, interval: int = 30, log_file: str = "logs/guardian.log"):
        """
        Continuously monitor files, re-scanning at each interval.
        """
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

        logging.info("GuardianFIM watch mode started")
        logging.info(f"Baseline: {baseline_path} | Interval: {interval}s | Log: {log_file}")
        print(f"\n[*] Watch mode active. Scanning every {interval} seconds. Press Ctrl+C to stop.\n")

        scan_count = 0
        try:
            while True:
                scan_count += 1
                print(f"\n{'─'*60}")
                print(f"  SCAN #{scan_count} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'─'*60}")

                results = self.scan(baseline_path)
                total_findings = len(results.get("findings", []))

                if total_findings > 0:
                    logging.warning(f"Scan #{scan_count}: {total_findings} finding(s) detected!")
                    for finding in results["findings"]:
                        logging.warning(f"  [{finding['severity']}] {finding['type']}: {finding['path']}")
                else:
                    logging.info(f"Scan #{scan_count}: All files intact.")

                print(f"\n[zzz] Next scan in {interval} seconds...")
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n\n[*] Watch mode stopped by user.")
            logging.info("GuardianFIM watch mode stopped.")

    # ─────────────────────────────────────────────────────────────────
    # EMAIL ALERT
    # ─────────────────────────────────────────────────────────────────

    def send_email_alert(self, results: dict, config):
        """Send email notification for scan findings."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        cfg = config.data.get("email", {})
        if not cfg.get("enabled"):
            print("[!] Email alerts are disabled in config.yaml")
            return

        findings = results.get("findings", [])
        if not findings:
            print("[i] No findings — skipping email alert.")
            return

        subject = f"[GuardianFIM] {len(findings)} integrity issue(s) detected"
        body_lines = [f"GuardianFIM Scan Report — {results['scan_time']}\n"]
        for f in findings:
            body_lines.append(f"[{f['severity']}] {f['type']}: {f['path']}")
            body_lines.append(f"  Detail: {f['detail']}\n")

        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = cfg["from"]
        msg["To"] = cfg["to"]
        msg.attach(MIMEText("\n".join(body_lines), "plain"))

        try:
            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 587)) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.send_message(msg)
            print(f"[✔] Email alert sent to {cfg['to']}")
        except Exception as e:
            print(f"[✘] Failed to send email: {e}")

    # ─────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────

    def _load_baseline(self, path: str) -> Optional[dict]:
        if not os.path.exists(path):
            print(f"[✘] Baseline file not found: {path}")
            print("[i] Run 'guardian_fim.py baseline <path>' first.")
            return None
        with open(path) as f:
            return json.load(f)

    def _progress_bar(self, current: int, total: int, width: int = 40) -> str:
        filled = int(width * current / total)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * current / total)
        return f"[{bar}] {pct}%"

    def _print_scan_summary(self, results: dict):
        s = results["summary"]
        findings = results["findings"]
        print(f"\n{'═'*60}")
        print(f"  SCAN COMPLETE — {results['scan_time']}")
        print(f"{'═'*60}")
        print(f"  ✔  Unchanged    : {s['unchanged']}")
        print(f"  ⚠  Modified     : {s['modified']}   (CRITICAL)")
        print(f"  ✚  New Files    : {s['added']}      (HIGH)")
        print(f"  ✘  Deleted      : {s['deleted']}    (HIGH)")
        print(f"  🔐 Perm Changed  : {s['permission_changed']}  (MEDIUM)")
        print(f"{'─'*60}")

        if not findings:
            print("  [✔] NO INTEGRITY VIOLATIONS FOUND")
        else:
            print(f"  [!] TOTAL FINDINGS: {len(findings)}")
            print()
            for finding in findings:
                sev = finding["severity"]
                color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "⚪")
                print(f"  {color} [{sev}] {finding['type']}")
                print(f"       Path: {finding['path']}")
                print(f"       {finding['detail']}")
                if finding.get("baseline_hash"):
                    print(f"       Baseline : {finding['baseline_hash'][:32]}...")
                if finding.get("current_hash"):
                    print(f"       Current  : {finding['current_hash'][:32]}...")
                print()
        print(f"{'═'*60}\n")
