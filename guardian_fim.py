#!/usr/bin/env python3
"""
GuardianFIM - File Integrity Monitor
A cybersecurity tool to detect unauthorized file changes using cryptographic hashes.
"""

import argparse
import sys
import os
from fim.monitor import FileIntegrityMonitor
from fim.reporter import Reporter
from fim.config import Config

BANNER = r"""
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗    ███████╗██╗███╗   ███╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║    ██╔════╝██║████╗ ████║
██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║    █████╗  ██║██╔████╔██║
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║    ██╔══╝  ██║██║╚██╔╝██║
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║    ██║     ██║██║ ╚═╝ ██║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝╚═╝     ╚═╝
                        File Integrity Monitor v1.0 | Cybersecurity Tool
"""


def print_banner():
    print(BANNER)
    print("=" * 90)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="GuardianFIM - Detect unauthorized file changes using cryptographic hashing",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- BASELINE command ---
    baseline_parser = subparsers.add_parser("baseline", help="Create a new integrity baseline")
    baseline_parser.add_argument(
        "paths", nargs="+",
        help="Files or directories to include in the baseline"
    )
    baseline_parser.add_argument(
        "--output", "-o", default="baseline.json",
        help="Output file for the baseline (default: baseline.json)"
    )
    baseline_parser.add_argument(
        "--algo", choices=["sha256", "sha512", "md5"], default="sha256",
        help="Hashing algorithm to use (default: sha256)"
    )
    baseline_parser.add_argument(
        "--exclude", nargs="*", default=[],
        help="Patterns to exclude (e.g. *.log *.tmp)"
    )

    # --- SCAN command ---
    scan_parser = subparsers.add_parser("scan", help="Scan against a baseline and detect changes")
    scan_parser.add_argument(
        "--baseline", "-b", default="baseline.json",
        help="Baseline file to compare against (default: baseline.json)"
    )
    scan_parser.add_argument(
        "--report", "-r", default=None,
        help="Output report file (HTML or JSON based on extension)"
    )
    scan_parser.add_argument(
        "--alert-level", choices=["all", "critical", "high", "medium"], default="all",
        help="Minimum alert level to display"
    )
    scan_parser.add_argument(
        "--email", action="store_true",
        help="Send email alert (configure in config.yaml)"
    )

    # --- WATCH command ---
    watch_parser = subparsers.add_parser("watch", help="Continuously monitor files in real-time")
    watch_parser.add_argument(
        "--baseline", "-b", default="baseline.json",
        help="Baseline file to compare against (default: baseline.json)"
    )
    watch_parser.add_argument(
        "--interval", "-i", type=int, default=30,
        help="Scan interval in seconds (default: 30)"
    )
    watch_parser.add_argument(
        "--log", "-l", default="logs/guardian.log",
        help="Log file path (default: logs/guardian.log)"
    )

    # --- REPORT command ---
    report_parser = subparsers.add_parser("report", help="Generate a report from scan results")
    report_parser.add_argument(
        "scan_result",
        help="JSON scan result file to generate report from"
    )
    report_parser.add_argument(
        "--format", "-f", choices=["html", "json", "txt"], default="html",
        help="Report format (default: html)"
    )
    report_parser.add_argument(
        "--output", "-o", default="reports/report",
        help="Output file path (without extension)"
    )

    # --- CONFIG command ---
    subparsers.add_parser("config", help="Show current configuration")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = Config()
    fim = FileIntegrityMonitor(config)
    reporter = Reporter()

    if args.command == "baseline":
        fim.create_baseline(
            paths=args.paths,
            output=args.output,
            algo=args.algo,
            exclude=args.exclude
        )

    elif args.command == "scan":
        results = fim.scan(
            baseline_path=args.baseline,
            alert_level=args.alert_level
        )
        if args.report:
            ext = os.path.splitext(args.report)[1].lower()
            fmt = "html" if ext == ".html" else "json"
            reporter.generate(results, args.report, fmt)
        if args.email:
            fim.send_email_alert(results, config)

    elif args.command == "watch":
        fim.watch(
            baseline_path=args.baseline,
            interval=args.interval,
            log_file=args.log
        )

    elif args.command == "report":
        import json
        with open(args.scan_result) as f:
            results = json.load(f)
        output_path = f"{args.output}.{args.format}"
        reporter.generate(results, output_path, args.format)

    elif args.command == "config":
        config.show()


if __name__ == "__main__":
    main()
