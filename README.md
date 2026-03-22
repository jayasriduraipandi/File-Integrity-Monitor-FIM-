# ⛨ GuardianFIM — File Integrity Monitor

[![CI](https://github.com/yourusername/GuardianFIM/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/GuardianFIM/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/cybersecurity-FIM-red.svg)]()

> **GuardianFIM** is a cybersecurity tool that detects unauthorized file changes using cryptographic hashing (SHA-256/512, MD5). It creates a trusted baseline snapshot of your filesystem, then continuously monitors for modifications, deletions, new files, and permission changes — alerting you immediately when tampering is detected.

## 🔍 What is File Integrity Monitoring?

File Integrity Monitoring (FIM) is a core cybersecurity technique used to detect:

| Threat | Example |
|---|---|
| 🔴 Malware injection | Attacker modifies a system binary |
| 🟠 Ransomware activity | Files being encrypted |
| 🟠 Unauthorized access | Config files altered by insider threat |
| 🟡 Compliance drift | System files changed without a change ticket |
| 🟡 Rootkit detection | Hidden files modifying core OS files |

FIM is required by **PCI-DSS (Req. 11.5)**, **HIPAA**, **SOC 2**, **ISO 27001**, and **NIST SP 800-53**.

---

## ✨ Features

- 🔐 **Cryptographic hashing** — SHA-256, SHA-512, MD5
- 📸 **Baseline snapshots** — create a trusted reference state
- 🔍 **Integrity scanning** — detect modified, deleted, new, and permission-changed files
- 👁️ **Watch mode** — real-time continuous monitoring
- 📊 **HTML reports** — beautiful dark-mode scan dashboards
- 📧 **Email alerts** — SMTP notifications for violations
- ⚙️ **YAML config** — flexible, version-controllable configuration
- ✅ **Full test suite** — 20+ unit & integration tests
- 🔄 **CI/CD ready** — GitHub Actions across 3 OS × 5 Python versions

---

## 📁 Project Structure

```
GuardianFIM/
├── guardian_fim.py          # CLI entry point
├── fim/
│   ├── __init__.py
│   ├── hasher.py            # Cryptographic hashing utilities
│   ├── monitor.py           # Core baseline/scan/watch logic
│   ├── alerter.py           # Alert output system
│   ├── reporter.py          # HTML/JSON/TXT report generation
│   └── config.py            # YAML configuration management
├── tests/
│   ├── test_hasher.py       # Unit tests for hashing
│   └── test_monitor.py      # Integration tests for monitor
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions CI pipeline
├── config.yaml              # Default configuration
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/GuardianFIM.git
cd GuardianFIM

# Install dependencies
pip install -r requirements.txt

# (Optional) Install as a CLI tool
pip install -e .
```

### 2. Create a Baseline

Snapshot all files in `/etc` and your web root:

```bash
python guardian_fim.py baseline /etc /var/www/html \
    --output baseline.json \
    --algo sha256 \
    --exclude "*.log" "*.tmp" "*.pid"
```

**Output:**
```
[*] Creating baseline with algorithm: SHA256
[*] Scanning paths: ['/etc', '/var/www/html']
[+] Found 342 files to hash...

  [████████████████████████████████████████] 100% 342/342

[+] Hashed 340 files (2 skipped)
[✔] Baseline saved to: /your/path/baseline.json
```

### 3. Run a Scan

Compare current state against your baseline:

```bash
python guardian_fim.py scan --baseline baseline.json --report reports/scan.html
```

**Output:**
```
════════════════════════════════════════════════════════════
  SCAN COMPLETE — 2025-01-15T14:32:11Z
════════════════════════════════════════════════════════════
  ✔  Unchanged    : 338
  ⚠  Modified     : 1    (CRITICAL)
  ✚  New Files    : 0    (HIGH)
  ✘  Deleted      : 1    (HIGH)
  🔐 Perm Changed  : 0   (MEDIUM)
────────────────────────────────────────────────────────────
  [!] TOTAL FINDINGS: 2

  🔴 [CRITICAL] MODIFIED
       Path: /etc/passwd
       File hash mismatch — content changed
       Baseline : a3f1c2b4d5e6f7a8...
       Current  : 9b2c4d6e8f1a3c5e...

  🟠 [HIGH] DELETED
       Path: /var/www/html/index.php
       File was deleted since baseline was created
════════════════════════════════════════════════════════════
```

### 4. Watch Mode (Continuous Monitoring)

```bash
python guardian_fim.py watch --baseline baseline.json --interval 60
```

Scans every 60 seconds, logging all changes to `logs/guardian.log`.

### 5. Generate Reports

```bash
# HTML report (dark-mode dashboard)
python guardian_fim.py report scan_result.json --format html --output reports/report

# JSON report (for SIEM integration)
python guardian_fim.py report scan_result.json --format json --output reports/report

# Plain text report
python guardian_fim.py report scan_result.json --format txt --output reports/report
```

---

## ⚙️ Configuration

Edit `config.yaml`:

```yaml
default_algorithm: sha256     # sha256 | sha512 | md5
default_baseline: baseline.json
watch_interval: 30            # seconds between scans

email:
  enabled: true
  smtp_host: smtp.gmail.com
  smtp_port: 587
  from: guardian@yourcompany.com
  to: security-team@yourcompany.com
  username: your_email@gmail.com
  password: your_app_password  # Use Gmail App Password
```

---

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=fim --cov-report=html

# Run specific test file
pytest tests/test_hasher.py -v
```

---

## 📋 Command Reference

| Command | Description |
|---|---|
| `baseline <paths>` | Create integrity baseline |
| `scan` | One-time scan against baseline |
| `watch` | Continuous real-time monitoring |
| `report <file>` | Generate report from scan result |
| `config` | Show active configuration |

### Options

```
baseline:
  --output/-o    Output file (default: baseline.json)
  --algo         sha256 | sha512 | md5 (default: sha256)
  --exclude      Glob patterns to exclude (e.g., *.log *.tmp)

scan:
  --baseline/-b  Baseline file to compare (default: baseline.json)
  --report/-r    Save results to file (.html or .json)
  --alert-level  all | medium | high | critical
  --email        Send email alert

watch:
  --baseline/-b  Baseline file
  --interval/-i  Seconds between scans (default: 30)
  --log/-l       Log file path
```

---

## 🛡️ Use Cases

### Detect Web Shell Injection
```bash
# Baseline your web root
python guardian_fim.py baseline /var/www/html --output webroot_baseline.json

# Scan hourly via cron
0 * * * * python /opt/GuardianFIM/guardian_fim.py scan \
  --baseline /opt/GuardianFIM/webroot_baseline.json \
  --report /var/log/fim/scan_$(date +\%Y\%m\%d_\%H\%M).html \
  --email
```

### Protect Configuration Files
```bash
python guardian_fim.py baseline /etc/nginx /etc/ssh /etc/hosts \
  --output config_baseline.json --algo sha512
```

### Compliance Monitoring (PCI-DSS)
```bash
python guardian_fim.py watch \
  --baseline pci_baseline.json \
  --interval 300 \
  --log /var/log/guardian_pci.log
```

---

## 🔒 Security Considerations

- **Protect your baseline**: Store `baseline.json` in a read-only or write-protected location, or sign it with GPG to prevent tampering.
- **Use SHA-256 or SHA-512**: MD5 is provided for legacy compatibility but is cryptographically weak for security-critical use cases.
- **Run with least privilege**: The monitor only needs read access to monitored paths.
- **Separate baseline storage**: Ideally store baselines on a separate, isolated system.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-alert-channel`
3. Add tests for your feature
4. Ensure `pytest tests/ -v` passes
5. Submit a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🔗 Related Tools & Standards

- [AIDE](https://aide.github.io/) — Advanced Intrusion Detection Environment
- [Tripwire](https://www.tripwire.com/) — Commercial FIM
- [OSSEC](https://www.ossec.net/) — Open Source HIDS with FIM
- [NIST SP 800-53 SI-7](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — Software, Firmware, and Information Integrity
- [PCI-DSS v4.0 Req 11.5](https://www.pcisecuritystandards.org/)
