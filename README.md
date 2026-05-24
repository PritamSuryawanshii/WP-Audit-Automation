# WP Audit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Framework-WordPress%20Security-darkred?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Penetration%20Testing-black?style=for-the-badge">
</p>

<p align="center">
  <b>WordPress Penetration Testing & Security Assessment Framework</b>
</p>

<p align="center">
  Automated reconnaissance, exposure detection, vulnerability assessment, and attack surface analysis for WordPress environments.
</p>

<p align="center">
  Built with assistance from <b>Claude Code AI</b> for rapid security automation development and assessment workflow engineering.
</p>

---

## 🔍 Overview

WP Audit is a modern WordPress security assessment framework designed for penetration testers, security researchers, and AppSec professionals.

The framework automates identification of high-risk WordPress misconfigurations, exposed backup artifacts, sensitive files, vulnerable plugin exposure, enumeration vectors, and insecure deployment practices commonly observed during real-world security assessments.

Built with a focus on:

- Accurate detection logic
- Reduced false positives
- Structured reporting
- CVSS-based severity classification
- Professional terminal output
- Lightweight automation workflows

---

# ⚡ Features

## 🛡️ Information Disclosure

- WordPress version disclosure detection
- Meta generator fingerprinting
- Username enumeration vectors
- REST API exposure analysis
- RSS feed user disclosure checks

---

## 📦 Backup & Sensitive Data Exposure

- `wp-config.php` backup discovery
- Duplicator installer exposure
- Public backup archive detection
- UpdraftPlus backup exposure
- Database dump discovery
- Archive and configuration file exposure

---

## ⚙️ Misconfiguration Detection

- Directory listing analysis
- XML-RPC attack surface validation
- WP-Cron exposure checks
- Debug and error log exposure
- `.git` repository disclosure

---

## 🧬 Uploads & Webshell Hunting

- PHP execution inside uploads
- Suspicious executable file discovery
- Sensitive file enumeration
- Potential webshell detection

---

## 🔌 Plugin Security Checks

- Really Simple SSL vulnerability probing
- LoginPress version analysis
- Elementor REST API exposure
- Wordfence version auditing
- Loco Translate version auditing

---

## 📊 Reporting

- CVSS scoring
- CWE mapping
- Technical evidence collection
- Structured remediation guidance
- JSON export support
- Risk-based finding prioritization

---

# 🚀 Installation

## Requirements

- Python 3.9+
- requests
- beautifulsoup4
- lxml

## Install Dependencies

```bash
pip install requests beautifulsoup4 lxml
```

---

# 🖥️ Usage

## Basic Scan

```bash
python3 wp_audit.py https://target.com
```

## Scan with Custom Delay

```bash
python3 wp_audit.py https://target.com --delay 1.0
```

## Export JSON Report

```bash
python3 wp_audit.py https://target.com --output report.json
```

## Disable Colored Output

```bash
python3 wp_audit.py https://target.com --no-color
```

---

# ⚙️ Command Line Options

| Option | Description |
|---|---|
| `--delay FLOAT` | Delay between requests |
| `--timeout INT` | HTTP timeout in seconds |
| `--output FILE` | Export findings to JSON |
| `--no-color` | Disable terminal colors |

---

# 🧪 Example Findings

```text
[CRITICAL] wp-config.php Backup File Publicly Accessible
[CRITICAL] Duplicator Backup Archive Publicly Accessible
[HIGH] XML-RPC Interface Enabled
[HIGH] Public Debug Log Exposure
[MEDIUM] Username Enumeration Detected
[LOW] WP-Cron Publicly Accessible
```

---

# 📌 Assessment Coverage

| Category | Coverage |
|---|---|
| Information Disclosure | Version leakage, REST API, logs |
| Backup Exposure | SQL dumps, archives, migration artifacts |
| Misconfiguration | XML-RPC, directory listing, WP-Cron |
| Sensitive Files | `.env`, `.git`, config leaks |
| Enumeration | Users, authors, feeds |
| Plugin Security | Outdated plugins, vulnerable endpoints |
| Upload Security | PHP execution, malicious uploads |

---

# 🔄 Assessment Workflow

```text
Target Enumeration
        ↓
WordPress Fingerprinting
        ↓
Exposure Discovery
        ↓
Plugin & Endpoint Validation
        ↓
Risk Classification
        ↓
Structured Security Report
```

---

# 📁 Example Project Structure

```bash
WP-Audit/
├── wp_audit.py
├── reports/
│   └── report.json
├── requirements.txt
└── README.md
```

---

# 🎯 Designed For

- Penetration Testers
- Bug Bounty Hunters
- Security Researchers
- AppSec Engineers
- Red Team Assessments
- Internal Security Audits

---

# 👨‍💻 Development

This project was engineered with assistance from **Claude Code AI** to accelerate secure tooling development, workflow automation, and large-scale security assessment logic.

The framework combines manual security research methodologies with AI-assisted development workflows to improve testing efficiency and coverage.
