#!/usr/bin/env python3
"""
wp_audit.py — WordPress Penetration Testing Automation Script
For use on authorized targets only.

Usage:
    python3 wp_audit.py <target_url> [options]

Options:
    --delay FLOAT     Seconds between requests (default: 0.5)
    --timeout INT     Request timeout in seconds (default: 15)
    --output FILE     Save JSON report to file
    --no-color        Disable terminal colors

Dependencies:
    pip install requests beautifulsoup4 lxml
"""

import sys
import json
import time
import argparse
import urllib.parse
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

try:
    import requests
    from bs4 import BeautifulSoup
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
except ImportError:
    print("[!] Missing dependencies. Run: pip install requests beautifulsoup4 lxml")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title:          str
    risk:           str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss_score:     str
    cvss_vector:    str
    cwe:            str
    description:    str
    evidence:       str
    recommendation: str
    url:            str = ""
    check_name:     str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Colour / Terminal Helpers
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    CRITICAL = "\033[91m"
    HIGH     = "\033[93m"
    MEDIUM   = "\033[94m"
    LOW      = "\033[96m"
    INFO     = "\033[37m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    GREEN    = "\033[92m"
    RESET    = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ("CRITICAL","HIGH","MEDIUM","LOW","INFO","BOLD","DIM","GREEN","RESET"):
            setattr(cls, attr, "")


# ─────────────────────────────────────────────────────────────────────────────
# Core Auditor
# ─────────────────────────────────────────────────────────────────────────────

class WPAudit:

    RISK_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    RISK_COLOR = {
        "CRITICAL": Colors.CRITICAL,
        "HIGH":     Colors.HIGH,
        "MEDIUM":   Colors.MEDIUM,
        "LOW":      Colors.LOW,
        "INFO":     Colors.INFO,
    }

    def __init__(self, base_url: str, timeout: int = 15,
                 delay: float = 0.5, output_file: Optional[str] = None):
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.delay       = delay
        self.output_file = output_file
        self.findings: List[Finding] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        })
        self.session.verify = False

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return self.base_url + path if path.startswith("/") else path

    def _get(self, path: str, allow_redirects: bool = True,
             **kwargs) -> Optional[requests.Response]:
        try:
            resp = self.session.get(
                self._url(path),
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )
            time.sleep(self.delay)
            return resp
        except requests.exceptions.RequestException:
            return None

    def _post(self, path: str, data=None, json_body=None,
              headers: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        try:
            resp = self.session.post(
                self._url(path),
                data=data,
                json=json_body,
                headers=headers or {},
                timeout=self.timeout,
                **kwargs,
            )
            time.sleep(self.delay)
            return resp
        except requests.exceptions.RequestException:
            return None

    # ── Finding helper ────────────────────────────────────────────────────────

    def _add(self, finding: Finding):
        self.findings.append(finding)
        color = self.RISK_COLOR.get(finding.risk, "")
        print(f"    {color}{Colors.BOLD}[{finding.risk}]{Colors.RESET}  {finding.title}")

    # ── HTML / page helpers ───────────────────────────────────────────────────

    def _is_directory_listing(self, resp: requests.Response) -> bool:
        """
        Confirm directory listing using BeautifulSoup structural analysis.
        Multiple independent signals required to avoid false positives.
        """
        if resp is None or resp.status_code != 200:
            return False
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return False

        soup  = BeautifulSoup(resp.text, "lxml")
        score = 0

        # Signal 1: <title> contains "Index of"
        title = soup.find("title")
        if title and "index of" in title.get_text().lower():
            score += 3

        # Signal 2: "Parent Directory" link present
        for a in soup.find_all("a", href=True):
            if a["href"] in ("../", "/"):
                score += 2
                break

        # Signal 3: Apache / Nginx dir listing markers in body text (not attr)
        body_lower = soup.get_text().lower()
        if "last modified" in body_lower and "size" in body_lower:
            score += 2

        # Signal 4: table or pre with file entries and "name" column header
        for th in soup.find_all("th"):
            if th.get_text().strip().lower() in ("name", "last modified", "size"):
                score += 1

        # Require at least 3 points to call it a directory listing
        return score >= 3

    def _links_from_listing(self, resp: requests.Response) -> List[str]:
        """Extract listed filenames using BeautifulSoup — no string regex."""
        if resp is None:
            return []
        soup  = BeautifulSoup(resp.text, "lxml")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            # Skip navigation, absolute URLs, query strings, anchors
            if href in ("../", "./", "/") or href.startswith("?") or \
               href.startswith("http") or href.startswith("#"):
                continue
            links.append(href)
        return links

    def _parse_plugin_version(self, readme_text: str) -> Optional[str]:
        """
        Extract Stable Tag from a WordPress plugin readme.txt
        using line-by-line parsing.
        """
        for line in readme_text.splitlines():
            stripped = line.strip()
            lower    = stripped.lower()
            if lower.startswith("stable tag:"):
                candidate = stripped.split(":", 1)[1].strip()
                # Sanity-check: should look like a version (digits and dots)
                if candidate and all(c.isdigit() or c == "." for c in candidate):
                    return candidate
        return None

    def _version_lt(self, installed: str, latest: str) -> bool:
        """Compare version strings using tuple comparison — no regex."""
        def to_tuple(v: str):
            return tuple(int(x) for x in v.split(".") if x.isdigit())
        try:
            return to_tuple(installed) < to_tuple(latest)
        except (ValueError, TypeError):
            return False

    def _confirm_file_extension(self, filename: str, extensions: tuple) -> bool:
        """Check if filename ends with any of the given extensions."""
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in extensions)

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 1 — WordPress Version Disclosure
    # ─────────────────────────────────────────────────────────────────────────

    def check_version_disclosure(self):
        print("\n  [*] Version disclosure via readme.html and meta tag...")

        # readme.html
        resp = self._get("/readme.html")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            text = soup.get_text().lower()
            if "wordpress" in text:
                self._add(Finding(
                    check_name   = "version_disclosure_readme",
                    title        = "WordPress Version Disclosed via readme.html",
                    risk         = "INFO",
                    cvss_score   = "0.0",
                    cvss_vector  = "N/A",
                    cwe          = "CWE-200",
                    description  = (
                        "The readme.html file is publicly accessible and confirms the "
                        "WordPress installation. It often includes the precise version, "
                        "providing attackers with a direct CVE lookup vector."
                    ),
                    evidence     = f"HTTP 200 on /readme.html — WordPress content confirmed.",
                    recommendation = "Delete /readme.html from the server root.",
                    url          = self._url("/readme.html"),
                ))

        # Meta generator tag
        home = self._get("/")
        if home and home.status_code == 200:
            soup = BeautifulSoup(home.text, "lxml")
            gen  = soup.find("meta", attrs={"name": "generator"})
            if gen:
                content = gen.get("content", "")
                if "wordpress" in content.lower():
                    self._add(Finding(
                        check_name   = "version_disclosure_meta",
                        title        = "WordPress Version in Meta Generator Tag",
                        risk         = "INFO",
                        cvss_score   = "0.0",
                        cvss_vector  = "N/A",
                        cwe          = "CWE-200",
                        description  = "WordPress version exposed in HTML meta generator tag on the homepage.",
                        evidence     = f'<meta name="generator" content="{content}">',
                        recommendation = (
                            "Add to functions.php: "
                            "remove_action('wp_head', 'wp_generator');"
                        ),
                        url = self._url("/"),
                    ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 2 — Directory Listing (Uploads, Plugins, Themes, Backup dirs)
    # ─────────────────────────────────────────────────────────────────────────

    def check_directory_listing(self):
        print("  [*] Directory listing across sensitive paths...")

        targets = {
            "/wp-content/uploads/"  : "User-upload storage — may expose sensitive files",
            "/wp-content/plugins/"  : "Enables precise plugin version fingerprinting for CVE matching",
            "/wp-content/themes/"   : "Exposes installed themes and versions",
            "/wp-includes/"         : "WordPress core internals — path disclosure",
            "/wp-content/backup/"   : "Potential backup directory",
            "/wp-content/backups/"  : "Potential backup directory",
            "/wp-content/uploads/backupwordpress/" : "BackupWordPress default storage",
            "/wp-content/uploads/wp-db-backup/"    : "WP-DB-Backup default storage",
            "/wp-content/uploads/ai1wm-backups/"   : "All-in-One WP Migration storage",
            "/wp-content/uploads/backupbuddy_backups/" : "BackupBuddy default storage",
            "/wp-content/backups-dup-lite/"        : "Duplicator Lite backup storage",
        }

        sensitive_exts = (".sql", ".zip", ".gz", ".tar", ".bak", ".log",
                          ".env", ".conf", ".php", ".key", ".pem", ".p12")

        for path, context in targets.items():
            resp = self._get(path)
            if resp is None:
                continue

            if self._is_directory_listing(resp):
                links     = self._links_from_listing(resp)
                hot_files = [
                    lnk for lnk in links
                    if self._confirm_file_extension(lnk, sensitive_exts)
                ]
                severity = "HIGH" if hot_files else "MEDIUM"

                self._add(Finding(
                    check_name   = f"dir_listing_{path.strip('/').replace('/', '_')}",
                    title        = f"Directory Listing Enabled: {path}",
                    risk         = severity,
                    cvss_score   = "7.5" if severity == "HIGH" else "5.3",
                    cvss_vector  = (
                        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        if severity == "HIGH"
                        else "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    ),
                    cwe          = "CWE-548",
                    description  = (
                        f"Directory listing is enabled at {path}. {context}. "
                        f"{'Sensitive files are directly accessible (see Evidence).' if hot_files else f'{len(links)} entries enumerable.'}"
                    ),
                    evidence     = (
                        f"HTTP 200 with directory index at {self._url(path)}. "
                        + (f"Sensitive files found: {hot_files[:8]}" if hot_files
                           else f"Total entries: {len(links)}")
                    ),
                    recommendation = (
                        "Add 'Options -Indexes' to the Apache config or .htaccess "
                        "at the web root level to disable directory listing globally."
                    ),
                    url = self._url(path),
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 3 — wp-config Backup Files
    # ─────────────────────────────────────────────────────────────────────────

    def check_wpconfig_backups(self):
        print("  [*] Hunting wp-config backup variants...")

        candidates = [
            "/wp-config.php.bak",   "/wp-config.php~",
            "/wp-config.php.old",   "/wp-config.php.orig",
            "/wp-config.php.save",  "/wp-config.bak",
            "/wp-config.txt",       "/wp-config.php.txt",
            "/wp-config.php.zip",   "/.wp-config.php.swp",
            "/wp-config.php.1",     "/wp-config_bak.php",
        ]

        # These must ALL be present to confirm it's an actual config file
        required_markers = ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]

        for path in candidates:
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            body             = resp.text
            matched          = [m for m in required_markers if m in body]
            # Require at least 3 of the 4 markers — avoids false positives from
            # tutorial pages or cached pages that mention these strings in passing
            if len(matched) >= 3:
                self._add(Finding(
                    check_name   = "wpconfig_backup",
                    title        = "wp-config.php Backup File Publicly Accessible",
                    risk         = "CRITICAL",
                    cvss_score   = "9.8",
                    cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe          = "CWE-312",
                    description  = (
                        "A backup copy of wp-config.php is publicly accessible. "
                        "This file contains database host, name, username, and password "
                        "in cleartext — providing direct MySQL access."
                    ),
                    evidence     = (
                        f"HTTP 200 at {path}. "
                        f"Confirmed DB credential markers present: {matched}"
                    ),
                    recommendation = (
                        "Delete all wp-config backup files immediately. "
                        "Rotate all exposed database credentials. "
                        "Deny access to .bak/.old/.orig extensions at the server level."
                    ),
                    url = self._url(path),
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 4 — Duplicator Installer File Exposure
    # ─────────────────────────────────────────────────────────────────────────

    def check_duplicator_installer(self):
        print("  [*] Checking Duplicator installer file exposure...")

        installer_paths = [
            "/installer.php",
            "/installer-backup.php",
            "/dup-installer/main.installer.php",
            "/wp-content/plugins/duplicator/installer.php",
        ]

        # Confirmation markers specific to the Duplicator installer page
        dup_markers = [
            "duplicator", "dup-installer", "database setup",
            "dup_pro", "step 1 of", "wp-config",
        ]

        for path in installer_paths:
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            body_lower = resp.text.lower()
            matched    = [m for m in dup_markers if m in body_lower]
            if len(matched) >= 2:
                self._add(Finding(
                    check_name   = "duplicator_installer",
                    title        = "Duplicator Installer File Accessible (Post-Migration Artifact)",
                    risk         = "CRITICAL",
                    cvss_score   = "9.8",
                    cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe          = "CWE-538",
                    description  = (
                        "The Duplicator plugin installer file was not removed after migration. "
                        "This page exposes database credentials, allows database schema extraction, "
                        "and in some configurations permits unauthorized full site reinstallation "
                        "pointing to an attacker-controlled database."
                    ),
                    evidence     = (
                        f"HTTP 200 at {path}. "
                        f"Duplicator installer content confirmed: {matched}"
                    ),
                    recommendation = (
                        "Delete installer.php and installer-backup.php immediately. "
                        "Configure your deployment pipeline to remove these files automatically after every migration."
                    ),
                    url = self._url(path),
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 5 — Duplicator Backup Package Exposure
    # ─────────────────────────────────────────────────────────────────────────

    def check_duplicator_packages(self):
        print("  [*] Checking Duplicator backup package storage...")

        dirs_to_probe = [
            "/wp-content/backups-dup-lite/",
            "/wp-content/uploads/",
            "/wp-content/plugins/duplicator/",
            "/wp-content/backups/",
        ]

        archive_exts  = (".zip", ".daf")        # Duplicator archive formats
        db_exts       = (".sql", ".sql.gz")

        for dir_path in dirs_to_probe:
            resp = self._get(dir_path)
            if resp is None or not self._is_directory_listing(resp):
                continue

            links = self._links_from_listing(resp)

            for link in links:
                link_lower = link.lower()
                is_archive = self._confirm_file_extension(link, archive_exts)
                is_db      = self._confirm_file_extension(link, db_exts)

                if not (is_archive or is_db):
                    continue

                # Confirm it looks like a Duplicator package:
                # typical name: 20240101120000_sitename_abc123_20240101_archive.zip
                # use string operations only — split on underscores and check
                name_parts = link.replace("-", "_").split("_")
                has_ts     = any(
                    p.isdigit() and len(p) >= 8 for p in name_parts
                )
                name_lower = link.lower()
                looks_like_dup = (
                    has_ts or
                    "dup" in name_lower or
                    "duplicator" in name_lower or
                    "archive" in name_lower or
                    "backup" in name_lower
                )

                if looks_like_dup:
                    self._add(Finding(
                        check_name   = "duplicator_package",
                        title        = "Duplicator Backup Archive Publicly Accessible",
                        risk         = "CRITICAL",
                        cvss_score   = "9.1",
                        cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe          = "CWE-312",
                        description  = (
                            f"A Duplicator backup archive is accessible at {dir_path}. "
                            "These archives contain: a full database dump (all user credentials, "
                            "wp-config values), all WordPress files, and the secret keys used for "
                            "cookie/session signing."
                        ),
                        evidence     = f"File found: {link} at {self._url(dir_path)}",
                        recommendation = (
                            "Move backup storage outside the web root. "
                            "Configure Duplicator to use a private directory or cloud remote storage. "
                            "Delete existing accessible archives immediately."
                        ),
                        url = self._url(dir_path + link),
                    ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 6 — UpdraftPlus Backup Exposure
    # ─────────────────────────────────────────────────────────────────────────

    def check_updraftplus_backups(self):
        print("  [*] Checking UpdraftPlus backup directory exposure...")

        updraft_paths = [
            "/wp-content/uploads/updraft/",
            "/wp-content/updraft/",
        ]

        db_exts   = (".gz", ".sql", ".sql.gz")
        file_exts = (".zip", ".tar", ".tar.gz", ".gz", ".sql", ".bak")

        for path in updraft_paths:
            resp = self._get(path)
            if resp is None:
                continue

            if not self._is_directory_listing(resp) and resp.status_code != 200:
                continue

            listing  = self._is_directory_listing(resp)
            links    = self._links_from_listing(resp) if listing else []

            # Separate DB backups from other files — DB backups are CRITICAL
            db_files    = [
                lnk for lnk in links
                if "-db." in lnk.lower() and self._confirm_file_extension(lnk, file_exts)
            ]
            other_files = [
                lnk for lnk in links
                if self._confirm_file_extension(lnk, file_exts) and lnk not in db_files
            ]

            if db_files:
                self._add(Finding(
                    check_name   = "updraft_db_backup",
                    title        = "UpdraftPlus Database Backup Publicly Accessible",
                    risk         = "CRITICAL",
                    cvss_score   = "9.1",
                    cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe          = "CWE-312",
                    description  = (
                        "UpdraftPlus database backup files are accessible without authentication. "
                        "These files contain all WordPress user accounts, password hashes, email "
                        "addresses, plugin/theme settings, and sometimes API keys stored in the database."
                    ),
                    evidence     = f"DB backup files at {self._url(path)}: {db_files[:5]}",
                    recommendation = (
                        "Configure UpdraftPlus to use remote storage (S3, Google Drive, Dropbox). "
                        "Add .htaccess to the updraft directory: 'deny from all'. "
                        "Delete all currently exposed backup files and rotate all credentials."
                    ),
                    url = self._url(path),
                ))

            if other_files:
                self._add(Finding(
                    check_name   = "updraft_site_backup",
                    title        = "UpdraftPlus Site Backup Files Publicly Accessible",
                    risk         = "HIGH",
                    cvss_score   = "7.5",
                    cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe          = "CWE-312",
                    description  = (
                        "UpdraftPlus site backup files (plugins, themes, uploads, others) are publicly "
                        "accessible. These archives may contain configuration files, API credentials "
                        "stored in plugin settings, private uploads, and server-side file paths."
                    ),
                    evidence     = f"Backup files at {self._url(path)}: {other_files[:5]}",
                    recommendation = (
                        "Configure UpdraftPlus to store backups outside the web root or to remote storage. "
                        "Restrict direct access to the backup directory via server configuration."
                    ),
                    url = self._url(path),
                ))

            if listing and not db_files and not other_files:
                self._add(Finding(
                    check_name   = "updraft_dir_exposed",
                    title        = "UpdraftPlus Backup Directory Exposed (Currently Empty)",
                    risk         = "LOW",
                    cvss_score   = "3.1",
                    cvss_vector  = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe          = "CWE-548",
                    description  = "UpdraftPlus backup directory is publicly listable but no backup files found yet.",
                    evidence     = f"HTTP 200 with directory listing at {self._url(path)}",
                    recommendation = "Restrict access to the updraft directory preemptively via .htaccess.",
                    url = self._url(path),
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 7 — XML-RPC Interface
    # ─────────────────────────────────────────────────────────────────────────

    def check_xmlrpc(self):
        print("  [*] Testing XML-RPC interface and capabilities...")

        resp = self._get("/xmlrpc.php")
        if resp is None:
            return

        # Confirm it's actually the WP XML-RPC endpoint — two distinct signals needed
        is_xmlrpc = (
            resp.status_code in (200, 405) and (
                "XML-RPC server accepts POST requests only" in resp.text or
                "text/xml" in resp.headers.get("Content-Type", "") or
                "application/xml" in resp.headers.get("Content-Type", "")
            )
        )

        if not is_xmlrpc:
            # Final fallback: POST a method call and check for xmlrpc response
            probe_body = (
                '<?xml version="1.0"?>'
                '<methodCall><methodName>system.listMethods</methodName>'
                '<params></params></methodCall>'
            )
            probe = self._post(
                "/xmlrpc.php",
                data=probe_body,
                headers={"Content-Type": "text/xml"},
            )
            if probe is None or probe.status_code != 200:
                return
            if "<methodResponse>" not in probe.text:
                return
            resp = probe

        # Query available methods
        list_methods_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<methodCall><methodName>system.listMethods</methodName>'
            '<params></params></methodCall>'
        )
        methods_resp = self._post(
            "/xmlrpc.php",
            data=list_methods_xml,
            headers={"Content-Type": "text/xml"},
        )

        supports_multicall  = False
        supports_auth_check = False
        method_count        = 0

        if methods_resp and methods_resp.status_code == 200:
            body                = methods_resp.text
            supports_multicall  = "system.multicall" in body
            supports_auth_check = "wp.getUsersBlogs" in body or "wp.getUsers" in body
            # Count methods using string split on value tags
            method_count = body.count("<value><string>")

        self._add(Finding(
            check_name   = "xmlrpc_enabled",
            title        = "XML-RPC Interface Enabled with Credential Brute-Force Surface",
            risk         = "HIGH",
            cvss_score   = "7.5",
            cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe          = "CWE-307",
            description  = (
                "WordPress XML-RPC is enabled and functional. "
                + ("system.multicall is available — this allows an attacker to batch "
                   "hundreds of credential pairs into a single HTTP request, effectively "
                   "defeating per-request rate-limiting controls (including Limit Login Attempts). "
                   if supports_multicall else "")
                + ("Authentication methods (wp.getUsersBlogs) are exposed, enabling "
                   "direct credential validation. "
                   if supports_auth_check else "")
                + f"Total exposed methods: {method_count}."
            ),
            evidence     = (
                f"HTTP {resp.status_code} on /xmlrpc.php. "
                f"system.multicall available: {supports_multicall}. "
                f"Auth methods exposed: {supports_auth_check}. "
                f"Methods enumerated: {method_count}."
            ),
            recommendation = (
                "If XML-RPC is not required, disable it entirely: "
                "add_filter('xmlrpc_enabled', '__return_false'); in functions.php. "
                "If required, restrict access to known IPs at the server level and "
                "ensure XML-RPC is covered by your rate-limiting configuration."
            ),
            url = self._url("/xmlrpc.php"),
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 8 — Username Enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def check_username_enumeration(self):
        print("  [*] Testing username enumeration vectors...")

        discovered: Dict[str, str] = {}   # username → source

        # Vector 1: REST API /wp-json/wp/v2/users
        rest = self._get("/wp-json/wp/v2/users")
        if rest and rest.status_code == 200:
            try:
                data = json.loads(rest.text)
                if isinstance(data, list):
                    for user in data:
                        if isinstance(user, dict):
                            slug = user.get("slug", "")
                            name = user.get("name", "")
                            if slug:
                                discovered[slug] = "REST API /wp/v2/users"
            except (json.JSONDecodeError, KeyError):
                pass

        # Vector 2: Author redirect enumeration (/?author=N)
        for uid in range(1, 6):
            author_resp = self._get(f"/?author={uid}", allow_redirects=False)
            if author_resp and author_resp.status_code in (301, 302):
                location = author_resp.headers.get("Location", "")
                if "/author/" in location:
                    # Parse out the username from the URL path segments
                    parts = [p for p in location.rstrip("/").split("/") if p]
                    try:
                        idx  = parts.index("author")
                        uname = parts[idx + 1]
                        if uname and uname not in discovered:
                            discovered[uname] = f"Author redirect /?author={uid}"
                    except (ValueError, IndexError):
                        pass

        # Vector 3: RSS feed dc:creator
        rss = self._get("/feed/")
        if rss and rss.status_code == 200:
            # Use BeautifulSoup XML parsing — not string extraction
            soup = BeautifulSoup(rss.text, "lxml-xml")
            for creator in soup.find_all("creator"):
                name = creator.get_text().strip()
                if name and name not in discovered:
                    discovered[name] = "RSS feed dc:creator"

        if discovered:
            user_list = list(discovered.keys())
            sources   = list(set(discovered.values()))
            self._add(Finding(
                check_name   = "username_enumeration",
                title        = "WordPress Usernames Enumerable via Multiple Vectors",
                risk         = "MEDIUM",
                cvss_score   = "5.3",
                cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe          = "CWE-200",
                description  = (
                    f"WordPress usernames are publicly enumerable. "
                    f"Discovered {len(user_list)} user(s): {user_list}. "
                    "Combined with XML-RPC multicall or the standard login form, "
                    "these usernames feed directly into credential brute-force attacks."
                ),
                evidence     = (
                    f"Usernames: {user_list}. "
                    f"Disclosure vectors: {sources}"
                ),
                recommendation = (
                    "Remove the generator meta tag. Disable REST API user listing for unauthenticated "
                    "requests. Redirect author archive pages. Ensure display names differ from login usernames."
                ),
                url = self._url("/"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 9 — Debug and Error Log Exposure
    # ─────────────────────────────────────────────────────────────────────────

    def check_debug_logs(self):
        print("  [*] Checking for exposed debug and error logs...")

        log_paths = [
            "/wp-content/debug.log",
            "/debug.log",
            "/wp-content/uploads/debug.log",
            "/error_log",
            "/wp-content/error_log",
            "/.error_log",
            "/wp-admin/error_log",
            "/wp-content/logs/",
        ]

        # Must match multiple log-specific markers to avoid false positives
        log_markers      = ["PHP", "on line", "Stack trace", "WordPress database error",
                            "wp-content", "PHP Warning", "PHP Notice", "PHP Fatal"]
        sensitive_markers = ["DB_PASSWORD", "AUTH_KEY", "SECURE_AUTH_KEY", "password",
                             "secret", "DB_USER"]

        for path in log_paths:
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue

            body           = resp.text
            log_hits       = [m for m in log_markers if m in body]
            sensitive_hits = [m for m in sensitive_markers if m in body]

            # Need at least 2 log markers to confirm it's an actual log file
            if len(log_hits) < 2:
                continue

            has_creds = len(sensitive_hits) > 0
            risk      = "HIGH" if has_creds else "MEDIUM"

            self._add(Finding(
                check_name   = f"debug_log_{path.strip('/').replace('/', '_')}",
                title        = f"WordPress Debug/Error Log Publicly Accessible",
                risk         = risk,
                cvss_score   = "7.5" if has_creds else "5.3",
                cvss_vector  = (
                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    if has_creds
                    else "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                ),
                cwe          = "CWE-532",
                description  = (
                    f"A WordPress debug/error log file is publicly accessible at {path}. "
                    + ("It contains sensitive data including credential markers. "
                       if has_creds else
                       "It exposes internal file paths, database queries, PHP errors, and "
                       "stack traces that significantly aid enumeration and exploitation.")
                ),
                evidence     = (
                    f"HTTP 200 at {path}. "
                    f"Log markers confirmed: {log_hits[:4]}. "
                    + (f"Sensitive markers: {sensitive_hits}. " if has_creds else "")
                    + f"File size: {len(body):,} bytes."
                ),
                recommendation = (
                    "Set WP_DEBUG_LOG to false in production. "
                    "If debug logging is needed, restrict file access in .htaccess: "
                    "'<Files debug.log> deny from all </Files>'. "
                    "Move log storage outside the web root."
                ),
                url = self._url(path),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 10 — PHP Files in Uploads Directory
    # ─────────────────────────────────────────────────────────────────────────

    def check_php_in_uploads(self):
        print("  [*] Scanning uploads for PHP files (potential webshells)...")

        resp = self._get("/wp-content/uploads/")
        if resp is None or not self._is_directory_listing(resp):
            return

        links = self._links_from_listing(resp)

        # PHP-executable extensions on Apache
        php_exts = (".php", ".php3", ".php4", ".php5", ".php7",
                    ".phtml", ".phar", ".phps")

        php_files = [
            lnk for lnk in links
            if self._confirm_file_extension(lnk, php_exts)
        ]

        if not php_files:
            return

        # Probe each file to confirm it's accessible and executable
        confirmed_executable = []
        confirmed_accessible = []

        for php_file in php_files[:10]:   # cap to avoid DoS
            file_resp = self._get(f"/wp-content/uploads/{php_file}")
            if file_resp is None:
                continue
            if file_resp.status_code == 200:
                ct = file_resp.headers.get("Content-Type", "")
                # If server returned text/html or text/plain with PHP output — it executed
                if "text/html" in ct or "text/plain" in ct:
                    # Check if body has PHP output indicators
                    body = file_resp.text
                    if any(tag in body for tag in ("<br />", "<html", "<?php", "Fatal error")):
                        confirmed_executable.append(php_file)
                    else:
                        confirmed_accessible.append(php_file)
                else:
                    confirmed_accessible.append(php_file)

        risk = "CRITICAL" if confirmed_executable else "HIGH"
        self._add(Finding(
            check_name   = "php_in_uploads",
            title        = "PHP Files Found in Uploads Directory"
                           + (" — Execution Confirmed" if confirmed_executable else ""),
            risk         = risk,
            cvss_score   = "9.8" if confirmed_executable else "8.1",
            cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe          = "CWE-434",
            description  = (
                "PHP files were found in the wp-content/uploads directory, which should "
                "only contain media files. "
                + ("PHP execution is confirmed — these files can be invoked directly as webshells. "
                   if confirmed_executable else
                   "PHP execution status not confirmed but files are accessible. "
                   "These may be webshells if server PHP handler is active for this directory.")
            ),
            evidence     = (
                f"PHP files found: {php_files[:8]}. "
                + (f"Confirmed executable: {confirmed_executable}. " if confirmed_executable else "")
                + (f"Confirmed accessible: {confirmed_accessible}. " if confirmed_accessible else "")
            ),
            recommendation = (
                "Investigate each PHP file immediately for malicious content. "
                "Add to uploads/.htaccess: "
                "<FilesMatch \\.php$> deny from all </FilesMatch>. "
                "This is a potential indicator of compromise — treat accordingly."
            ),
            url = self._url("/wp-content/uploads/"),
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 11 — Sensitive Files in Uploads
    # ─────────────────────────────────────────────────────────────────────────

    def check_sensitive_files_in_uploads(self):
        print("  [*] Checking uploads for sensitive file types (DB dumps, archives, configs)...")

        resp = self._get("/wp-content/uploads/")
        if resp is None or not self._is_directory_listing(resp):
            return

        links = self._links_from_listing(resp)

        db_exts      = (".sql", ".sql.gz", ".sql.bz2")
        archive_exts = (".zip", ".tar.gz", ".tar.bz2", ".tar", ".7z", ".bz2")
        config_exts  = (".env", ".conf", ".config", ".ini", ".yml", ".yaml", ".cfg")

        db_files      = [l for l in links if self._confirm_file_extension(l, db_exts)]
        archive_files = [l for l in links if self._confirm_file_extension(l, archive_exts)]
        config_files  = [l for l in links if self._confirm_file_extension(l, config_exts)]

        if db_files:
            self._add(Finding(
                check_name   = "db_dump_in_uploads",
                title        = "Database Dump Files Publicly Accessible in Uploads",
                risk         = "CRITICAL",
                cvss_score   = "9.1",
                cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe          = "CWE-312",
                description  = (
                    "SQL database dump files found in the public uploads directory. "
                    "These contain all WordPress tables: user credentials, hashed passwords, "
                    "email addresses, options (which may include API keys and plugin secrets)."
                ),
                evidence     = f"Database files: {db_files[:8]}",
                recommendation = "Remove all database dumps from the web root. Never store SQL exports in web-accessible directories.",
                url = self._url("/wp-content/uploads/"),
            ))

        if archive_files:
            self._add(Finding(
                check_name   = "archives_in_uploads",
                title        = "Archive Files Publicly Accessible in Uploads",
                risk         = "HIGH",
                cvss_score   = "7.5",
                cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe          = "CWE-312",
                description  = (
                    "Archive files found in the public uploads directory. "
                    "Archives may contain source code, database exports, configuration files, "
                    "or other sensitive data depending on their contents."
                ),
                evidence     = f"Archive files: {archive_files[:8]}",
                recommendation = "Remove archive files from web-accessible directories. Move to storage outside the web root.",
                url = self._url("/wp-content/uploads/"),
            ))

        if config_files:
            self._add(Finding(
                check_name   = "config_in_uploads",
                title        = "Configuration Files Publicly Accessible in Uploads",
                risk         = "HIGH",
                cvss_score   = "7.5",
                cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe          = "CWE-312",
                description  = (
                    "Configuration files found in the uploads directory. "
                    ".env and similar files commonly contain API keys, service credentials, "
                    "and other secrets."
                ),
                evidence     = f"Config files: {config_files[:8]}",
                recommendation = "Remove all configuration files from the uploads directory. Deny access to .env, .conf, and .ini extensions at the server level.",
                url = self._url("/wp-content/uploads/"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 12 — Really Simple SSL Auth Bypass Probe
    # ─────────────────────────────────────────────────────────────────────────

    def check_really_simple_ssl(self):
        print("  [*] Probing Really Simple SSL authentication bypass surface (CVE-2024-10924)...")

        endpoint = "/wp-json/reallysimplessl/v1/two_fa/skip_onboarding"

        resp = self._post(
            endpoint,
            json_body={"user_id": 1, "login_nonce": "pentest_probe_invalid_nonce"},
            headers={"Content-Type": "application/json"},
        )

        if resp is None:
            return

        if resp.status_code == 200:
            try:
                body = json.loads(resp.text)
                # A vulnerable response contains auth-related keys
                auth_indicators = ("data", "user_id", "token", "redirect",
                                   "nonce", "cookie", "auth")
                body_keys       = [k.lower() for k in body.keys()] if isinstance(body, dict) else []
                is_vulnerable   = any(ind in body_keys for ind in auth_indicators)

                if is_vulnerable:
                    self._add(Finding(
                        check_name   = "rssl_auth_bypass",
                        title        = "Really Simple SSL Authentication Bypass (CVE-2024-10924)",
                        risk         = "CRITICAL",
                        cvss_score   = "9.8",
                        cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe          = "CWE-288",
                        description  = (
                            "The Really Simple SSL two-factor onboarding endpoint is vulnerable to "
                            "authentication bypass (CVE-2024-10924, CVSS 9.8). An unauthenticated "
                            "attacker can authenticate as any WordPress user including administrators "
                            "by sending an invalid nonce to this endpoint."
                        ),
                        evidence     = (
                            f"POST to {endpoint} with invalid nonce returned HTTP 200 "
                            f"with auth-related response keys: {body_keys[:6]}"
                        ),
                        recommendation = "Update Really Simple SSL to version 9.1.2 or later immediately.",
                        url = self._url(endpoint),
                    ))
            except (json.JSONDecodeError, AttributeError):
                pass

        # If 401/403/404 — endpoint is patched or not present; no finding raised

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 13 — LoginPress Outdated Version
    # ─────────────────────────────────────────────────────────────────────────

    def check_loginpress(self):
        print("  [*] Checking LoginPress plugin version...")

        readme = self._get("/wp-content/plugins/loginpress/readme.txt")
        if readme is None or readme.status_code != 200:
            return

        version = self._parse_plugin_version(readme.text)
        if not version:
            return

        latest  = "6.2.2"
        if self._version_lt(version, latest):
            self._add(Finding(
                check_name   = "loginpress_outdated",
                title        = f"LoginPress Plugin Outdated ({version} < {latest})",
                risk         = "MEDIUM",
                cvss_score   = "6.1",
                cvss_vector  = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                cwe          = "CWE-1104",
                description  = (
                    f"LoginPress version {version} is installed (latest: {latest}). "
                    "This plugin controls login page rendering and has a history of SQL injection "
                    "and reflected XSS vulnerabilities. The gap to 6.2.2 should be reviewed "
                    "against the official changelog for security patches."
                ),
                evidence     = f"Version {version} confirmed from /wp-content/plugins/loginpress/readme.txt",
                recommendation = (
                    "Update LoginPress to the latest version. "
                    "Review the 6.2.1 and 6.2.2 changelogs for security-related fixes."
                ),
                url = self._url("/wp-content/plugins/loginpress/"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 14 — Elementor REST API Exposure
    # ─────────────────────────────────────────────────────────────────────────

    def check_elementor_rest(self):
        print("  [*] Probing Elementor REST API endpoints...")

        endpoints = [
            "/wp-json/elementor/v1/globals/",
            "/wp-json/elementor/v1/kit/",
        ]

        sensitive_keys = {"api_key", "token", "secret", "password",
                          "license", "auth", "credential"}

        for endpoint in endpoints:
            resp = self._get(endpoint)
            if resp is None or resp.status_code != 200:
                continue
            try:
                data     = json.loads(resp.text)
                data_str = json.dumps(data).lower()

                found_sensitive = [
                    k for k in sensitive_keys if k in data_str
                ]
                has_data = bool(data)

                if has_data:
                    risk = "HIGH" if found_sensitive else "MEDIUM"
                    self._add(Finding(
                        check_name   = "elementor_rest_exposure",
                        title        = "Elementor REST API Returns Data Without Authentication",
                        risk         = risk,
                        cvss_score   = "7.5" if found_sensitive else "5.3",
                        cvss_vector  = (
                            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                            if found_sensitive
                            else "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                        ),
                        cwe          = "CWE-200",
                        description  = (
                            f"Elementor REST API endpoint {endpoint} returns site configuration "
                            "data to unauthenticated requests. "
                            + (f"Response contains potential sensitive keys: {found_sensitive}. "
                               if found_sensitive else "")
                        ),
                        evidence     = (
                            f"HTTP 200 at {endpoint}. "
                            f"Response size: {len(resp.text):,} bytes. "
                            + (f"Sensitive key indicators: {found_sensitive}."
                               if found_sensitive else "Data returned without auth.")
                        ),
                        recommendation = (
                            "Review Elementor REST API authentication requirements. "
                            "Restrict sensitive endpoints to authenticated users only."
                        ),
                        url = self._url(endpoint),
                    ))
                    break  # One finding per plugin
            except (json.JSONDecodeError, AttributeError):
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 15 — WP-Cron External Access
    # ─────────────────────────────────────────────────────────────────────────

    def check_wpcron(self):
        print("  [*] Checking WP-Cron external accessibility...")

        resp = self._get("/wp-cron.php")
        if resp is None:
            return

        if resp.status_code == 200:
            # Confirm it's actually wp-cron and not a catch-all 200
            # Real wp-cron returns an empty 200 with no significant HTML body
            body = resp.text.strip()
            ct   = resp.headers.get("Content-Type", "")

            is_wpcron = (
                len(body) < 50 or          # wp-cron typically returns empty body
                "text/html" not in ct or
                "wp-cron" in body.lower()
            )

            if is_wpcron:
                self._add(Finding(
                    check_name   = "wpcron_exposed",
                    title        = "WP-Cron Endpoint Publicly Accessible",
                    risk         = "LOW",
                    cvss_score   = "3.7",
                    cvss_vector  = "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    cwe          = "CWE-400",
                    description  = (
                        "The WP-Cron endpoint (wp-cron.php) is publicly accessible. "
                        "An attacker can repeatedly trigger this endpoint to exhaust server "
                        "resources (DoS) or cause scheduled tasks to run out of sequence, "
                        "potentially affecting site functionality."
                    ),
                    evidence     = f"HTTP 200 on /wp-cron.php. Body size: {len(resp.text)} bytes.",
                    recommendation = (
                        "Disable external WP-Cron: add define('DISABLE_WP_CRON', true) to wp-config.php. "
                        "Configure a real system cron job: "
                        "*/15 * * * * curl https://target.com/wp-cron.php > /dev/null 2>&1"
                    ),
                    url = self._url("/wp-cron.php"),
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 16 — Exposed .git Directory
    # ─────────────────────────────────────────────────────────────────────────

    def check_git_exposure(self):
        print("  [*] Checking for .git directory exposure...")

        git_paths = [
            "/.git/HEAD",
            "/.git/config",
            "/.git/COMMIT_EDITMSG",
        ]

        git_markers = ["ref: refs/", "repositoryformatversion", "filemode", "bare"]

        for path in git_paths:
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            body         = resp.text
            matched      = [m for m in git_markers if m in body]
            if len(matched) >= 1:  # Git files are very specific — 1 marker suffices
                self._add(Finding(
                    check_name   = "git_exposure",
                    title        = ".git Repository Metadata Publicly Accessible",
                    risk         = "HIGH",
                    cvss_score   = "7.5",
                    cvss_vector  = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe          = "CWE-312",
                    description  = (
                        "The .git directory is publicly accessible. An attacker can reconstruct "
                        "the full source code of the application using git reconstruction tools, "
                        "exposing all configuration files, database credentials, API keys, and "
                        "custom code that may not otherwise be accessible."
                    ),
                    evidence     = f"HTTP 200 at {path}. Git markers: {matched}",
                    recommendation = (
                        "Block access to .git at the server level: "
                        "RedirectMatch 404 /\\.git — or use Nginx deny for the location. "
                        "Never deploy with a .git directory in the web root."
                    ),
                    url = self._url(path),
                ))
                break  # One finding is enough

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 17 — Wordfence WAF Version Gap
    # ─────────────────────────────────────────────────────────────────────────

    def check_wordfence(self):
        print("  [*] Checking Wordfence WAF version...")

        readme = self._get("/wp-content/plugins/wordfence/readme.txt")
        if readme is None or readme.status_code != 200:
            return

        version = self._parse_plugin_version(readme.text)
        if not version:
            return

        # Note Wordfence presence for context regardless of version
        latest = "8.2.2"
        if self._version_lt(version, latest):
            self._add(Finding(
                check_name   = "wordfence_outdated",
                title        = f"Wordfence WAF Outdated ({version} < {latest})",
                risk         = "MEDIUM",
                cvss_score   = "4.3",
                cvss_vector  = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe          = "CWE-1104",
                description  = (
                    f"Wordfence version {version} is installed (latest: {latest}). "
                    "An outdated WAF may have stale firewall rule sets and threat intelligence, "
                    "reducing protection against recently published exploits and attack patterns. "
                    "Wordfence rule updates are tightly tied to plugin version."
                ),
                evidence     = f"Version {version} confirmed from Wordfence readme.txt.",
                recommendation = "Update Wordfence to the latest version to maintain current firewall rules and signatures.",
                url = self._url("/wp-content/plugins/wordfence/"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 18 — Loco Translate File Write Surface
    # ─────────────────────────────────────────────────────────────────────────

    def check_loco_translate(self):
        print("  [*] Checking Loco Translate version gap...")

        readme = self._get("/wp-content/plugins/loco-translate/readme.txt")
        if readme is None or readme.status_code != 200:
            return

        version = self._parse_plugin_version(readme.text)
        if not version:
            return

        latest = "2.8.4"
        if self._version_lt(version, latest):
            self._add(Finding(
                check_name   = "loco_translate_outdated",
                title        = f"Loco Translate Outdated ({version} < {latest})",
                risk         = "MEDIUM",
                cvss_score   = "5.4",
                cvss_vector  = "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                cwe          = "CWE-1104",
                description  = (
                    f"Loco Translate version {version} is installed (latest: {latest}). "
                    "This plugin provides a file editor interface for .po/.mo translation files. "
                    "Previous versions have had CSRF vulnerabilities that allowed arbitrary file "
                    "writes when an authenticated admin was tricked into visiting a malicious page. "
                    "Review the 2.8.4 changelog for security patches."
                ),
                evidence     = f"Version {version} confirmed from readme.txt.",
                recommendation = "Update Loco Translate immediately. Restrict the plugin's file editor to administrator roles only.",
                url = self._url("/wp-content/plugins/loco-translate/"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 19 — Theme 500 Errors (Anomaly Detection)
    # ─────────────────────────────────────────────────────────────────────────

    def check_theme_errors(self):
        print("  [*] Checking for themes returning HTTP 500 (anomaly detection)...")

        themes_to_probe = [
            "/wp-content/themes/twentytwenty/",
            "/wp-content/themes/twentytwenty/index.php",
            "/wp-content/themes/twentytwentyone/",
            "/wp-content/themes/twentytwentyone/index.php",
        ]

        error_themes = []
        for path in themes_to_probe:
            resp = self._get(path)
            if resp and resp.status_code == 500:
                error_themes.append(path)

        if error_themes:
            self._add(Finding(
                check_name   = "theme_500_errors",
                title        = "Installed Themes Returning HTTP 500 Internal Server Error",
                risk         = "INFO",
                cvss_score   = "0.0",
                cvss_vector  = "N/A",
                cwe          = "CWE-388",
                description  = (
                    "Multiple inactive themes are returning HTTP 500 errors. "
                    "While inactive themes should not cause visible issues, 500 errors "
                    "can indicate: corrupted theme files, a partially injected webshell causing "
                    "a PHP parse error, or plugin/theme conflicts. This warrants investigation "
                    "as a potential indicator of compromise."
                ),
                evidence     = f"HTTP 500 observed on: {error_themes}",
                recommendation = (
                    "Enable WP_DEBUG temporarily in a test environment to capture the PHP error. "
                    "Inspect the theme files for unexpected or injected code. "
                    "Compare file hashes against known-good versions."
                ),
                url = self._url("/wp-content/themes/"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 20 — Generic Sensitive File Probing
    # ─────────────────────────────────────────────────────────────────────────

    def check_sensitive_files(self):
        print("  [*] Probing for common sensitive file exposures...")

        targets = {
            "/.env"              : ["APP_KEY", "DB_PASSWORD", "AWS_SECRET", "MAIL_PASSWORD"],
            "/.env.local"        : ["APP_KEY", "DB_PASSWORD"],
            "/.env.production"   : ["APP_KEY", "DB_PASSWORD"],
            "/phpinfo.php"       : ["PHP Version", "Server API", "Configuration File"],
            "/info.php"          : ["PHP Version", "Server API"],
            "/server-status"     : ["Server Version", "Apache", "Total Accesses"],
            "/.htpasswd"         : [":"],   # htpasswd lines are "user:hash"
        }

        for path, markers in targets.items():
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            body    = resp.text
            matched = [m for m in markers if m in body]
            if not matched:
                continue

            # Determine severity by file type
            if ".env" in path:
                risk, score = "CRITICAL", "9.1"
                cvss_v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                desc   = (
                    "Environment file exposed. Contains application secrets, "
                    "database credentials, and API keys in cleartext."
                )
            elif "phpinfo" in path or "info.php" in path:
                risk, score = "MEDIUM", "5.3"
                cvss_v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                desc   = (
                    "PHP configuration page exposed. Reveals server internals, "
                    "installed modules, file paths, and environment variables."
                )
            elif "server-status" in path:
                risk, score = "MEDIUM", "5.3"
                cvss_v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                desc   = "Apache server-status page reveals active requests, client IPs, and server internals."
            else:
                risk, score = "HIGH", "7.5"
                cvss_v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                desc   = f"Sensitive file accessible at {path}."

            self._add(Finding(
                check_name   = f"sensitive_file_{path.strip('/').replace('/', '_').replace('.', '_')}",
                title        = f"Sensitive File Accessible: {path}",
                risk         = risk,
                cvss_score   = score,
                cvss_vector  = cvss_v,
                cwe          = "CWE-312",
                description  = desc,
                evidence     = f"HTTP 200 at {path}. Content markers confirmed: {matched}",
                recommendation = f"Remove or restrict access to {path} immediately.",
                url = self._url(path),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # Run All Checks
    # ─────────────────────────────────────────────────────────────────────────

    def run(self):
        banner = f"{Colors.BOLD}{Colors.GREEN}"
        reset  = Colors.RESET

        print(f"\n{banner}{'═' * 70}{reset}")
        print(f"{banner}  WP Audit — WordPress Penetration Testing Tool{reset}")
        print(f"  Target  : {Colors.BOLD}{self.base_url}{Colors.RESET}")
        print(f"  Started : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
        print(f"  Delay   : {self.delay}s between requests")
        print(f"{banner}{'═' * 70}{reset}")
        print(f"\n{Colors.BOLD}  Running Checks{Colors.RESET}")

        checks = [
            self.check_version_disclosure,
            self.check_directory_listing,
            self.check_wpconfig_backups,
            self.check_duplicator_installer,
            self.check_duplicator_packages,
            self.check_updraftplus_backups,
            self.check_php_in_uploads,
            self.check_sensitive_files_in_uploads,
            self.check_xmlrpc,
            self.check_username_enumeration,
            self.check_debug_logs,
            self.check_really_simple_ssl,
            self.check_loginpress,
            self.check_elementor_rest,
            self.check_wpcron,
            self.check_git_exposure,
            self.check_wordfence,
            self.check_loco_translate,
            self.check_theme_errors,
            self.check_sensitive_files,
        ]

        for check in checks:
            try:
                check()
            except Exception as exc:
                print(f"  {Colors.DIM}[ERR] {check.__name__}: {exc}{Colors.RESET}")

        return self._generate_report()

    # ─────────────────────────────────────────────────────────────────────────
    # Report
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_report(self) -> List[Finding]:
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.RISK_ORDER.get(f.risk, 0),
            reverse=True,
        )

        counts = {r: 0 for r in self.RISK_ORDER}
        for f in sorted_findings:
            counts[f.risk] = counts.get(f.risk, 0) + 1

        B = Colors.BOLD
        R = Colors.RESET
        D = Colors.DIM

        print(f"\n\n{'═' * 70}")
        print(f"{B}  SECURITY ASSESSMENT REPORT{R}")
        print(f"  Target  : {self.base_url}")
        print(f"  Date    : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
        print(f"  Checks  : 20   |   Findings : {len(sorted_findings)}")
        print(f"{'═' * 70}")

        print(f"\n{B}  RISK SUMMARY{R}")
        print(f"  {'─' * 44}")
        for risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c     = counts.get(risk, 0)
            color = self.RISK_COLOR.get(risk, "")
            bar   = "█" * c + D + "░" * (10 - c) + R
            print(f"  {color}{risk:<10}{R}  {bar}  {B}{c}{R}")

        print(f"\n{B}  DETAILED FINDINGS{R}")
        print(f"  {'─' * 68}")

        for idx, f in enumerate(sorted_findings, 1):
            color = self.RISK_COLOR.get(f.risk, "")
            print(f"\n  [{idx:02d}] {color}{B}{f.risk}{R}  ─  {B}{f.title}{R}")
            print(f"       {'─' * 60}")
            print(f"       {D}CVSS{R}   {f.cvss_score}  {D}({f.cvss_vector}){R}")
            print(f"       {D}CWE{R}    {f.cwe}")
            print(f"       {D}URL{R}    {f.url or 'N/A'}")
            print()
            # Word-wrap description at 65 chars
            words, line = f.description.split(), ""
            for w in words:
                if len(line) + len(w) + 1 > 65:
                    print(f"       {line}")
                    line = w
                else:
                    line = (line + " " + w).strip()
            if line:
                print(f"       {line}")
            print()
            print(f"       {D}Evidence :{R}")
            ev_words, ev_line = f.evidence.split(), ""
            for w in ev_words:
                if len(ev_line) + len(w) + 1 > 62:
                    print(f"         {ev_line}")
                    ev_line = w
                else:
                    ev_line = (ev_line + " " + w).strip()
            if ev_line:
                print(f"         {ev_line}")
            print()
            print(f"       {D}Fix :{R}")
            fix_words, fix_line = f.recommendation.split(), ""
            for w in fix_words:
                if len(fix_line) + len(w) + 1 > 62:
                    print(f"         {fix_line}")
                    fix_line = w
                else:
                    fix_line = (fix_line + " " + w).strip()
            if fix_line:
                print(f"         {fix_line}")

        print(f"\n{'═' * 70}")
        print(f"{B}  END OF REPORT{R}")
        print(f"{'═' * 70}\n")

        # JSON export
        if self.output_file:
            report_data = {
                "target"   : self.base_url,
                "timestamp": datetime.now().isoformat(),
                "summary"  : counts,
                "findings" : [
                    {
                        "id"             : idx,
                        "check"          : f.check_name,
                        "title"          : f.title,
                        "risk"           : f.risk,
                        "cvss_score"     : f.cvss_score,
                        "cvss_vector"    : f.cvss_vector,
                        "cwe"            : f.cwe,
                        "url"            : f.url,
                        "description"    : f.description,
                        "evidence"       : f.evidence,
                        "recommendation" : f.recommendation,
                    }
                    for idx, f in enumerate(sorted_findings, 1)
                ],
            }
            with open(self.output_file, "w", encoding="utf-8") as fh:
                json.dump(report_data, fh, indent=2)
            print(f"  [+] JSON report saved to: {self.output_file}\n")

        return sorted_findings


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WP Audit — WordPress Penetration Testing Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 wp_audit.py https://target.com
  python3 wp_audit.py https://target.com --delay 1.0 --output report.json
  python3 wp_audit.py https://target.com --timeout 20 --no-color
        """,
    )
    parser.add_argument("url",            help="Target WordPress URL (e.g. https://target.com)")
    parser.add_argument("--delay",        type=float, default=0.5, metavar="SECS",
                        help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--timeout",      type=int,   default=15,  metavar="SECS",
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--output",       metavar="FILE",
                        help="Save findings as JSON to this file")
    parser.add_argument("--no-color",     action="store_true",
                        help="Disable terminal color output")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    # Normalise URL
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    auditor = WPAudit(
        base_url    = url,
        timeout     = args.timeout,
        delay       = args.delay,
        output_file = args.output,
    )
    auditor.run()


if __name__ == "__main__":
    main()
