#!/usr/bin/env python3
"""
Guardian — macOS Background Security Monitor
Runs every 3 hours via LaunchAgent. Zero dependencies, zero network calls, 100% local.
"""

import datetime
import glob
import json
import logging
import os
import pathlib
import plistlib
import re
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time

# ── Paths ────────────────────────────────────────────────────────────────────

GUARDIAN_DIR = pathlib.Path.home() / ".guardian"
REPORTS_DIR = GUARDIAN_DIR / "reports"
LOG_FILE = GUARDIAN_DIR / "guardian.log"
REPORT_RETENTION_DAYS = 30

# ── Whitelisted executables (absolute paths only) ───────────────────────────

ALLOWED_BINS = {
    "socketfilterfw": "/usr/libexec/ApplicationFirewall/socketfilterfw",
    "lsof": "/usr/sbin/lsof",
    "networksetup": "/usr/sbin/networksetup",
    "csrutil": "/usr/bin/csrutil",
    "spctl": "/usr/sbin/spctl",
    "fdesetup": "/usr/bin/fdesetup",
    "launchctl": "/bin/launchctl",
    "ps": "/bin/ps",
    "crontab": "/usr/bin/crontab",
    "dscl": "/usr/bin/dscl",
    "defaults": "/usr/bin/defaults",
    "softwareupdate": "/usr/sbin/softwareupdate",
    "osascript": "/usr/bin/osascript",
    "sw_vers": "/usr/bin/sw_vers",
    "whoami": "/usr/bin/whoami",
}

# ── Logging setup ───────────────────────────────────────────────────────────

GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("guardian")

# ── Safe subprocess wrapper ─────────────────────────────────────────────────

def safe_run(bin_key, args=None, timeout=30):
    """Run a whitelisted binary with shell=False and minimal env."""
    exe = ALLOWED_BINS.get(bin_key)
    if exe is None:
        return None, f"Unknown binary key: {bin_key}"
    if not os.path.isfile(exe):
        return None, f"Binary not found: {exe}"

    cmd = [exe] + (args or [])
    safe_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(pathlib.Path.home()),
        "LANG": "en_US.UTF-8",
    }
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=safe_env,
        )
        return proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return None, f"Timeout after {timeout}s: {' '.join(cmd)}"
    except Exception as e:
        return None, str(e)

# ── macOS notification ──────────────────────────────────────────────────────

def notify(title, message):
    """Send a macOS notification center alert. Sanitizes input."""
    safe_title = title.replace('"', '').replace("\\", "")[:100]
    safe_msg = message.replace('"', '').replace("\\", "")[:200]
    script = f'display notification "{safe_msg}" with title "{safe_title}"'
    safe_run("osascript", ["-e", script], timeout=10)

# ── Severity helpers ────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"
OK = "OK"


class Finding:
    def __init__(self, severity, category, title, detail=""):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail

    def __str__(self):
        tag = f"[{self.severity}]"
        line = f"  {tag:12s} {self.title}"
        if self.detail:
            wrapped = textwrap.indent(self.detail, "               ")
            line += "\n" + wrapped
        return line

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK MODULES
# ══════════════════════════════════════════════════════════════════════════════

def check_network_security():
    """Firewall, open ports, suspicious connections, DNS."""
    findings = []

    # ── Firewall status ──
    out, _ = safe_run("socketfilterfw", ["--getglobalstate"])
    if out:
        if "disabled" in out.lower():
            findings.append(Finding(CRITICAL, "Network", "Firewall is DISABLED",
                                    "Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"))
        else:
            findings.append(Finding(OK, "Network", "Firewall is enabled"))

    # ── Stealth mode ──
    out, _ = safe_run("socketfilterfw", ["--getstealthmode"])
    if out:
        if "disabled" in out.lower():
            findings.append(Finding(WARNING, "Network", "Stealth mode is disabled",
                                    "Stealth mode hides your Mac from port scans"))
        else:
            findings.append(Finding(OK, "Network", "Stealth mode is enabled"))

    # ── Unexpected listening ports ──
    out, _ = safe_run("lsof", ["-iTCP", "-sTCP:LISTEN", "-nP"], timeout=15)
    if out:
        known_safe = {"rapportd", "sharingd", "WiFiAgent", "ControlCenter",
                      "ControlCe",  # truncated name in lsof output
                      "UserEventAgent", "SystemUIServer", "loginwindow",
                      "remoted", "identityservicesd", "mDNSResponder",
                      "ollama", "OneDrive", "Python",  # user's known apps
                      }
        lines = out.strip().split("\n")[1:]  # skip header
        suspicious = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 1:
                proc_name = parts[0]
                if proc_name not in known_safe:
                    suspicious.append(line)
        if suspicious:
            detail = "\n".join(suspicious[:10])
            findings.append(Finding(WARNING, "Network",
                                    f"{len(suspicious)} unexpected listening port(s)", detail))
        else:
            findings.append(Finding(OK, "Network", "No unexpected listening ports"))

    # ── DNS servers check ──
    out, _ = safe_run("networksetup", ["-getdnsservers", "Wi-Fi"])
    if out and "aren't any" not in out.lower():
        dns_servers = [s.strip() for s in out.split("\n") if s.strip()]
        trusted_dns = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                       "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"}
        untrusted = [d for d in dns_servers if d not in trusted_dns]
        if untrusted:
            findings.append(Finding(WARNING, "Network",
                                    f"Non-standard DNS servers detected: {', '.join(untrusted)}"))
        else:
            findings.append(Finding(OK, "Network", "DNS servers look normal"))
    else:
        findings.append(Finding(OK, "Network", "DNS set to automatic (DHCP)"))

    return findings


def check_system_integrity():
    """SIP, Gatekeeper, FileVault, rogue LaunchAgents/Daemons."""
    findings = []

    # ── SIP ──
    out, _ = safe_run("csrutil", ["status"])
    if out:
        if "enabled" in out.lower():
            findings.append(Finding(OK, "System", "System Integrity Protection (SIP) is enabled"))
        else:
            findings.append(Finding(CRITICAL, "System", "SIP is DISABLED",
                                    "Boot into Recovery Mode and run: csrutil enable"))

    # ── Gatekeeper ──
    out, _ = safe_run("spctl", ["--status"])
    if out:
        if "enabled" in out.lower():
            findings.append(Finding(OK, "System", "Gatekeeper is enabled"))
        else:
            findings.append(Finding(CRITICAL, "System", "Gatekeeper is DISABLED",
                                    "Run: sudo spctl --master-enable"))

    # ── FileVault ──
    out, _ = safe_run("fdesetup", ["status"])
    if out:
        if "on" in out.lower():
            findings.append(Finding(OK, "System", "FileVault disk encryption is ON"))
        else:
            findings.append(Finding(CRITICAL, "System", "FileVault is OFF — disk is NOT encrypted",
                                    "Enable in System Settings > Privacy & Security > FileVault"))

    # ── Scan LaunchAgents / LaunchDaemons for unknown items ──
    known_prefixes = {
        "com.apple.", "com.google.", "com.microsoft.", "com.adobe.",
        "com.spotify.", "com.docker.", "com.zoom.", "com.guardian.",
        "com.github.", "com.brave.", "org.mozilla.", "com.logi.",
        "us.zoom.", "com.dropbox.", "com.jetbrains.", "com.slack.",
        "homebrew.", "com.valvesoftware.", "com.grammarly.",
        "com.twincatcher.", "com.jarvis.",
    }
    scan_dirs = [
        pathlib.Path.home() / "Library" / "LaunchAgents",
        pathlib.Path("/Library/LaunchAgents"),
        pathlib.Path("/Library/LaunchDaemons"),
    ]
    unknown_agents = []
    for d in scan_dirs:
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.suffix == ".plist":
                name = f.stem
                if not any(name.startswith(p) for p in known_prefixes):
                    unknown_agents.append(str(f))

    if unknown_agents:
        detail = "\n".join(unknown_agents[:15])
        findings.append(Finding(WARNING, "System",
                                f"{len(unknown_agents)} unknown LaunchAgent/Daemon(s) found", detail))
    else:
        findings.append(Finding(OK, "System", "No unknown LaunchAgents/Daemons"))

    return findings


def check_privacy():
    """Sharing services, camera/mic access, login items."""
    findings = []

    # ── Sharing services ──
    sharing_checks = [
        ("remotelogin", "Remote Login (SSH)"),
        ("remotedesktop", "Remote Desktop (Screen Sharing)"),
        ("remoteappleevents", "Remote Apple Events"),
    ]
    for service, label in sharing_checks:
        out, _ = safe_run("launchctl", ["print", f"system/com.openssh.sshd"], timeout=10)
        # Alternative: check systemsetup
        # We use a simpler method — check if known sharing daemons are running
        pass

    # Check sharing via launchctl for SSH
    out, _ = safe_run("launchctl", ["print", "system/com.openssh.sshd"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(WARNING, "Privacy", "Remote Login (SSH) is enabled",
                                "Disable if not needed: System Settings > General > Sharing"))
    else:
        findings.append(Finding(OK, "Privacy", "Remote Login (SSH) is disabled"))

    # ── TCC.db camera/mic access audit ──
    tcc_path = pathlib.Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    if tcc_path.is_file():
        try:
            conn = sqlite3.connect(f"file:{tcc_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            # Camera access
            cursor.execute(
                "SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2"
            )
            camera_apps = [row[0] for row in cursor.fetchall()]
            if camera_apps:
                findings.append(Finding(INFO, "Privacy",
                                        f"{len(camera_apps)} app(s) have camera access",
                                        "\n".join(camera_apps[:10])))

            # Microphone access
            cursor.execute(
                "SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2"
            )
            mic_apps = [row[0] for row in cursor.fetchall()]
            if mic_apps:
                findings.append(Finding(INFO, "Privacy",
                                        f"{len(mic_apps)} app(s) have microphone access",
                                        "\n".join(mic_apps[:10])))

            # Screen recording
            cursor.execute(
                "SELECT client FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2"
            )
            screen_apps = [row[0] for row in cursor.fetchall()]
            if screen_apps:
                findings.append(Finding(INFO, "Privacy",
                                        f"{len(screen_apps)} app(s) have screen recording access",
                                        "\n".join(screen_apps[:10])))

            conn.close()
        except Exception as e:
            findings.append(Finding(INFO, "Privacy",
                                    f"Could not read TCC.db (normal on newer macOS): {e}"))
    else:
        findings.append(Finding(INFO, "Privacy", "TCC.db not directly accessible (expected on recent macOS)"))

    # ── Login items ──
    login_items_dir = pathlib.Path.home() / "Library" / "Application Support" / "com.apple.backgroundtaskmanagementagent"
    if login_items_dir.is_dir():
        items = list(login_items_dir.iterdir())
        if items:
            findings.append(Finding(INFO, "Privacy",
                                    f"{len(items)} background login item config(s) found"))

    return findings


def check_malware_indicators():
    """Known malware paths, suspicious processes, cron jobs, periodic scripts."""
    findings = []

    # ── Known macOS malware file paths ──
    malware_paths = [
        "/Library/Application Support/JavaW",
        "/Library/LaunchAgents/com.pcv.hlpramc.plist",
        "/Library/LaunchAgents/com.startup.plist",
        "/Library/LaunchDaemons/com.machelper.plist",
        "/Library/LaunchDaemons/com.apple.installer.plist",  # fake Apple plist
        pathlib.Path.home() / "Library" / "LaunchAgents" / "com.pcv.hlpramc.plist",
        pathlib.Path.home() / "Library" / "LaunchAgents" / "com.startup.plist",
        pathlib.Path.home() / ".mitmproxy",  # MITM proxy (could be legit if user installed)
        "/tmp/.hidden_payload",
        "/var/tmp/.hidden_payload",
    ]
    found_malware = []
    for p in malware_paths:
        if pathlib.Path(p).exists():
            found_malware.append(str(p))

    if found_malware:
        detail = "\n".join(found_malware)
        findings.append(Finding(CRITICAL, "Malware",
                                f"{len(found_malware)} known malware indicator(s) found!", detail))
    else:
        findings.append(Finding(OK, "Malware", "No known malware file indicators"))

    # ── Suspicious processes ──
    out, _ = safe_run("ps", ["-axo", "pid,comm"], timeout=10)
    if out:
        suspicious_names = {"cryptominer", "xmrig", "coinhive", "coinminer",
                            "kworker", "bioset", "ksoftirqd",  # Linux-kernel fakes on macOS
                            "osascript.hidden", ".hidden"}
        procs = out.strip().split("\n")
        sus_procs = []
        for line in procs:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                pname = parts[1].lower()
                basename = os.path.basename(pname)
                if basename in suspicious_names or pname.startswith("/tmp/") or pname.startswith("/var/tmp/"):
                    sus_procs.append(line.strip())
        if sus_procs:
            detail = "\n".join(sus_procs[:10])
            findings.append(Finding(CRITICAL, "Malware",
                                    f"{len(sus_procs)} suspicious process(es) detected!", detail))
        else:
            findings.append(Finding(OK, "Malware", "No suspicious processes detected"))

    # ── Cron jobs ──
    out, _ = safe_run("crontab", ["-l"], timeout=10)
    if out and "no crontab" not in out.lower():
        findings.append(Finding(WARNING, "Malware",
                                "User cron jobs found — review for legitimacy",
                                out[:500]))
    else:
        findings.append(Finding(OK, "Malware", "No user cron jobs"))

    # ── Custom periodic scripts ──
    periodic_dirs = ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]
    custom_scripts = []
    for d in periodic_dirs:
        p = pathlib.Path(d)
        if p.is_dir():
            for f in p.iterdir():
                # Apple's built-in scripts are numbered (100.clean-logs, etc.)
                if not re.match(r"^\d{3}\.", f.name):
                    custom_scripts.append(str(f))
    if custom_scripts:
        findings.append(Finding(WARNING, "Malware",
                                f"{len(custom_scripts)} custom periodic script(s)",
                                "\n".join(custom_scripts[:10])))
    else:
        findings.append(Finding(OK, "Malware", "No custom periodic scripts"))

    return findings


def check_user_accounts():
    """Unexpected accounts, guest account, SSH authorized keys."""
    findings = []

    # ── List user accounts ──
    out, _ = safe_run("dscl", [".", "-list", "/Users"], timeout=10)
    if out:
        users = [u.strip() for u in out.split("\n") if u.strip()]
        # Filter out system accounts (start with _)
        real_users = [u for u in users if not u.startswith("_") and u not in
                      {"daemon", "nobody", "root", "Guest"}]
        findings.append(Finding(INFO, "Accounts",
                                f"User accounts: {', '.join(real_users)}"))

        # Check for unexpected non-system accounts (more than 2 is unusual for personal Mac)
        if len(real_users) > 3:
            findings.append(Finding(WARNING, "Accounts",
                                    f"{len(real_users)} user accounts found — verify all are expected"))

    # ── Guest account ──
    out, _ = safe_run("defaults", ["read",
                                    "/Library/Preferences/com.apple.loginwindow",
                                    "GuestEnabled"], timeout=10)
    if out:
        if out.strip() == "1":
            findings.append(Finding(WARNING, "Accounts", "Guest account is ENABLED",
                                    "Disable if not needed: System Settings > Users & Groups"))
        else:
            findings.append(Finding(OK, "Accounts", "Guest account is disabled"))

    # ── SSH authorized keys ──
    auth_keys = pathlib.Path.home() / ".ssh" / "authorized_keys"
    if auth_keys.is_file():
        try:
            lines = auth_keys.read_text().strip().split("\n")
            key_count = len([l for l in lines if l.strip() and not l.strip().startswith("#")])
            if key_count > 0:
                findings.append(Finding(WARNING, "Accounts",
                                        f"{key_count} SSH authorized key(s) found — verify all are yours",
                                        f"File: {auth_keys}"))
            else:
                findings.append(Finding(OK, "Accounts", "No SSH authorized keys"))
        except Exception:
            findings.append(Finding(INFO, "Accounts", "Could not read SSH authorized_keys"))
    else:
        findings.append(Finding(OK, "Accounts", "No SSH authorized_keys file"))

    return findings


def check_software_updates():
    """Available macOS and security updates."""
    findings = []

    out, err = safe_run("softwareupdate", ["-l"], timeout=120)
    combined = (out or "") + "\n" + (err or "")
    if "no new software available" in combined.lower():
        findings.append(Finding(OK, "Updates", "macOS is up to date"))
    elif "software update found" in combined.lower() or "security" in combined.lower():
        # Extract update names
        updates = []
        for line in combined.split("\n"):
            line = line.strip()
            if line.startswith("*") or line.startswith("Label:"):
                updates.append(line.lstrip("* ").strip())
        if updates:
            findings.append(Finding(WARNING, "Updates",
                                    f"{len(updates)} update(s) available",
                                    "\n".join(updates[:10])))
        else:
            findings.append(Finding(WARNING, "Updates", "Software updates may be available",
                                    combined[:300]))
    else:
        findings.append(Finding(INFO, "Updates", "Could not determine update status",
                                combined[:200]))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(all_findings):
    """Generate a formatted text report."""
    now = datetime.datetime.now()
    hostname_out, _ = safe_run("sw_vers", ["-productVersion"])
    user_out, _ = safe_run("whoami")

    lines = []
    lines.append("=" * 70)
    lines.append("  GUARDIAN — macOS Security Report")
    lines.append("=" * 70)
    lines.append(f"  Date    : {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  macOS   : {hostname_out or 'unknown'}")
    lines.append(f"  User    : {user_out or 'unknown'}")
    lines.append("=" * 70)
    lines.append("")

    # Summary counts
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0, OK: 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines.append(f"  Summary: {counts[CRITICAL]} critical, {counts[WARNING]} warning, "
                 f"{counts[INFO]} info, {counts[OK]} ok")
    lines.append("")

    # Group by category
    categories = []
    seen = set()
    for f in all_findings:
        if f.category not in seen:
            categories.append(f.category)
            seen.add(f.category)

    for cat in categories:
        lines.append(f"── {cat} {'─' * (65 - len(cat))}")
        for f in all_findings:
            if f.category == cat:
                lines.append(str(f))
        lines.append("")

    lines.append("=" * 70)
    lines.append("  End of report")
    lines.append("=" * 70)

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  CLEANUP OLD REPORTS
# ══════════════════════════════════════════════════════════════════════════════

def cleanup_old_reports():
    """Delete reports older than REPORT_RETENTION_DAYS."""
    cutoff = time.time() - (REPORT_RETENTION_DAYS * 86400)
    count = 0
    for f in REPORTS_DIR.iterdir():
        if f.suffix == ".txt" and f.stat().st_mtime < cutoff:
            f.unlink()
            count += 1
    if count:
        log.info(f"Cleaned up {count} old report(s)")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    start = time.time()
    log.info("Guardian scan starting")

    # Run all checks in parallel using threads
    results = {}
    checks = {
        "network": check_network_security,
        "system": check_system_integrity,
        "privacy": check_privacy,
        "malware": check_malware_indicators,
        "accounts": check_user_accounts,
        "updates": check_software_updates,
    }

    def run_check(name, func):
        try:
            results[name] = func()
        except Exception as e:
            log.error(f"Check '{name}' failed: {e}")
            results[name] = [Finding(WARNING, name.title(), f"Check failed: {e}")]

    threads = []
    for name, func in checks.items():
        t = threading.Thread(target=run_check, args=(name, func), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=180)

    # Collect all findings in module order
    all_findings = []
    for name in ["network", "system", "privacy", "malware", "accounts", "updates"]:
        all_findings.extend(results.get(name, []))

    # Generate report
    report = generate_report(all_findings)

    # Save report
    now = datetime.datetime.now()
    report_file = REPORTS_DIR / f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    report_file.write_text(report)
    log.info(f"Report saved: {report_file}")

    # Send notifications
    critical_findings = [f for f in all_findings if f.severity == CRITICAL]
    warning_findings = [f for f in all_findings if f.severity == WARNING]

    if critical_findings:
        titles = [f.title for f in critical_findings[:3]]
        notify("Guardian: CRITICAL Issues",
               f"{len(critical_findings)} critical: " + "; ".join(titles))
    elif warning_findings:
        titles = [f.title for f in warning_findings[:3]]
        notify("Guardian: Warnings Found",
               f"{len(warning_findings)} warning(s): " + "; ".join(titles))
    else:
        notify("Guardian: All Clear", "No security issues detected")

    # Cleanup old reports
    cleanup_old_reports()

    elapsed = time.time() - start
    log.info(f"Guardian scan complete in {elapsed:.1f}s — "
             f"{len(critical_findings)} critical, {len(warning_findings)} warning")

    # Exit with code reflecting severity
    if critical_findings:
        sys.exit(2)
    elif warning_findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
