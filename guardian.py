#!/usr/bin/env python3
"""
Guardian v4.0 — macOS Background Security Monitor (Ultimate Edition)
Runs every 3 hours via LaunchAgent. Zero cost, zero network calls, 100% local.
14 check modules, 60+ checks, security score, trends, personalized suggestions.
Optional: osquery + ClamAV integration if installed (both free).
"""

import datetime
import hashlib
import json
import logging
import os
import pathlib
import plistlib
import re
import sqlite3
import stat
import subprocess
import sys
import textwrap
import threading
import time

# ── Paths ────────────────────────────────────────────────────────────────────

GUARDIAN_DIR = pathlib.Path.home() / ".guardian"
REPORTS_DIR = GUARDIAN_DIR / "reports"
LOG_FILE = GUARDIAN_DIR / "guardian.log"
SCORES_FILE = GUARDIAN_DIR / "scores.json"
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
    "pmset": "/usr/bin/pmset",
    "tmutil": "/usr/bin/tmutil",
    "sysctl": "/usr/sbin/sysctl",
    "system_profiler": "/usr/sbin/system_profiler",
    "mdutil": "/usr/bin/mdutil",
    "security": "/usr/bin/security",
    "diskutil": "/usr/sbin/diskutil",
    "profiles": "/usr/bin/profiles",
    "last": "/usr/bin/last",
    "ifconfig": "/sbin/ifconfig",
    "ioreg": "/usr/sbin/ioreg",
    "log": "/usr/bin/log",
    "codesign": "/usr/bin/codesign",
    "plutil": "/usr/bin/plutil",
    "systemsetup": "/usr/sbin/systemsetup",
}

# Optional tools — detected at runtime
OPTIONAL_BINS = {}

def detect_optional_tools():
    """Find optional free tools if installed."""
    candidates = {
        "osqueryi": ["/opt/homebrew/bin/osqueryi", "/usr/local/bin/osqueryi"],
        "clamscan": ["/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"],
        "freshclam": ["/opt/homebrew/bin/freshclam", "/usr/local/bin/freshclam"],
        "terminal-notifier": ["/opt/homebrew/bin/terminal-notifier", "/usr/local/bin/terminal-notifier"],
    }
    for name, paths in candidates.items():
        for p in paths:
            if os.path.isfile(p):
                OPTIONAL_BINS[name] = p
                break

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
    exe = ALLOWED_BINS.get(bin_key) or OPTIONAL_BINS.get(bin_key)
    if exe is None:
        return None, f"Unknown binary key: {bin_key}"
    if not os.path.isfile(exe):
        return None, f"Binary not found: {exe}"
    cmd = [exe] + (args or [])
    safe_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
        "HOME": str(pathlib.Path.home()),
        "LANG": "en_US.UTF-8",
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=False, env=safe_env,
        )
        return proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return None, f"Timeout after {timeout}s"
    except Exception as e:
        return None, str(e)

# ── macOS notification ──────────────────────────────────────────────────────

def notify(title, message):
    safe_title = title.replace('"', '').replace("\\", "")[:100]
    safe_msg = message.replace('"', '').replace("\\", "")[:200]

    # Primary: terminal-notifier (reliable from LaunchAgents)
    if "terminal-notifier" in OPTIONAL_BINS:
        out, err = safe_run("terminal-notifier", [
            "-title", safe_title,
            "-message", safe_msg,
            "-sound", "Glass",
            "-group", "guardian",
        ], timeout=10)
        if err:
            log.warning(f"terminal-notifier failed: {err}")
        else:
            log.info(f"Notification sent: {safe_title}")
            return

    # Fallback: osascript (may not work from LaunchAgent)
    script = (f'display notification "{safe_msg}" with title "{safe_title}" '
              f'sound name "Glass"')
    out, err = safe_run("osascript", ["-e", script], timeout=10)
    if err:
        log.warning(f"osascript notification failed: {err}")
    else:
        log.info(f"Notification sent (osascript): {safe_title}")

# ── Severity & scoring ──────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"
OK = "OK"

SEVERITY_PENALTY = {CRITICAL: 15, WARNING: 5, INFO: 0, OK: 0}


class Finding:
    __slots__ = ("severity", "category", "title", "detail", "fix")

    def __init__(self, severity, category, title, detail="", fix=""):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.fix = fix

    def __str__(self):
        tag = f"[{self.severity}]"
        line = f"  {tag:12s} {self.title}"
        if self.detail:
            line += "\n" + textwrap.indent(self.detail, "               ")
        if self.fix:
            line += "\n" + textwrap.indent(f"Fix: {self.fix}", "               ")
        return line

    def to_dict(self):
        return {"severity": self.severity, "category": self.category,
                "title": self.title, "detail": self.detail, "fix": self.fix}


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1: NETWORK SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def check_network_security():
    findings = []

    # 1a. Firewall
    out, _ = safe_run("socketfilterfw", ["--getglobalstate"])
    if out:
        if "disabled" in out.lower():
            findings.append(Finding(CRITICAL, "Network", "Firewall is DISABLED",
                fix="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"))
        else:
            findings.append(Finding(OK, "Network", "Firewall is enabled"))

    # 1b. Stealth mode
    out, _ = safe_run("socketfilterfw", ["--getstealthmode"])
    if out:
        if "disabled" in out.lower():
            findings.append(Finding(WARNING, "Network", "Stealth mode is disabled",
                detail="Your Mac responds to port scan probes, making it visible on networks.",
                fix="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"))
        else:
            findings.append(Finding(OK, "Network", "Stealth mode is enabled"))

    # 1c. Block all incoming
    out, _ = safe_run("socketfilterfw", ["--getblockall"])
    if out:
        if "disabled" in out.lower():
            findings.append(Finding(INFO, "Network", "Block-all-incoming mode is off (normal)"))
        else:
            findings.append(Finding(OK, "Network", "Block-all-incoming mode is ON"))

    # 1d. Auto-allow signed
    out, _ = safe_run("socketfilterfw", ["--getallowsigned"])
    if out and "enabled" in out.lower():
        findings.append(Finding(INFO, "Network", "Signed apps auto-allowed through firewall"))

    # 1e. Listening ports
    out, _ = safe_run("lsof", ["-iTCP", "-sTCP:LISTEN", "-nP"], timeout=15)
    if out:
        known_safe = {
            "rapportd", "sharingd", "WiFiAgent", "ControlCenter", "ControlCe",
            "UserEventAgent", "SystemUIServer", "loginwindow", "remoted",
            "identityservicesd", "mDNSResponder", "launchd", "httpd",
            "ollama", "OneDrive", "Python", "node", "Code Helper",
            "Finder", "AirPlayXPCSe", "screensharingd",
        }
        lines = out.strip().split("\n")[1:]
        suspicious = []
        for line in lines:
            parts = line.split()
            if parts and parts[0] not in known_safe:
                suspicious.append(line)
        if suspicious:
            findings.append(Finding(WARNING, "Network",
                f"{len(suspicious)} unexpected listening port(s)",
                "\n".join(suspicious[:10]),
                fix="Review — kill unrecognized: kill <PID>"))
        else:
            findings.append(Finding(OK, "Network", "No unexpected listening ports"))

    # 1f. Active outbound connections to unusual destinations
    out, _ = safe_run("lsof", ["-iTCP", "-sTCP:ESTABLISHED", "-nP"], timeout=15)
    if out:
        lines = out.strip().split("\n")[1:]
        foreign_conns = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 9:
                dest = parts[8]  # e.g. 1.2.3.4:443
                if "->" in dest:
                    dest = dest.split("->")[1]
                # Flag non-443/80 ports to unusual destinations
                if ":" in dest:
                    port = dest.split(":")[-1]
                    if port not in ("443", "80", "993", "587", "53", "8443", "5228",
                                    "11434", "42050", "8844", "5223", "5222"):
                        proc = parts[0]
                        if proc not in ("mDNSRespo", "identitys", "rapportd", "apsd"):
                            foreign_conns.append(f"{proc}: {dest}")
        if foreign_conns:
            findings.append(Finding(INFO, "Network",
                f"{len(foreign_conns)} connection(s) on non-standard ports",
                "\n".join(list(set(foreign_conns))[:10])))

    # 1g. DNS
    out, _ = safe_run("networksetup", ["-getdnsservers", "Wi-Fi"])
    if out and "aren't any" not in out.lower():
        dns_servers = [s.strip() for s in out.split("\n") if s.strip()]
        trusted_dns = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                       "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"}
        untrusted = [d for d in dns_servers if d not in trusted_dns]
        if untrusted:
            findings.append(Finding(WARNING, "Network",
                f"Non-standard DNS: {', '.join(untrusted)}",
                fix="If unexpected: networksetup -setdnsservers Wi-Fi empty"))
        else:
            findings.append(Finding(OK, "Network", "DNS servers are trusted"))
    else:
        findings.append(Finding(OK, "Network", "DNS set to automatic (DHCP)"))

    # 1h. Proxy settings
    for proxy_type, label in [("webproxy", "HTTP Proxy"), ("securewebproxy", "HTTPS Proxy"),
                               ("socksfirewallproxy", "SOCKS Proxy")]:
        out, _ = safe_run("networksetup", [f"-get{proxy_type}", "Wi-Fi"])
        if out and "enabled: yes" in out.lower():
            findings.append(Finding(WARNING, "Network",
                f"{label} is configured on Wi-Fi",
                detail=out[:200],
                fix=f"If unexpected: networksetup -set{proxy_type}state Wi-Fi off"))

    # 1i. VPN
    out, _ = safe_run("networksetup", ["-listallnetworkservices"])
    if out:
        vpn_services = [l.strip() for l in out.split("\n")
                        if any(v in l.lower() for v in ["vpn", "tunnel", "wireguard"])]
        if vpn_services:
            findings.append(Finding(INFO, "Network",
                f"VPN service(s): {', '.join(vpn_services)}"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2: SYSTEM INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════

def check_system_integrity():
    findings = []

    # 2a. SIP
    out, _ = safe_run("csrutil", ["status"])
    if out:
        if "enabled" in out.lower():
            findings.append(Finding(OK, "System", "System Integrity Protection (SIP) is enabled"))
        else:
            findings.append(Finding(CRITICAL, "System", "SIP is DISABLED",
                fix="Boot Recovery Mode (Cmd+R) > csrutil enable"))

    # 2b. Gatekeeper
    out, _ = safe_run("spctl", ["--status"])
    if out:
        if "enabled" in out.lower():
            findings.append(Finding(OK, "System", "Gatekeeper is enabled"))
        else:
            findings.append(Finding(CRITICAL, "System", "Gatekeeper is DISABLED",
                fix="sudo spctl --master-enable"))

    # 2c. FileVault
    out, _ = safe_run("fdesetup", ["status"])
    if out:
        if "on" in out.lower():
            findings.append(Finding(OK, "System", "FileVault disk encryption is ON"))
        else:
            findings.append(Finding(CRITICAL, "System", "FileVault is OFF — disk NOT encrypted",
                fix="System Settings > Privacy & Security > FileVault > Turn On"))

    # 2d. XProtect
    xprotect_paths = [
        pathlib.Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle"),
        pathlib.Path("/System/Library/CoreServices/XProtect.bundle"),
    ]
    for xp in xprotect_paths:
        if xp.exists():
            info_plist = xp / "Contents" / "Info.plist"
            if info_plist.exists():
                try:
                    with open(info_plist, "rb") as f:
                        pdata = plistlib.load(f)
                    ver = pdata.get("CFBundleShortVersionString", "?")
                    findings.append(Finding(OK, "System", f"XProtect active (v{ver})"))
                except Exception:
                    findings.append(Finding(OK, "System", "XProtect is present"))
            break
    else:
        findings.append(Finding(WARNING, "System", "XProtect not found"))

    # 2e. Secure Boot
    out, _ = safe_run("system_profiler", ["SPiBridgeDataType"], timeout=15)
    if out and "secure boot" in out.lower():
        if "full security" in out.lower():
            findings.append(Finding(OK, "System", "Secure Boot: Full Security"))
        elif "medium security" in out.lower():
            findings.append(Finding(WARNING, "System", "Secure Boot: Medium Security",
                fix="Recovery Mode > Startup Security Utility > Full Security"))
        elif "no security" in out.lower():
            findings.append(Finding(CRITICAL, "System", "Secure Boot: NO SECURITY",
                fix="Recovery Mode > Startup Security Utility > Full Security"))

    # 2f. LaunchAgents/Daemons
    known_prefixes = {
        "com.apple.", "com.google.", "com.microsoft.", "com.adobe.",
        "com.spotify.", "com.docker.", "com.zoom.", "com.guardian.",
        "com.github.", "com.brave.", "org.mozilla.", "com.logi.",
        "us.zoom.", "com.dropbox.", "com.jetbrains.", "com.slack.",
        "homebrew.", "com.valvesoftware.", "com.grammarly.",
        "com.twincatcher.", "com.jarvis.", "org.chromium.",
        "com.objective-see.", "com.malwarebytes.", "com.1password.",
        "com.McAfee.", "com.symantec.", "com.kaspersky.",
        "org.wireshark.", "com.sublimetext.", "com.visualstudio.",
        "com.electron.", "io.github.", "org.videolan.",
        "com.cursor.", "com.todesktop.",
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
                if not any(f.stem.startswith(p) for p in known_prefixes):
                    detail_info = str(f)
                    try:
                        with open(f, "rb") as pf:
                            pdata = plistlib.load(pf)
                        prog = pdata.get("Program") or ""
                        prog_args = pdata.get("ProgramArguments", [])
                        if prog:
                            detail_info += f"\n  Program: {prog}"
                        elif prog_args:
                            detail_info += f"\n  Command: {' '.join(str(a) for a in prog_args[:3])}"
                    except Exception:
                        pass
                    unknown_agents.append(detail_info)
    if unknown_agents:
        findings.append(Finding(WARNING, "System",
            f"{len(unknown_agents)} unknown LaunchAgent/Daemon(s)",
            "\n".join(unknown_agents[:15]),
            fix="Review each — remove any you don't recognize"))
    else:
        findings.append(Finding(OK, "System", "No unknown LaunchAgents/Daemons"))

    # 2g. Kernel extensions
    kext_dir = pathlib.Path("/Library/Extensions")
    if kext_dir.is_dir():
        kexts = [f.name for f in kext_dir.iterdir() if f.suffix == ".kext"]
        if kexts:
            findings.append(Finding(INFO, "System",
                f"{len(kexts)} third-party kernel extension(s)",
                "\n".join(kexts[:10])))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3: PRIVACY
# ══════════════════════════════════════════════════════════════════════════════

def check_privacy():
    findings = []

    # 3a. Remote Login
    out, _ = safe_run("launchctl", ["print", "system/com.openssh.sshd"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(WARNING, "Privacy", "Remote Login (SSH) is enabled",
            fix="System Settings > General > Sharing > Remote Login OFF"))
    else:
        findings.append(Finding(OK, "Privacy", "Remote Login (SSH) is disabled"))

    # 3b. Screen Sharing
    out, _ = safe_run("launchctl", ["print", "system/com.apple.screensharing"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(WARNING, "Privacy", "Screen Sharing is enabled",
            fix="System Settings > General > Sharing > Screen Sharing OFF"))
    else:
        findings.append(Finding(OK, "Privacy", "Screen Sharing is disabled"))

    # 3c. Remote Apple Events
    out, _ = safe_run("launchctl", ["print", "system/com.apple.AEServer"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(WARNING, "Privacy", "Remote Apple Events enabled",
            fix="System Settings > General > Sharing > Remote Apple Events OFF"))

    # 3d. File Sharing
    out, _ = safe_run("launchctl", ["print", "system/com.apple.smbd"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(INFO, "Privacy", "File Sharing (SMB) is enabled",
            fix="Disable if not needed: System Settings > General > Sharing"))

    # 3e. TCC.db audit
    tcc_path = pathlib.Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    tcc_services = [
        ("kTCCServiceCamera", "Camera"),
        ("kTCCServiceMicrophone", "Microphone"),
        ("kTCCServiceScreenCapture", "Screen Recording"),
        ("kTCCServiceAccessibility", "Accessibility"),
        ("kTCCServiceSystemPolicyAllFiles", "Full Disk Access"),
        ("kTCCServiceAppleEvents", "Automation"),
        ("kTCCServiceSystemPolicyDesktopFolder", "Desktop Folder"),
        ("kTCCServiceSystemPolicyDocumentsFolder", "Documents Folder"),
        ("kTCCServiceSystemPolicyDownloadsFolder", "Downloads Folder"),
    ]
    if tcc_path.is_file():
        try:
            conn = sqlite3.connect(f"file:{tcc_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            for svc_id, svc_name in tcc_services:
                try:
                    cursor.execute(
                        "SELECT client FROM access WHERE service=? AND auth_value=2",
                        (svc_id,))
                    apps = [row[0] for row in cursor.fetchall()]
                    if apps:
                        findings.append(Finding(INFO, "Privacy",
                            f"{len(apps)} app(s) have {svc_name} access",
                            "\n".join(apps[:10]),
                            fix=f"Review: System Settings > Privacy & Security > {svc_name}"))
                except Exception:
                    pass
            conn.close()
        except Exception:
            findings.append(Finding(INFO, "Privacy",
                "TCC.db not directly readable (normal on newer macOS)"))

    # 3f. Analytics sharing
    analytics_prefs = pathlib.Path("/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist")
    if analytics_prefs.exists():
        try:
            with open(analytics_prefs, "rb") as f:
                data = plistlib.load(f)
            if data.get("AutoSubmit", False):
                findings.append(Finding(INFO, "Privacy",
                    "Diagnostic data sharing is ON",
                    fix="System Settings > Privacy & Security > Analytics & Improvements"))
        except Exception:
            pass

    # 3g. Location services
    location_plist = pathlib.Path("/var/db/locationd/clients.plist")
    if location_plist.exists():
        try:
            with open(location_plist, "rb") as f:
                loc_data = plistlib.load(f)
            loc_apps = [k for k in loc_data.keys() if not k.startswith("com.apple.")]
            if loc_apps:
                findings.append(Finding(INFO, "Privacy",
                    f"{len(loc_apps)} third-party app(s) have location access",
                    "\n".join(loc_apps[:10])))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4: MALWARE INDICATORS
# ══════════════════════════════════════════════════════════════════════════════

def check_malware_indicators():
    findings = []

    # 4a. Known malware paths (expanded)
    home = pathlib.Path.home()
    malware_paths = [
        "/Library/Application Support/JavaW",
        "/Library/Application Support/amc",
        "/Library/Application Support/VSearch",
        "/Library/Application Support/Conduit",
        "/Library/Application Support/Genieo",
        "/Library/Application Support/macAutoFixer",
        "/Library/Application Support/dz0",
        "/Library/LaunchAgents/com.pcv.hlpramc.plist",
        "/Library/LaunchAgents/com.startup.plist",
        "/Library/LaunchAgents/com.updater.mcy.plist",
        "/Library/LaunchAgents/com.avickUpd.plist",
        "/Library/LaunchDaemons/com.machelper.plist",
        "/Library/LaunchDaemons/com.apple.installer.plist",
        "/Library/LaunchDaemons/com.apple.sysmond.plist",
        home / "Library/LaunchAgents/com.pcv.hlpramc.plist",
        home / "Library/LaunchAgents/com.startup.plist",
        home / "Library/LaunchAgents/com.updater.mcy.plist",
        home / "Library/LaunchAgents/com.ExpertModuleSearchP.plist",
        home / ".local/sysupd",
        "/tmp/.hidden_payload", "/var/tmp/.hidden_payload", "/private/tmp/.hidden",
        "/Library/LaunchDaemons/com.Eltima.UpdaterAgent.plist",
        "/tmp/agent.sh", "/tmp/version.json", "/tmp/version.plist",
        home / ".xcassets",
        # Atomic Stealer
        home / "Library/LaunchAgents/com.apple.atos.plist",
        # Cuckoo spyware
        "/Library/LaunchDaemons/com.cril.atos.plist",
        # Activator trojan
        home / "Library/LaunchAgents/com.apple.atoslauncher.plist",
    ]
    found = [str(p) for p in malware_paths if pathlib.Path(p).exists()]
    if found:
        findings.append(Finding(CRITICAL, "Malware",
            f"{len(found)} known malware indicator(s)!", "\n".join(found),
            fix="Investigate and remove. Consider running Apple MRT or ClamAV scan."))
    else:
        findings.append(Finding(OK, "Malware", "No known malware file indicators"))

    # 4b. Suspicious processes
    out, _ = safe_run("ps", ["-axo", "pid,comm"], timeout=10)
    if out:
        bad_names = {
            "cryptominer", "xmrig", "coinhive", "coinminer", "minerd",
            "kworker", "bioset", "ksoftirqd", "osascript.hidden", ".hidden",
            "sysmond_helper", "updater_agent", "atos_launcher",
        }
        sus = []
        for line in out.strip().split("\n"):
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                p = parts[1].lower()
                bn = os.path.basename(p)
                if (bn in bad_names or p.startswith("/tmp/")
                        or p.startswith("/var/tmp/") or p.startswith("/private/tmp/")):
                    sus.append(line.strip())
        if sus:
            findings.append(Finding(CRITICAL, "Malware",
                f"{len(sus)} suspicious process(es)!", "\n".join(sus[:10]),
                fix="Kill: kill -9 <PID>"))
        else:
            findings.append(Finding(OK, "Malware", "No suspicious processes"))

    # 4c. High CPU (cryptominer detection)
    out, _ = safe_run("ps", ["-axo", "pid,%cpu,comm", "-r"], timeout=10)
    if out:
        safe_high_cpu = {"windowserver", "kernel_task", "mdworker", "mds_stores",
                         "photolibraryd", "photoanalysisd", "xcode", "swift", "clang",
                         "python", "node", "ollama", "code helper", "compiling",
                         "softwareupdate", "installer"}
        for line in out.strip().split("\n")[1:20]:
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                try:
                    cpu = float(parts[1])
                    proc = parts[2]
                    if cpu > 80 and not any(k in proc.lower() for k in safe_high_cpu):
                        findings.append(Finding(WARNING, "Malware",
                            f"High CPU: {proc} ({cpu}%)",
                            fix="Investigate — possible cryptominer"))
                except ValueError:
                    pass

    # 4d. Cron jobs
    out, _ = safe_run("crontab", ["-l"], timeout=10)
    if out and "no crontab" not in out.lower():
        findings.append(Finding(WARNING, "Malware", "User cron jobs found",
            out[:500], fix="Review: crontab -l"))
    else:
        findings.append(Finding(OK, "Malware", "No user cron jobs"))

    # 4e. Periodic scripts
    custom = []
    for d in ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]:
        p = pathlib.Path(d)
        if p.is_dir():
            for f in p.iterdir():
                if not re.match(r"^\d{3}\.", f.name):
                    custom.append(str(f))
    if custom:
        findings.append(Finding(WARNING, "Malware",
            f"{len(custom)} custom periodic script(s)", "\n".join(custom[:10])))
    else:
        findings.append(Finding(OK, "Malware", "No custom periodic scripts"))

    # 4f. Dotfiles audit
    known_dots = {
        ".bash_history", ".bash_profile", ".bashrc", ".zshrc", ".zsh_history",
        ".zprofile", ".zsh_sessions", ".profile", ".gitconfig", ".gitignore_global",
        ".ssh", ".gnupg", ".npm", ".config", ".local", ".cache", ".docker",
        ".vscode", ".cursor", ".DS_Store", ".CFUserTextEncoding", ".Trash",
        ".cups", ".lesshst", ".python_history", ".node_repl_history",
        ".guardian", ".ollama", ".continuum", ".claude", ".claude.json",
        ".conda", ".jupyter", ".ipython", ".matplotlib", ".keras",
        ".streamlit", ".viminfo", ".wget-hsts", ".netrc",
        ".jarvis_memory.json", ".jarvis_notes.json", ".jarvis_routines.json",
        ".swiftpm", ".templateengine", ".zcompdump", ".zsh_history",
        ".Xauthority", ".osquery",
    }
    try:
        odd = [f.name for f in home.iterdir()
               if f.name.startswith(".") and f.name not in known_dots]
    except Exception:
        odd = []
    if odd:
        findings.append(Finding(INFO, "Malware",
            f"{len(odd)} uncommon dotfile(s) in ~",
            "\n".join(sorted(odd)[:15])))

    # 4g. Executables in /tmp
    tmp_execs = []
    for td in ["/tmp", "/var/tmp", "/private/tmp"]:
        p = pathlib.Path(td)
        if not p.is_dir():
            continue
        try:
            for f in p.iterdir():
                try:
                    if f.is_file() and os.access(str(f), os.X_OK):
                        tmp_execs.append(str(f))
                except Exception:
                    pass
        except Exception:
            pass
    if tmp_execs:
        findings.append(Finding(WARNING, "Malware",
            f"{len(tmp_execs)} executable(s) in /tmp",
            "\n".join(tmp_execs[:10]),
            fix="Review and delete suspicious executables from /tmp"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5: USER ACCOUNTS
# ══════════════════════════════════════════════════════════════════════════════

def check_user_accounts():
    findings = []

    # 5a. User list
    out, _ = safe_run("dscl", [".", "-list", "/Users"], timeout=10)
    if out:
        real = [u.strip() for u in out.split("\n") if u.strip()
                and not u.strip().startswith("_")
                and u.strip() not in {"daemon", "nobody", "root", "Guest"}]
        findings.append(Finding(INFO, "Accounts", f"User accounts: {', '.join(real)}"))
        if len(real) > 3:
            findings.append(Finding(WARNING, "Accounts",
                f"{len(real)} user accounts — verify all expected"))

    # 5b. Admin users
    out, _ = safe_run("dscl", [".", "-read", "/Groups/admin", "GroupMembership"], timeout=10)
    if out and ":" in out:
        admins = out.split(":", 1)[1].strip().split()
        findings.append(Finding(INFO, "Accounts", f"Admin users: {', '.join(admins)}"))
        if len(admins) > 2:
            findings.append(Finding(WARNING, "Accounts",
                f"{len(admins)} admin accounts — minimize for security"))

    # 5c. Guest account
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], timeout=10)
    if out:
        if out.strip() == "1":
            findings.append(Finding(WARNING, "Accounts", "Guest account is ENABLED",
                fix="System Settings > Users & Groups > Guest User > OFF"))
        else:
            findings.append(Finding(OK, "Accounts", "Guest account is disabled"))

    # 5d. Auto-login
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"], timeout=10)
    if out and "does not exist" not in out.lower():
        findings.append(Finding(CRITICAL, "Accounts",
            f"Auto-login enabled for: {out.strip()}",
            detail="Anyone who opens your Mac gets full access without a password.",
            fix="System Settings > Users & Groups > Login Options > Auto Login OFF"))
    else:
        findings.append(Finding(OK, "Accounts", "Auto-login is disabled"))

    # 5e. SSH authorized keys
    auth_keys = pathlib.Path.home() / ".ssh" / "authorized_keys"
    if auth_keys.is_file():
        try:
            keys = [l for l in auth_keys.read_text().strip().split("\n")
                    if l.strip() and not l.strip().startswith("#")]
            if keys:
                findings.append(Finding(WARNING, "Accounts",
                    f"{len(keys)} SSH authorized key(s) — verify all yours",
                    fix=f"Review: cat {auth_keys}"))
        except Exception:
            pass
    else:
        findings.append(Finding(OK, "Accounts", "No SSH authorized_keys"))

    # 5f. SSH permissions
    ssh_dir = pathlib.Path.home() / ".ssh"
    if ssh_dir.is_dir():
        bad = []
        try:
            dm = oct(ssh_dir.stat().st_mode)[-3:]
            if dm != "700":
                bad.append(f"~/.ssh: {dm} (need 700)")
            for f in ssh_dir.iterdir():
                if f.name.startswith("id_") and not f.name.endswith(".pub"):
                    m = oct(f.stat().st_mode)[-3:]
                    if m != "600":
                        bad.append(f"{f.name}: {m} (need 600)")
        except Exception:
            pass
        if bad:
            findings.append(Finding(WARNING, "Accounts", "SSH permissions too open",
                "\n".join(bad), fix="chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*"))
        else:
            findings.append(Finding(OK, "Accounts", "SSH permissions correct"))

    # 5g. Recent login history
    out, _ = safe_run("last", ["-10"], timeout=10)
    if out:
        lines = [l for l in out.strip().split("\n") if l.strip() and "wtmp" not in l.lower()]
        if lines:
            findings.append(Finding(INFO, "Accounts",
                f"Recent logins (last 10):\n" + "\n".join(lines[:5])))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 6: SOFTWARE UPDATES
# ══════════════════════════════════════════════════════════════════════════════

def check_software_updates():
    findings = []

    out, err = safe_run("softwareupdate", ["-l"], timeout=120)
    combined = (out or "") + "\n" + (err or "")
    if "no new software available" in combined.lower():
        findings.append(Finding(OK, "Updates", "macOS is up to date"))
    elif "software update found" in combined.lower() or "label:" in combined.lower():
        updates = []
        sec_update = False
        for line in combined.split("\n"):
            line = line.strip()
            if line.startswith("*") or line.startswith("Label:"):
                name = line.lstrip("* ").replace("Label:", "").strip()
                updates.append(name)
                if "security" in name.lower():
                    sec_update = True
        sev = CRITICAL if sec_update else WARNING
        findings.append(Finding(sev, "Updates",
            f"{len(updates)} update(s) available" +
            (" (SECURITY update!)" if sec_update else ""),
            "\n".join(updates[:10]),
            fix="System Settings > General > Software Update"))
    else:
        findings.append(Finding(INFO, "Updates", "Could not determine update status"))

    # Auto-update settings
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(WARNING, "Updates", "Auto update checking DISABLED",
            fix="System Settings > General > Software Update > Automatic Updates ON"))
    else:
        findings.append(Finding(OK, "Updates", "Auto update checking enabled"))

    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(WARNING, "Updates",
            "Auto security response updates DISABLED",
            fix="System Settings > Software Update > Security Responses ON"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 7: LOCK SCREEN & AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def check_lock_screen():
    findings = []

    # 7a. Password after screensaver
    out, _ = safe_run("defaults", ["read", "com.apple.screensaver", "askForPassword"], timeout=10)
    if out:
        if out.strip() == "1":
            findings.append(Finding(OK, "Lock Screen", "Password required after screensaver"))
        else:
            findings.append(Finding(CRITICAL, "Lock Screen",
                "Password NOT required after screensaver",
                detail="Anyone can use your Mac after screensaver activates.",
                fix="System Settings > Lock Screen > Require password: Immediately"))

    # 7b. Password delay
    out, _ = safe_run("defaults", ["read", "com.apple.screensaver", "askForPasswordDelay"], timeout=10)
    if out:
        try:
            delay = int(out.strip())
            if delay > 5:
                findings.append(Finding(WARNING, "Lock Screen",
                    f"Password delay: {delay}s after screensaver",
                    fix="Set to Immediately in System Settings > Lock Screen"))
            else:
                findings.append(Finding(OK, "Lock Screen",
                    f"Password required within {delay}s"))
        except ValueError:
            pass

    # 7c. Screensaver timeout
    out, _ = safe_run("defaults", ["read", "com.apple.screensaver", "idleTime"], timeout=10)
    if out:
        try:
            idle = int(out.strip())
            if idle == 0:
                findings.append(Finding(WARNING, "Lock Screen",
                    "Screensaver set to NEVER",
                    fix="System Settings > Lock Screen > Start Screen Saver: 5 minutes"))
            elif idle > 600:
                findings.append(Finding(WARNING, "Lock Screen",
                    f"Screensaver: {idle // 60} min (recommend 5 min)",
                    fix="System Settings > Lock Screen > Start Screen Saver: 5 minutes"))
            else:
                findings.append(Finding(OK, "Lock Screen",
                    f"Screensaver: {idle // 60} min"))
        except ValueError:
            pass

    # 7d. Display sleep
    out, _ = safe_run("pmset", ["-g", "custom"], timeout=10)
    if out:
        for line in out.split("\n"):
            if "displaysleep" in line.lower():
                parts = line.strip().split()
                try:
                    val = int(parts[-1])
                    if val == 0:
                        findings.append(Finding(WARNING, "Lock Screen",
                            "Display sleep: NEVER",
                            fix="System Settings > Energy > Turn display off: 5 minutes"))
                    elif val > 15:
                        findings.append(Finding(INFO, "Lock Screen",
                            f"Display sleeps after {val} min"))
                except (ValueError, IndexError):
                    pass
                break

    # 7e. Password hints
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"], timeout=10)
    if out:
        try:
            r = int(out.strip())
            if r > 0:
                findings.append(Finding(INFO, "Lock Screen",
                    f"Password hint after {r} failed attempt(s)",
                    fix="sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"))
        except ValueError:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 8: BACKUP & RECOVERY
# ══════════════════════════════════════════════════════════════════════════════

def check_backups():
    findings = []

    out, _ = safe_run("tmutil", ["status"], timeout=15)
    if out:
        findings.append(Finding(OK, "Backup", "Time Machine is configured"))
    else:
        findings.append(Finding(WARNING, "Backup", "Time Machine may not be configured",
            fix="System Settings > General > Time Machine > Add Backup Disk"))

    out, _ = safe_run("tmutil", ["latestbackup"], timeout=15)
    if out and "/" in out:
        match = re.search(r"(\d{4}-\d{2}-\d{2})", out)
        if match:
            try:
                bdate = datetime.datetime.strptime(match.group(1), "%Y-%m-%d")
                days = (datetime.datetime.now() - bdate).days
                if days > 7:
                    findings.append(Finding(WARNING, "Backup",
                        f"Last backup: {days} days ago ({match.group(1)})",
                        fix="Connect backup disk and run Time Machine"))
                else:
                    findings.append(Finding(OK, "Backup",
                        f"Last backup: {match.group(1)} ({days}d ago)"))
            except ValueError:
                findings.append(Finding(INFO, "Backup", f"Last backup: {out}"))
    else:
        findings.append(Finding(WARNING, "Backup", "No Time Machine backups found",
            fix="Set up: System Settings > General > Time Machine"))

    out, _ = safe_run("tmutil", ["destinationinfo"], timeout=15)
    if out and ("encrypted" in out.lower()):
        findings.append(Finding(OK, "Backup", "Time Machine backup is encrypted"))
    elif out and "name" in out.lower():
        findings.append(Finding(WARNING, "Backup",
            "Time Machine backup may not be encrypted",
            fix="Enable encryption when adding backup disk"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 9: FILE SYSTEM SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def check_filesystem():
    findings = []
    home = pathlib.Path.home()

    # 9a. Home dir permissions
    try:
        hm = oct(home.stat().st_mode)[-3:]
        if hm in ("700", "750", "755"):
            findings.append(Finding(OK, "Filesystem", f"Home permissions: {hm}"))
        else:
            findings.append(Finding(WARNING, "Filesystem",
                f"Home permissions too open: {hm}", fix=f"chmod 750 {home}"))
    except Exception:
        pass

    # 9b. World-writable sensitive files
    ww = []
    for d in [home / ".ssh", home / ".gnupg"]:
        if not d.is_dir():
            continue
        try:
            for f in d.iterdir():
                if f.is_file() and f.stat().st_mode & stat.S_IWOTH:
                    ww.append(str(f))
        except Exception:
            pass
    if ww:
        findings.append(Finding(WARNING, "Filesystem",
            f"{len(ww)} world-writable sensitive file(s)",
            "\n".join(ww[:10]), fix="chmod o-w <file>"))

    # 9c. Credential file permissions
    creds = [
        (".netrc", "Plaintext credentials"),
        (".env", "Environment vars / API keys"),
        (".aws/credentials", "AWS credentials"),
        (".docker/config.json", "Docker registry tokens"),
    ]
    for fname, desc in creds:
        fp = home / fname
        if fp.is_file():
            m = oct(fp.stat().st_mode)[-3:]
            if m not in ("600", "400"):
                findings.append(Finding(WARNING, "Filesystem",
                    f"~/{fname} too open ({m})", detail=desc,
                    fix=f"chmod 600 ~/{fname}"))

    # 9d. Old installers in Downloads
    dl = home / "Downloads"
    if dl.is_dir():
        exts = {".command", ".sh", ".scpt", ".applescript", ".pkg", ".dmg"}
        cutoff = time.time() - (90 * 86400)
        old = []
        try:
            for f in dl.iterdir():
                if f.suffix.lower() in exts and f.stat().st_mtime < cutoff:
                    old.append(f.name)
        except Exception:
            pass
        if old:
            findings.append(Finding(INFO, "Filesystem",
                f"{len(old)} old installer/script(s) in Downloads",
                "\n".join(old[:10]),
                fix="Delete old .dmg/.pkg/.command files"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 10: HARDWARE & POWER
# ══════════════════════════════════════════════════════════════════════════════

def check_hardware():
    findings = []

    out, _ = safe_run("system_profiler", ["SPHardwareDataType"], timeout=15)
    if out:
        if "apple m" in out.lower():
            findings.append(Finding(OK, "Hardware", "Apple Silicon (Secure Enclave present)"))
        elif "t2" in out.lower():
            findings.append(Finding(OK, "Hardware", "T2 chip (hardware encryption)"))
        for line in out.split("\n"):
            if "serial number" in line.lower():
                findings.append(Finding(INFO, "Hardware", line.strip()))
                break

    out, _ = safe_run("pmset", ["-g"], timeout=10)
    if out:
        for line in out.split("\n"):
            if "womp" in line.lower():
                try:
                    if int(line.strip().split()[-1]) == 1:
                        findings.append(Finding(INFO, "Hardware",
                            "Wake on LAN enabled",
                            fix="If not needed: sudo pmset -a womp 0"))
                except (ValueError, IndexError):
                    pass
            if "powernap" in line.lower():
                try:
                    if int(line.strip().split()[-1]) == 1:
                        findings.append(Finding(INFO, "Hardware",
                            "Power Nap enabled (wakes for updates)"))
                except (ValueError, IndexError):
                    pass

    out, _ = safe_run("diskutil", ["info", "/"], timeout=15)
    if out:
        for line in out.split("\n"):
            if "smart status" in line.lower() or "s.m.a.r.t" in line.lower():
                if "verified" in line.lower():
                    findings.append(Finding(OK, "Hardware", "Disk SMART: Verified"))
                elif "failing" in line.lower():
                    findings.append(Finding(CRITICAL, "Hardware",
                        "Disk SMART: FAILING!",
                        fix="BACK UP DATA NOW — disk may fail soon"))
                break

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 11: BROWSER SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def check_browser_security():
    findings = []
    home = pathlib.Path.home()

    browsers = {
        "Chrome": home / "Library/Application Support/Google/Chrome",
        "Brave": home / "Library/Application Support/BraveSoftware/Brave-Browser",
        "Firefox": home / "Library/Application Support/Firefox/Profiles",
        "Edge": home / "Library/Application Support/Microsoft Edge",
    }

    for name, path in browsers.items():
        if not path.is_dir():
            continue

        # Chromium-based extension scanning
        if name in ("Chrome", "Brave", "Edge"):
            ext_dirs = []
            # Find all profile extension directories
            for profile_dir in path.iterdir():
                ext_path = profile_dir / "Extensions" if profile_dir.is_dir() else None
                if ext_path and ext_path.is_dir():
                    ext_dirs.append(ext_path)
            # Also check Default profile
            default_ext = path / "Default" / "Extensions"
            if default_ext.is_dir():
                ext_dirs.append(default_ext)

            extensions = set()
            for ext_dir in ext_dirs:
                try:
                    for ext in ext_dir.iterdir():
                        if ext.is_dir() and ext.name != "Temp":
                            # Try to read manifest for name
                            ext_name = ext.name
                            for ver_dir in ext.iterdir():
                                manifest = ver_dir / "manifest.json"
                                if manifest.is_file():
                                    try:
                                        with open(manifest) as mf:
                                            data = json.loads(mf.read())
                                        ext_name = data.get("name", ext.name)
                                        if ext_name.startswith("__MSG_"):
                                            ext_name = ext.name
                                    except Exception:
                                        pass
                                    break
                            extensions.add(ext_name)
                except Exception:
                    pass

            if extensions:
                findings.append(Finding(INFO, "Browser",
                    f"{name}: {len(extensions)} extension(s)",
                    "\n".join(sorted(extensions)[:15]),
                    fix=f"Review in {name} > Extensions — remove unused ones"))

        # Firefox addon scanning
        elif name == "Firefox":
            try:
                for profile in path.iterdir():
                    addons_json = profile / "addons.json"
                    if addons_json.is_file():
                        with open(addons_json) as f:
                            data = json.loads(f.read())
                        addons = [a.get("name", "?") for a in data.get("addons", [])
                                  if a.get("type") == "extension" and a.get("active")]
                        if addons:
                            findings.append(Finding(INFO, "Browser",
                                f"Firefox: {len(addons)} extension(s)",
                                "\n".join(addons[:15]),
                                fix="Review in Firefox > Add-ons"))
                        break
            except Exception:
                pass

    # Safari extensions (basic check)
    safari_ext = home / "Library/Safari/Extensions"
    if safari_ext.is_dir():
        try:
            exts = [f.stem for f in safari_ext.iterdir()
                    if f.suffix in (".safariextz", ".appex")]
            if exts:
                findings.append(Finding(INFO, "Browser",
                    f"Safari: {len(exts)} extension(s)",
                    "\n".join(exts[:10])))
        except Exception:
            pass

    if not findings:
        findings.append(Finding(OK, "Browser", "No browser extensions detected"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 12: CERTIFICATE TRUST STORE (MITM detection)
# ══════════════════════════════════════════════════════════════════════════════

def check_certificates():
    findings = []

    # Check user keychain for manually trusted root certificates
    out, _ = safe_run("security", ["dump-trust-settings", "-d"], timeout=15)
    if out:
        # Count non-Apple trusted roots
        certs = re.findall(r"Cert \d+ :\s*(.+)", out)
        if certs:
            findings.append(Finding(WARNING, "Certificates",
                f"{len(certs)} admin-trusted certificate(s) in trust store",
                "\n".join(certs[:10]),
                fix="Review: Keychain Access > System Roots — remove any you don't recognize"))
        else:
            findings.append(Finding(OK, "Certificates", "No extra admin-trusted certificates"))
    else:
        findings.append(Finding(OK, "Certificates", "No custom admin-trusted certificates"))

    # Check user trust settings
    out, _ = safe_run("security", ["dump-trust-settings"], timeout=15)
    if out and "Cert" in out:
        certs = re.findall(r"Cert \d+ :\s*(.+)", out)
        if certs:
            findings.append(Finding(WARNING, "Certificates",
                f"{len(certs)} user-trusted certificate(s)",
                "\n".join(certs[:10]),
                detail="User-trusted certs can enable MITM proxy interception.",
                fix="Review: Keychain Access > login > Certificates"))
    else:
        findings.append(Finding(OK, "Certificates", "No user-trusted custom certificates"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 13: OPTIONAL — osquery (if installed)
# ══════════════════════════════════════════════════════════════════════════════

def check_osquery():
    findings = []

    if "osqueryi" not in OPTIONAL_BINS:
        findings.append(Finding(INFO, "osquery",
            "osquery not installed (optional enhancement)",
            detail="osquery adds deep system visibility — USB history, process trees, socket auditing.",
            fix="Install free: brew install osquery"))
        return findings

    findings.append(Finding(OK, "osquery", "osquery is installed — running enhanced checks"))

    # USB device history
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT vendor, model, last_connected FROM usb_devices LIMIT 15"], timeout=15)
    if out:
        try:
            devices = json.loads(out)
            if devices:
                detail = "\n".join(f"{d.get('vendor','?')} {d.get('model','?')}"
                                   for d in devices[:10])
                findings.append(Finding(INFO, "osquery",
                    f"{len(devices)} USB device(s) in history", detail))
        except Exception:
            pass

    # Listening ports with process info
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT p.name, l.port, l.address, l.protocol FROM listening_ports l "
        "JOIN processes p ON l.pid = p.pid WHERE l.port > 0 LIMIT 20"], timeout=15)
    if out:
        try:
            ports = json.loads(out)
            if ports:
                detail = "\n".join(f"{p.get('name','?')}:{p.get('port','?')} ({p.get('protocol','?')})"
                                   for p in ports[:15])
                findings.append(Finding(INFO, "osquery",
                    f"{len(ports)} listening port(s) (detailed)", detail))
        except Exception:
            pass

    # Open files in /tmp by processes
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT p.name, pof.path FROM process_open_files pof "
        "JOIN processes p ON pof.pid = p.pid "
        "WHERE pof.path LIKE '/tmp/%' OR pof.path LIKE '/var/tmp/%' LIMIT 10"], timeout=15)
    if out:
        try:
            tmp_files = json.loads(out)
            if tmp_files:
                detail = "\n".join(f"{f.get('name','?')}: {f.get('path','?')}"
                                   for f in tmp_files)
                findings.append(Finding(WARNING, "osquery",
                    f"{len(tmp_files)} process(es) with open files in /tmp", detail))
        except Exception:
            pass

    # Startup items
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT name, path, status FROM startup_items LIMIT 20"], timeout=15)
    if out:
        try:
            items = json.loads(out)
            if items:
                detail = "\n".join(f"{i.get('name','?')}: {i.get('path','?')} [{i.get('status','?')}]"
                                   for i in items[:15])
                findings.append(Finding(INFO, "osquery",
                    f"{len(items)} startup item(s)", detail))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 14: OPTIONAL — ClamAV (if installed)
# ══════════════════════════════════════════════════════════════════════════════

def check_clamav():
    findings = []

    if "clamscan" not in OPTIONAL_BINS:
        findings.append(Finding(INFO, "Antivirus",
            "ClamAV not installed (optional enhancement)",
            detail="ClamAV is a free open-source antivirus. Adds real file scanning.",
            fix="Install free: brew install clamav && freshclam"))
        return findings

    findings.append(Finding(OK, "Antivirus", "ClamAV is installed"))

    # Scan /tmp, Downloads, and Desktop (lightweight limits prevent slowdown)
    home = pathlib.Path.home()
    scan_targets = []
    for t in ["/tmp", str(home / "Downloads"), str(home / "Desktop")]:
        if os.path.isdir(t):
            scan_targets.append(t)

    if scan_targets:
        for target in scan_targets:
            out, err = safe_run("clamscan", [
                "--recursive", "--no-summary", "--infected",
                "--max-filesize=10M", "--max-scansize=50M",
                "--max-files=200", "--max-dir-recursion=3",
                target], timeout=120)
            if out:
                infected_lines = [l for l in out.split("\n") if "FOUND" in l]
                if infected_lines:
                    findings.append(Finding(CRITICAL, "Antivirus",
                        f"ClamAV: {len(infected_lines)} infected file(s) in {target}!",
                        "\n".join(infected_lines[:10]),
                        fix="Delete infected files or quarantine them"))
                else:
                    findings.append(Finding(OK, "Antivirus",
                        f"ClamAV scan clean: {target}"))
            else:
                findings.append(Finding(OK, "Antivirus",
                    f"ClamAV scan clean: {target}"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 15: SHARING & AIRDROP
# ══════════════════════════════════════════════════════════════════════════════

def check_sharing():
    findings = []

    # 15a. AirDrop discoverability
    out, _ = safe_run("defaults", ["read", "com.apple.sharingd", "DiscoverableMode"], timeout=10)
    if out:
        mode = out.strip()
        if mode == "Everyone":
            findings.append(Finding(WARNING, "Sharing",
                "AirDrop is set to EVERYONE",
                detail="Anyone nearby can send you files.",
                fix="System Settings > General > AirDrop > Contacts Only (or Off)"))
        elif mode == "Contacts Only":
            findings.append(Finding(OK, "Sharing", "AirDrop: Contacts Only"))
        elif mode == "Off":
            findings.append(Finding(OK, "Sharing", "AirDrop is disabled"))
        else:
            findings.append(Finding(OK, "Sharing", f"AirDrop: {mode}"))

    # 15b. Bluetooth sharing
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.Bluetooth", "PrefKeyServicesEnabled"], timeout=10)
    if out and out.strip() == "1":
        findings.append(Finding(WARNING, "Sharing",
            "Bluetooth Sharing is enabled",
            fix="System Settings > General > Sharing > Bluetooth Sharing OFF"))

    # 15c. Printer sharing
    out, _ = safe_run("launchctl", ["print", "system/org.cups.cupsd"], timeout=10)
    if out:
        # Check if printer sharing is on via cupsctl
        sharing_conf = pathlib.Path("/etc/cups/cupsd.conf")
        if sharing_conf.exists():
            try:
                content = sharing_conf.read_text()
                if "Browsing On" in content or "_remote_any" in content:
                    findings.append(Finding(INFO, "Sharing",
                        "Printer Sharing may be enabled",
                        fix="System Settings > General > Sharing > Printer Sharing OFF"))
            except Exception:
                pass

    # 15d. Media sharing
    out, _ = safe_run("defaults", ["read", "com.apple.amp.mediasharingd", "home-sharing-enabled"], timeout=10)
    if out and out.strip() == "1":
        findings.append(Finding(INFO, "Sharing",
            "Home Media Sharing is enabled"))

    # 15e. Content caching
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.AssetCache", "Activated"], timeout=10)
    if out and out.strip() == "1":
        findings.append(Finding(INFO, "Sharing",
            "Content Caching is enabled (shares Apple updates on network)"))

    if not findings:
        findings.append(Finding(OK, "Sharing", "No unnecessary sharing services detected"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 16: SIRI & LOCK SCREEN EXPOSURE
# ══════════════════════════════════════════════════════════════════════════════

def check_siri_exposure():
    findings = []

    # 16a. Siri enabled
    out, _ = safe_run("defaults", ["read", "com.apple.assistant.support", "Assistant Enabled"], timeout=10)
    if out and out.strip() == "1":
        findings.append(Finding(INFO, "Siri", "Siri is enabled"))

        # 16b. Siri on lock screen
        out, _ = safe_run("defaults", ["read", "com.apple.Siri", "LockscreenEnabled"], timeout=10)
        if out and out.strip() == "1":
            findings.append(Finding(WARNING, "Siri",
                "Siri accessible from LOCK SCREEN",
                detail="Someone can ask Siri questions without unlocking your Mac.",
                fix="System Settings > Siri > Allow Siri When Locked > OFF"))
        else:
            findings.append(Finding(OK, "Siri", "Siri not accessible from lock screen"))
    else:
        findings.append(Finding(OK, "Siri", "Siri is disabled"))

    # 16c. Lock screen notifications
    out, _ = safe_run("defaults", ["read",
        "com.apple.ncprefs", "content_visibility"], timeout=10)
    # This is complex — just check notification center on lock screen
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.loginwindow", "LoginwindowLaunchesRelaunchApps"], timeout=10)

    # 16d. Show owner info on lock screen
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.loginwindow", "LoginwindowText"], timeout=10)
    if out and "does not exist" not in out.lower():
        findings.append(Finding(INFO, "Siri",
            f"Lock screen message set: {out.strip()[:50]}"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 17: CONFIGURATION PROFILES (MDM detection)
# ══════════════════════════════════════════════════════════════════════════════

def check_config_profiles():
    findings = []

    out, _ = safe_run("profiles", ["status", "-type", "enrollment"], timeout=15)
    if out:
        if "mdm" in out.lower() and "yes" in out.lower():
            findings.append(Finding(WARNING, "Profiles",
                "This Mac is enrolled in MDM (Mobile Device Management)",
                detail="An organization can remotely manage this Mac.",
                fix="If this is your personal Mac, remove MDM enrollment"))
        else:
            findings.append(Finding(OK, "Profiles", "No MDM enrollment detected"))
    else:
        findings.append(Finding(OK, "Profiles", "No MDM enrollment"))

    # Check for installed configuration profiles
    out, _ = safe_run("profiles", ["list"], timeout=15)
    if out and "there are no profiles installed" not in out.lower():
        profile_count = out.count("attribute:")
        if profile_count > 0:
            findings.append(Finding(INFO, "Profiles",
                f"{profile_count} configuration profile(s) installed",
                out[:300],
                fix="Review: System Settings > Privacy & Security > Profiles"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 18: NETWORK INTERFACES & HISTORY
# ══════════════════════════════════════════════════════════════════════════════

def check_network_interfaces():
    findings = []

    # 18a. Check for unexpected network interfaces (VPN tunnels, TAP/TUN)
    out, _ = safe_run("ifconfig", ["-a"], timeout=10)
    if out:
        suspicious_ifaces = []
        current_iface = ""
        for line in out.split("\n"):
            if not line.startswith("\t") and ":" in line:
                current_iface = line.split(":")[0]
            if current_iface.startswith(("tap", "tun", "feth", "bridge")):
                if current_iface not in [i[0] for i in suspicious_ifaces]:
                    suspicious_ifaces.append((current_iface, line.strip()))

        if suspicious_ifaces:
            detail = "\n".join(f"{name}: {info}" for name, info in suspicious_ifaces[:5])
            findings.append(Finding(INFO, "Net Interfaces",
                f"{len(suspicious_ifaces)} virtual network interface(s) detected",
                detail))

    # 18b. Check Wi-Fi security type
    out, _ = safe_run("networksetup", ["-getinfo", "Wi-Fi"])
    if out:
        for line in out.split("\n"):
            if "ip address" in line.lower() and ":" in line:
                ip = line.split(":", 1)[1].strip()
                if ip and ip != "none":
                    findings.append(Finding(INFO, "Net Interfaces",
                        f"Wi-Fi IP: {ip}"))
                break

    # 18c. Recent Wi-Fi networks (check for open networks in history)
    wifi_plist = pathlib.Path("/Library/Preferences/com.apple.wifi.known-networks.plist")
    if wifi_plist.exists():
        try:
            with open(wifi_plist, "rb") as f:
                data = plistlib.load(f)
            open_networks = []
            for ssid, info in data.items():
                if isinstance(info, dict):
                    sec_type = info.get("SecurityMode", "")
                    if sec_type == "Open" or "none" in str(sec_type).lower():
                        open_networks.append(ssid)
            if open_networks:
                findings.append(Finding(WARNING, "Net Interfaces",
                    f"{len(open_networks)} open (unencrypted) Wi-Fi network(s) in history",
                    "\n".join(open_networks[:10]),
                    fix="Remove: System Settings > Wi-Fi > (i) next to network > Forget"))
        except Exception:
            pass

    if not findings:
        findings.append(Finding(OK, "Net Interfaces", "Network interfaces look normal"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 19: QUARANTINE & DOWNLOAD HISTORY
# ══════════════════════════════════════════════════════════════════════════════

def check_quarantine():
    findings = []
    home = pathlib.Path.home()

    # macOS quarantine events database
    qdb = home / "Library" / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"
    if qdb.is_file():
        try:
            conn = sqlite3.connect(f"file:{qdb}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Count total quarantine events
            cursor.execute("SELECT COUNT(*) FROM LSQuarantineEvent")
            total = cursor.fetchone()[0]

            # Recent downloads (last 7 days)
            week_ago = time.time() - (7 * 86400)
            # Apple's quarantine timestamps are CoreData format (seconds since 2001-01-01)
            coredata_epoch = 978307200  # Unix timestamp of 2001-01-01
            week_ago_cd = week_ago - coredata_epoch
            cursor.execute(
                "SELECT LSQuarantineDataURLString, LSQuarantineOriginURLString "
                "FROM LSQuarantineEvent WHERE LSQuarantineTimeStamp > ? "
                "ORDER BY LSQuarantineTimeStamp DESC LIMIT 10",
                (week_ago_cd,))
            recent = cursor.fetchall()

            if recent:
                detail_lines = []
                for data_url, origin_url in recent:
                    name = (data_url or "").split("/")[-1] if data_url else "?"
                    source = (origin_url or "")[:60]
                    detail_lines.append(f"{name[:40]}  from: {source}")
                findings.append(Finding(INFO, "Downloads",
                    f"{len(recent)} file(s) downloaded in last 7 days ({total} total)",
                    "\n".join(detail_lines)))

            # Check for suspicious file types downloaded recently
            cursor.execute(
                "SELECT LSQuarantineDataURLString FROM LSQuarantineEvent "
                "WHERE LSQuarantineTimeStamp > ?",
                (week_ago_cd,))
            recent_files = cursor.fetchall()
            sus_downloads = []
            sus_exts = {".command", ".sh", ".scpt", ".terminal", ".tool", ".workflow"}
            for (url,) in recent_files:
                if url:
                    for ext in sus_exts:
                        if url.lower().endswith(ext):
                            sus_downloads.append(url.split("/")[-1])
            if sus_downloads:
                findings.append(Finding(WARNING, "Downloads",
                    f"{len(sus_downloads)} potentially risky download(s) this week",
                    "\n".join(sus_downloads[:10]),
                    fix="Review these files — scripts can be malicious"))

            conn.close()
        except Exception as e:
            findings.append(Finding(INFO, "Downloads",
                f"Could not read quarantine database: {e}"))
    else:
        findings.append(Finding(INFO, "Downloads",
            "Quarantine database not found"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 20: APPLICATION SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def check_app_security():
    findings = []

    # 20a. Check for unsigned or ad-hoc signed apps in /Applications
    apps_dir = pathlib.Path("/Applications")
    unsigned_apps = []
    adhoc_apps = []

    if apps_dir.is_dir():
        try:
            for app in apps_dir.iterdir():
                if not app.suffix == ".app":
                    continue
                out, err = safe_run("codesign", ["-dv", str(app)], timeout=5)
                combined = (out or "") + (err or "")
                if "code object is not signed" in combined.lower():
                    unsigned_apps.append(app.name)
                elif "adhoc" in combined.lower():
                    adhoc_apps.append(app.name)
        except Exception:
            pass

    if unsigned_apps:
        findings.append(Finding(WARNING, "Apps",
            f"{len(unsigned_apps)} unsigned app(s) in /Applications",
            "\n".join(unsigned_apps[:10]),
            fix="Unsigned apps bypass Gatekeeper — verify these are legitimate"))
    if adhoc_apps:
        findings.append(Finding(INFO, "Apps",
            f"{len(adhoc_apps)} ad-hoc signed app(s)",
            "\n".join(adhoc_apps[:10])))

    # 20b. Recently modified apps (potential tampering)
    week_ago = time.time() - (7 * 86400)
    recently_modified = []
    if apps_dir.is_dir():
        try:
            for app in apps_dir.iterdir():
                if app.suffix == ".app":
                    try:
                        mtime = app.stat().st_mtime
                        if mtime > week_ago:
                            date_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
                            recently_modified.append(f"{app.name} (modified {date_str})")
                    except Exception:
                        pass
        except Exception:
            pass
    if recently_modified:
        findings.append(Finding(INFO, "Apps",
            f"{len(recently_modified)} app(s) modified in last 7 days",
            "\n".join(recently_modified[:10])))

    # 20c. Apps from unidentified developers (check quarantine flag)
    out, _ = safe_run("spctl", ["--assess", "--type", "execute", "/Applications/"], timeout=5)
    # This is per-app; just note Gatekeeper status is already covered

    if not findings:
        findings.append(Finding(OK, "Apps", "All applications appear properly signed"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 21: SYSTEM LOG ANALYSIS (failed logins, sudo, auth events)
# ══════════════════════════════════════════════════════════════════════════════

def check_system_logs():
    findings = []

    # 21a. Failed sudo attempts in last 24h
    out, _ = safe_run("log", ["show", "--predicate",
        "process == \"sudo\" AND eventMessage CONTAINS \"incorrect password\"",
        "--style", "compact", "--last", "24h"], timeout=30)
    if out:
        lines = [l for l in out.strip().split("\n") if l.strip() and "Filtering" not in l]
        if len(lines) > 0:
            findings.append(Finding(WARNING, "Logs",
                f"{len(lines)} failed sudo attempt(s) in last 24 hours",
                "\n".join(lines[:5]),
                fix="If these weren't you, investigate — someone may be trying to gain admin access"))
        else:
            findings.append(Finding(OK, "Logs", "No failed sudo attempts in 24h"))
    else:
        findings.append(Finding(OK, "Logs", "No failed sudo attempts in 24h"))

    # 21b. Failed login attempts (screensaver/login window)
    out, _ = safe_run("log", ["show", "--predicate",
        "subsystem == \"com.apple.Authorization\" AND eventMessage CONTAINS \"Failed\"",
        "--style", "compact", "--last", "24h"], timeout=30)
    if out:
        lines = [l for l in out.strip().split("\n") if l.strip() and "Filtering" not in l]
        if len(lines) > 3:
            findings.append(Finding(WARNING, "Logs",
                f"{len(lines)} failed auth events in last 24 hours",
                fix="Multiple failed logins could indicate unauthorized access attempts"))

    # 21c. Kernel panics in last 7 days
    panic_dir = pathlib.Path("/Library/Logs/DiagnosticReports")
    if panic_dir.is_dir():
        week_ago = time.time() - (7 * 86400)
        panics = []
        try:
            for f in panic_dir.iterdir():
                if "panic" in f.name.lower() and f.stat().st_mtime > week_ago:
                    panics.append(f.name)
        except Exception:
            pass
        if panics:
            findings.append(Finding(WARNING, "Logs",
                f"{len(panics)} kernel panic(s) in last 7 days",
                "\n".join(panics[:5]),
                fix="Kernel panics can indicate hardware issues or malicious kernel extensions"))

    # 21d. System uptime (very long uptime = no security updates applied)
    out, _ = safe_run("sysctl", ["-n", "kern.boottime"], timeout=10)
    if out:
        match = re.search(r"sec = (\d+)", out)
        if match:
            boot_ts = int(match.group(1))
            uptime_days = (time.time() - boot_ts) / 86400
            if uptime_days > 30:
                findings.append(Finding(WARNING, "Logs",
                    f"System uptime: {int(uptime_days)} days",
                    detail="Very long uptime means no reboot — security updates often require restart.",
                    fix="Restart your Mac to apply pending updates"))
            else:
                findings.append(Finding(OK, "Logs",
                    f"System uptime: {int(uptime_days)} day(s)"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 22: DEEP SYSTEM HARDENING (final checks)
# ══════════════════════════════════════════════════════════════════════════════

def check_deep_hardening():
    findings = []
    home = pathlib.Path.home()

    # 22a. /etc/hosts hijacking — check for suspicious redirects
    hosts_file = pathlib.Path("/etc/hosts")
    if hosts_file.is_file():
        try:
            content = hosts_file.read_text()
            suspicious_hosts = []
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hostname = parts[1]
                    # Ignore localhost entries and broadcasthost
                    if hostname in ("localhost", "broadcasthost", "localhost.localdomain"):
                        continue
                    # Flag entries redirecting known sites to different IPs
                    if ip not in ("127.0.0.1", "::1", "255.255.255.255", "0.0.0.0", "fe80::1%lo0"):
                        suspicious_hosts.append(f"{ip}  {hostname}")
                    # Also flag if legit domains are redirected to 127.0.0.1 (could be adware)
                    if ip == "127.0.0.1" and any(d in hostname for d in
                            [".google.", ".apple.", ".microsoft.", ".amazon.",
                             ".facebook.", ".instagram.", ".twitter.", ".github."]):
                        suspicious_hosts.append(f"BLOCKED: {hostname} -> {ip}")
            if suspicious_hosts:
                findings.append(Finding(WARNING, "Hardening",
                    f"{len(suspicious_hosts)} suspicious /etc/hosts entry(ies)",
                    "\n".join(suspicious_hosts[:10]),
                    fix="Review /etc/hosts — malware can redirect websites to steal credentials"))
            else:
                findings.append(Finding(OK, "Hardening", "/etc/hosts file is clean"))
        except Exception:
            pass

    # 22b. /etc/sudoers NOPASSWD audit
    sudoers = pathlib.Path("/etc/sudoers")
    if sudoers.is_file():
        try:
            content = sudoers.read_text()
            nopasswd_lines = []
            for line in content.split("\n"):
                line = line.strip()
                if "NOPASSWD" in line and not line.startswith("#"):
                    nopasswd_lines.append(line)
            if nopasswd_lines:
                findings.append(Finding(WARNING, "Hardening",
                    f"{len(nopasswd_lines)} NOPASSWD rule(s) in sudoers",
                    "\n".join(nopasswd_lines[:5]),
                    fix="NOPASSWD lets programs run as admin without your password — review carefully"))
            else:
                findings.append(Finding(OK, "Hardening", "No NOPASSWD rules in sudoers"))
        except PermissionError:
            # Can't read sudoers without root — that's fine, it means permissions are correct
            findings.append(Finding(OK, "Hardening", "sudoers file permissions are restricted (good)"))

    # Also check sudoers.d directory
    sudoers_d = pathlib.Path("/etc/sudoers.d")
    if sudoers_d.is_dir():
        try:
            custom_sudoers = [f.name for f in sudoers_d.iterdir()
                              if f.is_file() and not f.name.startswith(".")]
            if custom_sudoers:
                findings.append(Finding(INFO, "Hardening",
                    f"{len(custom_sudoers)} custom sudoers file(s)",
                    "\n".join(custom_sudoers[:5])))
        except Exception:
            pass

    # 22c. Shell startup file tampering — scan for suspicious commands
    shell_files = [
        home / ".zshrc", home / ".zprofile", home / ".zshenv",
        home / ".bash_profile", home / ".bashrc", home / ".profile",
    ]
    suspicious_patterns = [
        (r"curl\s+.*\|\s*(ba)?sh", "Downloads and executes remote code"),
        (r"wget\s+.*\|\s*(ba)?sh", "Downloads and executes remote code"),
        (r"eval\s+\$\(", "Evaluates dynamically generated commands"),
        (r"base64\s+(-d|--decode)", "Decodes hidden base64 content"),
        (r"nc\s+-l", "Netcat listener (possible reverse shell)"),
        (r"ncat\s+-l", "Ncat listener (possible reverse shell)"),
        (r"/dev/tcp/", "Bash TCP connection (possible reverse shell)"),
        (r"export\s+PATH=.*:/tmp", "/tmp added to PATH (malware technique)"),
        (r"alias\s+sudo=", "sudo alias override (credential stealing)"),
        (r"alias\s+ssh=", "ssh alias override (credential stealing)"),
    ]
    tampered = []
    for sf in shell_files:
        if not sf.is_file():
            continue
        try:
            content = sf.read_text()
            for pattern, desc in suspicious_patterns:
                if re.search(pattern, content):
                    tampered.append(f"{sf.name}: {desc}")
        except Exception:
            pass

    if tampered:
        findings.append(Finding(CRITICAL, "Hardening",
            f"{len(tampered)} suspicious command(s) in shell startup files!",
            "\n".join(tampered[:10]),
            fix="Review your shell files — these could be malware injections"))
    else:
        findings.append(Finding(OK, "Hardening", "Shell startup files look clean"))

    # 22d. Find My Mac status
    out, _ = safe_run("defaults", ["read",
        "com.apple.FindMyMac", "FMMEnabled"], timeout=10)
    if out:
        if out.strip() == "1":
            findings.append(Finding(OK, "Hardening", "Find My Mac is enabled"))
        else:
            findings.append(Finding(WARNING, "Hardening",
                "Find My Mac is DISABLED",
                fix="System Settings > Apple ID > Find My > Find My Mac: ON"))
    else:
        # Alternative check
        out, _ = safe_run("defaults", ["read",
            "/Library/Preferences/com.apple.FindMyMac", "FMMEnabled"], timeout=10)
        if out and out.strip() == "1":
            findings.append(Finding(OK, "Hardening", "Find My Mac is enabled"))
        else:
            findings.append(Finding(WARNING, "Hardening",
                "Find My Mac may be disabled",
                fix="System Settings > Apple ID > Find My > Find My Mac: ON"))

    # 22e. Secure Keyboard Entry in Terminal
    out, _ = safe_run("defaults", ["read",
        "com.apple.Terminal", "SecureKeyboardEntry"], timeout=10)
    if out and out.strip() == "1":
        findings.append(Finding(OK, "Hardening", "Terminal Secure Keyboard Entry is ON"))
    else:
        findings.append(Finding(WARNING, "Hardening",
            "Terminal Secure Keyboard Entry is OFF",
            detail="Without this, other apps can read what you type in Terminal (passwords, etc).",
            fix="Open Terminal > Terminal menu > Secure Keyboard Entry > check it ON"))

    # 22f. at/batch job scheduler — another persistence mechanism
    at_dir = pathlib.Path("/var/at/jobs")
    if at_dir.is_dir():
        try:
            at_jobs = [f.name for f in at_dir.iterdir() if f.is_file()]
            if at_jobs:
                findings.append(Finding(WARNING, "Hardening",
                    f"{len(at_jobs)} at/batch job(s) found",
                    "\n".join(at_jobs[:5]),
                    fix="Review: sudo atq — remove suspicious ones: sudo atrm <job#>"))
            else:
                findings.append(Finding(OK, "Hardening", "No at/batch jobs"))
        except Exception:
            findings.append(Finding(OK, "Hardening", "at/batch job directory not accessible (normal)"))

    # 22g. Safari privacy settings
    out, _ = safe_run("defaults", ["read",
        "com.apple.Safari", "SendDoNotTrackHTTPHeader"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(INFO, "Hardening",
            "Safari 'Do Not Track' header is OFF",
            fix="Safari > Settings > Privacy > Prevent cross-site tracking: ON"))

    out, _ = safe_run("defaults", ["read",
        "com.apple.Safari", "WebKitPreferences.privateClickMeasurementEnabled"], timeout=10)

    # Check Safari fraudulent website warning
    out, _ = safe_run("defaults", ["read",
        "com.apple.Safari", "WarnAboutFraudulentWebsites"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(WARNING, "Hardening",
            "Safari fraudulent website warning is OFF",
            fix="Safari > Settings > Security > Warn when visiting a fraudulent website: ON"))
    elif out and out.strip() == "1":
        findings.append(Finding(OK, "Hardening", "Safari phishing protection is ON"))

    # 22h. SUID/SGID binaries in unusual locations
    suid_dirs = ["/usr/local/bin", "/opt/homebrew/bin",
                 str(home / ".local/bin"), "/tmp", "/var/tmp"]
    suid_files = []
    for d in suid_dirs:
        p = pathlib.Path(d)
        if not p.is_dir():
            continue
        try:
            for f in p.iterdir():
                try:
                    if f.is_file():
                        mode = f.stat().st_mode
                        if mode & stat.S_ISUID or mode & stat.S_ISGID:
                            suid_files.append(f"{f} (mode: {oct(mode)[-4:]})")
                except Exception:
                    pass
        except Exception:
            pass

    if suid_files:
        findings.append(Finding(CRITICAL, "Hardening",
            f"{len(suid_files)} SUID/SGID binary(ies) in non-system directories!",
            "\n".join(suid_files[:10]),
            fix="SUID binaries run with elevated privileges — remove if unexpected: chmod u-s <file>"))
    else:
        findings.append(Finding(OK, "Hardening", "No SUID/SGID binaries in user directories"))

    # 22i. Check for iCloud Private Relay
    out, _ = safe_run("defaults", ["read",
        "com.apple.Safari", "WBSPrivacyProxyAvailabilityTraffic"], timeout=10)
    # Private Relay is hard to check directly — check via network settings
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.networkextension", "PrivateRelay"], timeout=10)
    # Simplified: just note if it could be checked
    # iCloud Private Relay depends on iCloud+ subscription, so we just inform
    icloud_pr = pathlib.Path(home / "Library/Preferences/com.apple.iCloudPrivateRelay.plist")
    if icloud_pr.exists():
        findings.append(Finding(OK, "Hardening", "iCloud Private Relay config detected"))
    else:
        findings.append(Finding(INFO, "Hardening",
            "iCloud Private Relay not detected",
            detail="Private Relay hides your IP and encrypts Safari traffic.",
            fix="Requires iCloud+ (starts at $0.99/mo) — free alternative: Cloudflare WARP"))

    # 22j. Login/logout hooks (legacy persistence mechanism)
    for hook_type in ["LoginHook", "LogoutHook"]:
        out, _ = safe_run("defaults", ["read",
            "com.apple.loginwindow", hook_type], timeout=10)
        if out and "does not exist" not in out.lower():
            findings.append(Finding(WARNING, "Hardening",
                f"{hook_type} is set: {out.strip()[:60]}",
                detail="Login/logout hooks are a legacy persistence mechanism used by malware.",
                fix=f"Remove: sudo defaults delete com.apple.loginwindow {hook_type}"))

    # 22k. Check Remote Management (ARD)
    out, _ = safe_run("launchctl", ["print", "system/com.apple.RemoteDesktop.agent"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(WARNING, "Hardening",
            "Apple Remote Desktop agent is running",
            fix="If not needed: System Settings > General > Sharing > Remote Management OFF"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  ENHANCED OSQUERY CHECKS (more queries if osquery is available)
# ══════════════════════════════════════════════════════════════════════════════

def check_osquery_enhanced():
    """Additional osquery checks beyond the basic module."""
    findings = []

    if "osqueryi" not in OPTIONAL_BINS:
        return findings

    # Chrome extensions via osquery
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT name, identifier, version FROM chrome_extensions LIMIT 20"], timeout=15)
    if out:
        try:
            exts = json.loads(out)
            if exts:
                detail = "\n".join(f"{e.get('name','?')} v{e.get('version','?')}"
                                   for e in exts[:15])
                findings.append(Finding(INFO, "osquery+",
                    f"Chrome: {len(exts)} extension(s) (detailed)", detail))
        except Exception:
            pass

    # Safari extensions via osquery
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT name, version FROM safari_extensions LIMIT 15"], timeout=15)
    if out:
        try:
            exts = json.loads(out)
            if exts:
                detail = "\n".join(f"{e.get('name','?')} v{e.get('version','?')}"
                                   for e in exts[:15])
                findings.append(Finding(INFO, "osquery+",
                    f"Safari: {len(exts)} extension(s)", detail))
        except Exception:
            pass

    # Disk encryption via osquery (only check named user volumes, not raw partitions)
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT name, encrypted FROM disk_encryption WHERE name NOT LIKE '/dev/%'"], timeout=15)
    if out:
        try:
            disks = json.loads(out)
            unencrypted = [d for d in disks if d.get("encrypted") == "0"
                           and d.get("name", "").strip()]
            if unencrypted:
                detail = "\n".join(d.get("name", "?") for d in unencrypted[:5])
                findings.append(Finding(WARNING, "osquery+",
                    f"{len(unencrypted)} unencrypted volume(s)", detail))
        except Exception:
            pass

    # SIP status via osquery (only flag truly dangerous disabled flags)
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT config_flag, enabled FROM sip_config WHERE enabled = 1"], timeout=15)
    if out:
        try:
            sip = json.loads(out)
            enabled_flags = [s.get("config_flag", "") for s in sip]
            findings.append(Finding(OK, "osquery+",
                f"SIP: {len(enabled_flags)} protection(s) active"))
        except Exception:
            pass

    # Installed packages (recently installed)
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT name, version, location FROM packages "
        "ORDER BY install_time DESC LIMIT 10"], timeout=15)
    if out:
        try:
            pkgs = json.loads(out)
            if pkgs:
                detail = "\n".join(f"{p.get('name','?')} v{p.get('version','?')}"
                                   for p in pkgs[:10])
                findings.append(Finding(INFO, "osquery+",
                    f"Recent packages installed", detail))
        except Exception:
            pass

    # Kernel info
    out, _ = safe_run("osqueryi", ["--json",
        "SELECT version FROM kernel_info"], timeout=10)
    if out:
        try:
            ki = json.loads(out)
            if ki:
                findings.append(Finding(INFO, "osquery+",
                    f"Kernel: {ki[0].get('version','?')}"))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  SUGGESTIONS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def generate_suggestions(all_findings, score):
    """Generate personalized, FREE-only security suggestions with step-by-step instructions."""
    suggestions = []
    titles = {f.title for f in all_findings}

    # ── Fix current issues first ──

    if any(f.severity == CRITICAL for f in all_findings):
        suggestions.append({
            "priority": "HIGH",
            "title": "Fix critical issues immediately [FREE - built into macOS]",
            "detail": "You have critical security issues. Steps:\n"
                      "  1. Read the Action Items section above\n"
                      "  2. Each item has the exact command or setting to fix it\n"
                      "  3. Fix them in order — critical first, then warnings"
        })

    if any("firewall" in t.lower() and "disabled" in t.lower() for t in titles):
        suggestions.append({
            "priority": "HIGH",
            "title": "Enable the macOS firewall [FREE - built into macOS]",
            "detail": "The firewall blocks hackers from connecting to your Mac.\n"
                      "  Step 1: Open Terminal (Cmd+Space, type Terminal, hit Enter)\n"
                      "  Step 2: Paste this and hit Enter:\n"
                      "          sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on\n"
                      "  Step 3: Type your Mac password (won't show as you type) and hit Enter\n"
                      "  Done — firewall is now on."
        })

    if any("stealth" in t.lower() and "disabled" in t.lower() for t in titles):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Enable stealth mode [FREE - built into macOS]",
            "detail": "Stealth mode hides your Mac from hackers scanning networks.\n"
                      "  Step 1: Open Terminal\n"
                      "  Step 2: Paste this and hit Enter:\n"
                      "          sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on\n"
                      "  Step 3: Enter your password\n"
                      "  Done — your Mac is now invisible on networks."
        })

    if any("update" in f.title.lower() and f.severity in (CRITICAL, WARNING) for f in all_findings):
        suggestions.append({
            "priority": "HIGH",
            "title": "Install software updates [FREE - built into macOS]",
            "detail": "Updates fix security holes that hackers actively exploit.\n"
                      "  Step 1: Click the Apple menu (top-left corner)\n"
                      "  Step 2: Click 'System Settings'\n"
                      "  Step 3: Click 'General' in the left sidebar\n"
                      "  Step 4: Click 'Software Update'\n"
                      "  Step 5: Click 'Update Now' or 'Upgrade Now'\n"
                      "  Step 6: Wait for it to download and install (may need to restart)"
        })

    if any("backup" in f.title.lower() and f.severity == WARNING for f in all_findings):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Set up Time Machine backups [FREE - built into macOS]",
            "detail": "Backups protect you from ransomware, disk failure, and accidental deletion.\n"
                      "  Step 1: Connect an external hard drive to your Mac\n"
                      "  Step 2: Click the Apple menu > System Settings\n"
                      "  Step 3: Click 'General' > 'Time Machine'\n"
                      "  Step 4: Click 'Add Backup Disk' and select your drive\n"
                      "  Step 5: Check 'Encrypt Backups' for extra security\n"
                      "  Step 6: Click 'Set Up Disk'\n"
                      "  Done — backups will run automatically whenever the drive is connected."
        })

    if any("password not required" in t.lower() for t in titles):
        suggestions.append({
            "priority": "HIGH",
            "title": "Require password after screensaver [FREE - built into macOS]",
            "detail": "Without this, anyone can use your Mac when you step away.\n"
                      "  Step 1: Click Apple menu > System Settings\n"
                      "  Step 2: Click 'Lock Screen'\n"
                      "  Step 3: Set 'Require password after screen saver begins' to 'Immediately'\n"
                      "  Done."
        })

    if any("auto-login" in t.lower() and "enabled" in t.lower() for t in titles):
        suggestions.append({
            "priority": "HIGH",
            "title": "Disable auto-login [FREE - built into macOS]",
            "detail": "Auto-login means anyone who opens your Mac has full access.\n"
                      "  Step 1: Click Apple menu > System Settings\n"
                      "  Step 2: Click 'Users & Groups'\n"
                      "  Step 3: Click 'Login Options' (at the bottom)\n"
                      "  Step 4: Set 'Automatic Login' to 'Off'\n"
                      "  Done."
        })

    # ── Proactive suggestions (always shown, all FREE) ──

    if any("dns" in t.lower() and "dhcp" in t.lower() for t in titles):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Use encrypted DNS for privacy [FREE - Cloudflare]",
            "detail": "Right now your internet provider can see every website you visit.\n"
                      "Switching to Cloudflare DNS (1.1.1.1) is free and takes 10 seconds.\n"
                      "  Step 1: Open Terminal\n"
                      "  Step 2: Paste this and hit Enter:\n"
                      "          networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1\n"
                      "  Done — your DNS queries are now private.\n"
                      "  To undo later: networksetup -setdnsservers Wi-Fi empty"
        })

    if "osqueryi" not in OPTIONAL_BINS:
        suggestions.append({
            "priority": "LOW",
            "title": "Install osquery for deeper monitoring [FREE - open source by Meta]",
            "detail": "Adds USB device tracking, process trees, and detailed network analysis.\n"
                      "  Step 1: Open Terminal\n"
                      "  Step 2: Paste this and hit Enter:\n"
                      "          brew install osquery\n"
                      "  Step 3: Enter your password if asked\n"
                      "  Done — Guardian will automatically use it on the next scan."
        })

    if "clamscan" not in OPTIONAL_BINS:
        suggestions.append({
            "priority": "LOW",
            "title": "Install ClamAV antivirus [FREE - open source]",
            "detail": "Adds real virus scanning to Guardian (scans Downloads, Desktop, /tmp).\n"
                      "  Step 1: Open Terminal\n"
                      "  Step 2: Run: brew install clamav\n"
                      "  Step 3: Run: sudo mkdir -p /opt/homebrew/var/lib/clamav\n"
                      "  Step 4: Run: sudo chown -R $(whoami) /opt/homebrew/var/lib/clamav\n"
                      "  Step 5: Run: sudo cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf\n"
                      "  Step 6: Run: sudo sed -i '' 's/^Example/#Example/' /opt/homebrew/etc/clamav/freshclam.conf\n"
                      "  Step 7: Run: freshclam   (downloads virus definitions, takes ~2 min)\n"
                      "  Done — Guardian will automatically scan files on the next run."
        })

    lulu_app = pathlib.Path("/Applications/LuLu.app")
    if not lulu_app.exists():
        suggestions.append({
            "priority": "LOW",
            "title": "Install LuLu outbound firewall [FREE - open source by Objective-See]",
            "detail": "macOS firewall only blocks INCOMING connections. LuLu also blocks\n"
                      "OUTBOUND connections — catches malware trying to phone home.\n"
                      "  Step 1: Open Safari and go to: objective-see.org/products/lulu.html\n"
                      "  Step 2: Click the download button\n"
                      "  Step 3: Open the downloaded .dmg file\n"
                      "  Step 4: Drag LuLu to your Applications folder\n"
                      "  Step 5: Open LuLu from Applications\n"
                      "  Step 6: Click 'Allow' when macOS asks for permissions\n"
                      "  Done — LuLu will ask you to approve/block apps that try to connect out."
        })

    knockknock = pathlib.Path("/Applications/KnockKnock.app")
    if not knockknock.exists():
        suggestions.append({
            "priority": "LOW",
            "title": "Install KnockKnock malware scanner [FREE - open source by Objective-See]",
            "detail": "Scans for malware that persists after reboot (the most dangerous kind).\n"
                      "  Step 1: Open Safari and go to: objective-see.org/products/knockknock.html\n"
                      "  Step 2: Click the download button\n"
                      "  Step 3: Open the downloaded .dmg file\n"
                      "  Step 4: Drag KnockKnock to your Applications folder\n"
                      "  Step 5: Open it and click 'Scan' whenever you want to check\n"
                      "  No background process — just run it when you want a scan."
        })

    oversight = pathlib.Path("/Applications/OverSight.app")
    if not oversight.exists():
        suggestions.append({
            "priority": "LOW",
            "title": "Install OverSight camera/mic monitor [FREE - open source by Objective-See]",
            "detail": "Alerts you whenever ANY app uses your camera or microphone.\n"
                      "  Step 1: Open Safari and go to: objective-see.org/products/oversight.html\n"
                      "  Step 2: Click the download button\n"
                      "  Step 3: Open the downloaded .dmg file\n"
                      "  Step 4: Drag OverSight to your Applications folder\n"
                      "  Step 5: Open OverSight and allow permissions when asked\n"
                      "  Done — you'll get a popup whenever an app activates your camera or mic."
        })

    if score >= 80:
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Use Apple Keychain as your password manager [FREE - built into macOS]",
            "detail": "Apple Keychain generates and stores unique passwords for every site.\n"
                      "  Step 1: Click Apple menu > System Settings\n"
                      "  Step 2: Click 'Passwords' (or your Apple ID > iCloud > Passwords)\n"
                      "  Step 3: Make sure iCloud Keychain is ON\n"
                      "  Step 4: When Safari asks to save a password, click 'Save Password'\n"
                      "  Step 5: Use 'Suggest Strong Password' when creating new accounts\n"
                      "  Done — Safari will autofill passwords across all your Apple devices."
        })

    suggestions.append({
        "priority": "MEDIUM",
        "title": "Use free VPN on public Wi-Fi [FREE - Cloudflare WARP]",
        "detail": "Public Wi-Fi (coffee shops, airports) can expose your traffic.\n"
                  "  Step 1: Open the App Store on your Mac\n"
                  "  Step 2: Search for 'Cloudflare WARP' (or '1.1.1.1')\n"
                  "  Step 3: Click 'Get' to install it (100%% free, no account needed)\n"
                  "  Step 4: Open WARP from Applications\n"
                  "  Step 5: Toggle it ON when you're on public Wi-Fi\n"
                  "  Alternative: ProtonVPN (free tier) from protonvpn.com"
    })

    if any("airdrop" in f.title.lower() and "everyone" in f.title.lower() for f in all_findings):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Restrict AirDrop [FREE - built into macOS]",
            "detail": "AirDrop set to Everyone lets strangers send you files.\n"
                      "  Step 1: Click Apple menu > System Settings\n"
                      "  Step 2: Click 'General' > 'AirDrop & Handoff'\n"
                      "  Step 3: Set AirDrop to 'Contacts Only'\n"
                      "  Done."
        })

    if any("siri" in f.title.lower() and "lock screen" in f.title.lower() for f in all_findings):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Disable Siri on lock screen [FREE - built into macOS]",
            "detail": "Someone can ask Siri questions without unlocking your Mac.\n"
                      "  Step 1: Click Apple menu > System Settings\n"
                      "  Step 2: Click 'Siri'\n"
                      "  Step 3: Turn OFF 'Allow Siri When Locked'\n"
                      "  Done."
        })

    if any("failed sudo" in f.title.lower() and f.severity == WARNING for f in all_findings):
        suggestions.append({
            "priority": "HIGH",
            "title": "Investigate failed sudo attempts [FREE - built into macOS]",
            "detail": "Someone tried to run admin commands with the wrong password.\n"
                      "  Step 1: Check if it was you (did you mistype your password recently?)\n"
                      "  Step 2: If it wasn't you, change your password NOW:\n"
                      "          Apple menu > System Settings > Users & Groups > Change Password\n"
                      "  Step 3: Pick a strong password (12+ characters, mix of letters/numbers)\n"
                      "  Step 4: Check for any apps or people you don't recognize on your Mac"
        })

    if any("uptime" in f.title.lower() and f.severity == WARNING for f in all_findings):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Restart your Mac [FREE]",
            "detail": "Your Mac has been on for over 30 days. Security updates need a restart.\n"
                      "  Step 1: Save any open work\n"
                      "  Step 2: Click Apple menu > Restart\n"
                      "  Done."
        })

    suggestions.append({
        "priority": "MEDIUM",
        "title": "Enable two-factor authentication [FREE - built into Apple ID]",
        "detail": "2FA stops hackers even if they steal your password.\n"
                  "  Step 1: Click Apple menu > System Settings\n"
                  "  Step 2: Click your name at the top (Apple ID)\n"
                  "  Step 3: Click 'Sign-In & Security'\n"
                  "  Step 4: Click 'Two-Factor Authentication' and follow the steps\n"
                  "  Done — Apple will text you a code when someone tries to sign in."
    })

    suggestions.append({
        "priority": "LOW",
        "title": "Enable Safari phishing protection [FREE - built into Safari]",
        "detail": "Safari can warn you before you visit fake/scam websites.\n"
                  "  Step 1: Open Safari\n"
                  "  Step 2: Click Safari menu > Settings (or Cmd+,)\n"
                  "  Step 3: Click the 'Security' tab\n"
                  "  Step 4: Check 'Warn when visiting a fraudulent website'\n"
                  "  Done."
    })

    suggestions.append({
        "priority": "LOW",
        "title": "Enable Find My Mac [FREE - built into macOS]",
        "detail": "If your Mac is lost or stolen, you can locate, lock, or erase it remotely.\n"
                  "  Step 1: Click Apple menu > System Settings\n"
                  "  Step 2: Click your name (Apple ID) > 'Find My'\n"
                  "  Step 3: Turn ON 'Find My Mac'\n"
                  "  Step 4: Also turn ON 'Find My network' (helps find it even when offline)\n"
                  "  Done — go to icloud.com/find from any device to locate your Mac."
    })

    suggestions.append({
        "priority": "LOW",
        "title": "Enable Activation Lock [FREE - automatic with Find My Mac on Apple Silicon]",
        "detail": "Prevents anyone from erasing and reusing your Mac if stolen.\n"
                  "  If you have Apple Silicon (M1/M2/M3/M4): automatic when Find My Mac is on.\n"
                  "  If you have Intel: Boot into Recovery Mode > Utilities > Startup Security Utility."
    })

    return suggestions


# ══════════════════════════════════════════════════════════════════════════════
#  SCORING & TRENDS
# ══════════════════════════════════════════════════════════════════════════════

def calculate_score(findings):
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f.severity, 0)
    return max(0, min(100, score))


def score_grade(score):
    if score >= 90: return "A"
    elif score >= 80: return "B"
    elif score >= 70: return "C"
    elif score >= 60: return "D"
    else: return "F"


def load_score_history():
    if SCORES_FILE.exists():
        try:
            return json.loads(SCORES_FILE.read_text())
        except Exception:
            return []
    return []


def save_score(score, critical, warning):
    history = load_score_history()
    history.append({
        "date": datetime.datetime.now().isoformat(),
        "score": score, "critical": critical, "warning": warning,
    })
    history = history[-100:]
    SCORES_FILE.write_text(json.dumps(history, indent=2))


def trend_summary(current_score):
    history = load_score_history()
    if len(history) < 1:
        return "First scan — no trend data yet"
    prev = history[-1]["score"]
    diff = current_score - prev
    if diff > 0:
        return f"IMPROVED +{diff} pts (was {prev})"
    elif diff < 0:
        return f"DECREASED -{abs(diff)} pts (was {prev})"
    else:
        return f"Unchanged at {current_score}"


def score_sparkline(history):
    """Generate ASCII sparkline of last 10 scores."""
    if len(history) < 2:
        return ""
    recent = [h["score"] for h in history[-10:]]
    blocks = " ▁▂▃▄▅▆▇█"
    lo, hi = min(recent), max(recent)
    rng = hi - lo if hi != lo else 1
    return "".join(blocks[min(8, int((s - lo) / rng * 8))] for s in recent)


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(all_findings, score, suggestions):
    now = datetime.datetime.now()
    macos_ver, _ = safe_run("sw_vers", ["-productVersion"])
    build_ver, _ = safe_run("sw_vers", ["-buildVersion"])
    user_out, _ = safe_run("whoami")

    counts = {CRITICAL: 0, WARNING: 0, INFO: 0, OK: 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    grade = score_grade(score)
    trend = trend_summary(score)
    history = load_score_history()
    spark = score_sparkline(history)

    # Tool status
    tools_status = []
    if "osqueryi" in OPTIONAL_BINS:
        tools_status.append("osquery: ON")
    else:
        tools_status.append("osquery: not installed")
    if "clamscan" in OPTIONAL_BINS:
        tools_status.append("ClamAV: ON")
    else:
        tools_status.append("ClamAV: not installed")

    lines = []
    lines.append("=" * 72)
    lines.append("  GUARDIAN v4.0 — macOS Security Report")
    lines.append("=" * 72)
    lines.append(f"  Date     : {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  macOS    : {macos_ver or '?'} ({build_ver or '?'})")
    lines.append(f"  User     : {user_out or '?'}")
    lines.append(f"  Tools    : {' | '.join(tools_status)}")
    lines.append(f"  Score    : {score}/100 (Grade: {grade})")
    lines.append(f"  Trend    : {trend}" + (f"  History: {spark}" if spark else ""))
    lines.append("=" * 72)
    lines.append("")

    # Score bar
    filled = score * 40 // 100
    bar = "█" * filled + "░" * (40 - filled)
    lines.append(f"  [{bar}] {score}/100")
    lines.append("")
    lines.append(f"  {counts[CRITICAL]} CRITICAL  |  {counts[WARNING]} WARNING  |  "
                 f"{counts[INFO]} INFO  |  {counts[OK]} OK")
    lines.append("")

    # Findings by category
    categories = []
    seen = set()
    for f in all_findings:
        if f.category not in seen:
            categories.append(f.category)
            seen.add(f.category)

    for cat in categories:
        lines.append(f"── {cat} {'─' * (67 - len(cat))}")
        for f in all_findings:
            if f.category == cat:
                lines.append(str(f))
        lines.append("")

    # Action items
    actionable = [f for f in all_findings if f.severity in (CRITICAL, WARNING) and f.fix]
    if actionable:
        lines.append("── Action Items " + "─" * 55)
        for i, f in enumerate(actionable, 1):
            lines.append(f"  {i}. [{f.severity}] {f.title}")
            lines.append(f"     {f.fix}")
        lines.append("")

    # Suggestions
    if suggestions:
        lines.append("── Suggestions to Improve Your Security " + "─" * 31)
        lines.append("")
        for i, s in enumerate(suggestions, 1):
            lines.append(f"  {i}. [{s['priority']}] {s['title']}")
            for detail_line in s["detail"].split("\n"):
                lines.append(f"     {detail_line}")
            lines.append("")

    lines.append("=" * 72)
    lines.append(f"  Guardian v4.0 — {len(all_findings)} checks | {len(suggestions)} suggestions")
    lines.append("=" * 72)

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  CLEANUP
# ══════════════════════════════════════════════════════════════════════════════

def cleanup_old_reports():
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
    log.info("Guardian v4.0 scan starting")

    # Detect optional tools
    detect_optional_tools()
    if OPTIONAL_BINS:
        log.info(f"Optional tools detected: {', '.join(OPTIONAL_BINS.keys())}")

    # All 21 check modules
    checks = {
        "network": check_network_security,
        "system": check_system_integrity,
        "privacy": check_privacy,
        "malware": check_malware_indicators,
        "accounts": check_user_accounts,
        "updates": check_software_updates,
        "lockscreen": check_lock_screen,
        "backups": check_backups,
        "filesystem": check_filesystem,
        "hardware": check_hardware,
        "browser": check_browser_security,
        "certificates": check_certificates,
        "osquery": check_osquery,
        "clamav": check_clamav,
        "sharing": check_sharing,
        "siri": check_siri_exposure,
        "profiles": check_config_profiles,
        "netinterfaces": check_network_interfaces,
        "quarantine": check_quarantine,
        "apps": check_app_security,
        "logs": check_system_logs,
        "hardening": check_deep_hardening,
        "osquery_enhanced": check_osquery_enhanced,
    }

    results = {}

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

    module_order = ["network", "system", "privacy", "malware", "accounts",
                    "updates", "lockscreen", "backups", "filesystem", "hardware",
                    "browser", "certificates", "sharing", "siri", "profiles",
                    "netinterfaces", "quarantine", "apps", "logs",
                    "hardening", "osquery", "osquery_enhanced", "clamav"]
    all_findings = []
    for name in module_order:
        all_findings.extend(results.get(name, []))

    score = calculate_score(all_findings)
    critical_count = sum(1 for f in all_findings if f.severity == CRITICAL)
    warning_count = sum(1 for f in all_findings if f.severity == WARNING)

    # Generate suggestions
    suggestions = generate_suggestions(all_findings, score)

    # Generate and save report
    report = generate_report(all_findings, score, suggestions)
    now = datetime.datetime.now()
    report_file = REPORTS_DIR / f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    report_file.write_text(report)

    # Save JSON report too (for programmatic access)
    json_data = {
        "date": now.isoformat(),
        "score": score,
        "grade": score_grade(score),
        "critical": critical_count,
        "warning": warning_count,
        "findings": [f.to_dict() for f in all_findings],
        "suggestions": suggestions,
        "optional_tools": list(OPTIONAL_BINS.keys()),
    }
    json_file = REPORTS_DIR / f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.json"
    json_file.write_text(json.dumps(json_data, indent=2))

    log.info(f"Reports saved: {report_file}")

    # Save score history
    save_score(score, critical_count, warning_count)

    # Notifications
    grade = score_grade(score)
    if critical_count:
        titles = [f.title for f in all_findings if f.severity == CRITICAL][:3]
        notify(f"Guardian: {score}/100 ({grade}) CRITICAL",
               "; ".join(titles))
    elif warning_count:
        titles = [f.title for f in all_findings if f.severity == WARNING][:3]
        notify(f"Guardian: {score}/100 ({grade}) Warnings",
               f"{warning_count} warning(s): " + "; ".join(titles))
    else:
        notify(f"Guardian: {score}/100 ({grade}) All Clear",
               "No issues. Check report for suggestions to level up.")

    cleanup_old_reports()

    elapsed = time.time() - start
    log.info(f"Scan done in {elapsed:.1f}s — {score}/100, "
             f"{critical_count}C {warning_count}W, {len(suggestions)} suggestions")

    if critical_count:
        sys.exit(2)
    elif warning_count:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
