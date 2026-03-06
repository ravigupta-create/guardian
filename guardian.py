#!/usr/bin/env python3
"""
Guardian — macOS Background Security Monitor (Max Edition)
Runs every 3 hours via LaunchAgent. Zero dependencies, zero network calls, 100% local.
10 check modules, 40+ individual checks, security score, trend tracking.
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
    """Send a macOS notification. Sanitizes input."""
    safe_title = title.replace('"', '').replace("\\", "")[:100]
    safe_msg = message.replace('"', '').replace("\\", "")[:200]
    script = f'display notification "{safe_msg}" with title "{safe_title}"'
    safe_run("osascript", ["-e", script], timeout=10)

# ── Severity & scoring ──────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"
OK = "OK"

# Points deducted per severity (from 100)
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

    # 1a. Firewall global state
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

    # 1c. Block all incoming connections mode
    out, _ = safe_run("socketfilterfw", ["--getblockall"])
    if out:
        if "disabled" in out.lower():
            findings.append(Finding(INFO, "Network", "Block-all-incoming mode is off (normal for most users)"))
        else:
            findings.append(Finding(OK, "Network", "Block-all-incoming mode is ON (maximum protection)"))

    # 1d. Auto-allow signed software
    out, _ = safe_run("socketfilterfw", ["--getallowsigned"])
    if out and "enabled" in out.lower():
        findings.append(Finding(INFO, "Network",
            "Signed apps auto-allowed through firewall (default macOS behavior)"))

    # 1e. Unexpected listening ports
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
                fix="Review these processes — kill any you don't recognize with: kill <PID>"))
        else:
            findings.append(Finding(OK, "Network", "No unexpected listening ports"))

    # 1f. DNS servers
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

    # 1g. Wi-Fi proxy settings
    for proxy_type, label in [("webproxy", "HTTP Proxy"), ("securewebproxy", "HTTPS Proxy"),
                               ("socksfirewallproxy", "SOCKS Proxy")]:
        out, _ = safe_run("networksetup", [f"-get{proxy_type}", "Wi-Fi"])
        if out and "enabled: yes" in out.lower():
            findings.append(Finding(WARNING, "Network",
                f"{label} is configured on Wi-Fi",
                detail=out[:200],
                fix=f"If unexpected: networksetup -set{proxy_type}state Wi-Fi off"))

    # 1h. Check for VPN interfaces (just informational)
    out, _ = safe_run("networksetup", ["-listallnetworkservices"])
    if out:
        vpn_services = [l.strip() for l in out.split("\n")
                        if any(v in l.lower() for v in ["vpn", "tunnel", "wireguard"])]
        if vpn_services:
            findings.append(Finding(INFO, "Network",
                f"VPN service(s) configured: {', '.join(vpn_services)}"))

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
                fix="Boot into Recovery Mode (Cmd+R) and run: csrutil enable"))

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

    # 2d. XProtect / MRT status (Apple's built-in malware protection)
    xprotect_paths = [
        pathlib.Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle"),
        pathlib.Path("/System/Library/CoreServices/XProtect.bundle"),
    ]
    xprotect_found = False
    for xp in xprotect_paths:
        if xp.exists():
            xprotect_found = True
            # Check XProtect version/last update
            info_plist = xp / "Contents" / "Info.plist"
            if info_plist.exists():
                try:
                    with open(info_plist, "rb") as f:
                        plist_data = plistlib.load(f)
                    version = plist_data.get("CFBundleShortVersionString", "unknown")
                    findings.append(Finding(OK, "System",
                        f"XProtect is present (version {version})"))
                except Exception:
                    findings.append(Finding(OK, "System", "XProtect is present"))
            break
    if not xprotect_found:
        findings.append(Finding(WARNING, "System", "XProtect not found",
            fix="XProtect should be present on all Macs — check for system corruption"))

    # 2e. Secure Boot (Apple Silicon / T2)
    out, _ = safe_run("system_profiler", ["SPiBridgeDataType"], timeout=15)
    if out and "secure boot" in out.lower():
        if "full security" in out.lower():
            findings.append(Finding(OK, "System", "Secure Boot: Full Security"))
        elif "medium security" in out.lower():
            findings.append(Finding(WARNING, "System", "Secure Boot: Medium Security",
                fix="Startup Security Utility in Recovery Mode > Full Security"))
        elif "no security" in out.lower():
            findings.append(Finding(CRITICAL, "System", "Secure Boot: NO SECURITY",
                fix="Boot Recovery Mode > Startup Security Utility > Full Security"))

    # 2f. LaunchAgents/Daemons scan
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
                    # Try to read the plist to get the program path
                    detail_info = str(f)
                    try:
                        with open(f, "rb") as pf:
                            pdata = plistlib.load(pf)
                        prog = pdata.get("Program") or ""
                        prog_args = pdata.get("ProgramArguments", [])
                        if prog:
                            detail_info += f"\n  → Program: {prog}"
                        elif prog_args:
                            detail_info += f"\n  → Command: {' '.join(str(a) for a in prog_args[:3])}"
                    except Exception:
                        pass
                    unknown_agents.append(detail_info)

    if unknown_agents:
        findings.append(Finding(WARNING, "System",
            f"{len(unknown_agents)} unknown LaunchAgent/Daemon(s)",
            "\n".join(unknown_agents[:15]),
            fix="Review each plist — remove any you don't recognize"))
    else:
        findings.append(Finding(OK, "System", "No unknown LaunchAgents/Daemons"))

    # 2g. Kernel extensions (kexts) — 3rd party
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

    # 3a. Remote Login (SSH)
    out, _ = safe_run("launchctl", ["print", "system/com.openssh.sshd"], timeout=10)
    if out and "state = running" in out.lower():
        findings.append(Finding(WARNING, "Privacy", "Remote Login (SSH) is enabled",
            fix="System Settings > General > Sharing > Remote Login OFF"))
    else:
        findings.append(Finding(OK, "Privacy", "Remote Login (SSH) is disabled"))

    # 3b. Screen sharing
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

    # 3e. TCC.db camera/mic/screen/accessibility/FDA audit
    tcc_path = pathlib.Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    tcc_services = [
        ("kTCCServiceCamera", "Camera"),
        ("kTCCServiceMicrophone", "Microphone"),
        ("kTCCServiceScreenCapture", "Screen Recording"),
        ("kTCCServiceAccessibility", "Accessibility"),
        ("kTCCServiceSystemPolicyAllFiles", "Full Disk Access"),
        ("kTCCServiceAppleEvents", "Automation (AppleEvents)"),
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
                        (svc_id,)
                    )
                    apps = [row[0] for row in cursor.fetchall()]
                    if apps:
                        sev = INFO
                        if svc_name in ("Full Disk Access", "Accessibility", "Screen Recording"):
                            sev = INFO  # high-privilege but user-granted
                        findings.append(Finding(sev, "Privacy",
                            f"{len(apps)} app(s) have {svc_name} access",
                            "\n".join(apps[:10]),
                            fix=f"Review in System Settings > Privacy & Security > {svc_name}"))
                except Exception:
                    pass
            conn.close()
        except Exception as e:
            findings.append(Finding(INFO, "Privacy",
                f"TCC.db not directly readable (normal on newer macOS)"))
    else:
        findings.append(Finding(INFO, "Privacy",
            "TCC.db not accessible (expected on macOS 10.14+)"))

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

    # 3g. Spotlight Suggestions (sends queries to Apple)
    out, _ = safe_run("defaults", ["read", "com.apple.assistant.support", "Search Queries Data Sharing Status"])
    if out and out.strip() == "2":
        findings.append(Finding(INFO, "Privacy",
            "Siri Suggestions in Spotlight sends queries to Apple",
            fix="System Settings > Siri & Spotlight > Spotlight Privacy"))

    # 3h. Location services
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
            pass  # Usually permission denied, that's fine

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4: MALWARE INDICATORS
# ══════════════════════════════════════════════════════════════════════════════

def check_malware_indicators():
    findings = []

    # 4a. Comprehensive known malware paths
    malware_paths = [
        # Adware / PUPs
        "/Library/Application Support/JavaW",
        "/Library/Application Support/amc",
        "/Library/Application Support/VSearch",
        "/Library/Application Support/Conduit",
        "/Library/Application Support/Genieo",
        "/Library/Application Support/macAutoFixer",
        "/Library/Application Support/dz0",
        # Fake Apple plists
        "/Library/LaunchAgents/com.pcv.hlpramc.plist",
        "/Library/LaunchAgents/com.startup.plist",
        "/Library/LaunchAgents/com.updater.mcy.plist",
        "/Library/LaunchAgents/com.avickUpd.plist",
        "/Library/LaunchDaemons/com.machelper.plist",
        "/Library/LaunchDaemons/com.apple.installer.plist",
        "/Library/LaunchDaemons/com.apple.sysmond.plist",
        # User-level malware
        pathlib.Path.home() / "Library" / "LaunchAgents" / "com.pcv.hlpramc.plist",
        pathlib.Path.home() / "Library" / "LaunchAgents" / "com.startup.plist",
        pathlib.Path.home() / "Library" / "LaunchAgents" / "com.updater.mcy.plist",
        pathlib.Path.home() / "Library" / "LaunchAgents" / "com.ExpertModuleSearchP.plist",
        # Shlayer trojan
        pathlib.Path.home() / ".local" / "sysupd",
        # Hidden payloads
        "/tmp/.hidden_payload",
        "/var/tmp/.hidden_payload",
        "/private/tmp/.hidden",
        # OSX.Proton
        "/Library/LaunchDaemons/com.Eltima.UpdaterAgent.plist",
        # Silver Sparrow
        "/tmp/agent.sh",
        "/tmp/version.json",
        "/tmp/version.plist",
        # XCSSET
        pathlib.Path.home() / ".xcassets",
    ]
    found_malware = []
    for p in malware_paths:
        if pathlib.Path(p).exists():
            found_malware.append(str(p))

    if found_malware:
        findings.append(Finding(CRITICAL, "Malware",
            f"{len(found_malware)} known malware indicator(s)!",
            "\n".join(found_malware),
            fix="Investigate and remove these files. Consider running Apple's MRT."))
    else:
        findings.append(Finding(OK, "Malware", "No known malware file indicators"))

    # 4b. Suspicious processes
    out, _ = safe_run("ps", ["-axo", "pid,comm"], timeout=10)
    if out:
        suspicious_names = {
            "cryptominer", "xmrig", "coinhive", "coinminer", "minerd",
            "kworker", "bioset", "ksoftirqd",  # Linux fakes
            "osascript.hidden", ".hidden",
            "sysmond_helper", "updater_agent",
        }
        procs = out.strip().split("\n")
        sus_procs = []
        for line in procs:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                pname = parts[1].lower()
                basename = os.path.basename(pname)
                if (basename in suspicious_names
                        or pname.startswith("/tmp/")
                        or pname.startswith("/var/tmp/")
                        or pname.startswith("/private/tmp/")):
                    sus_procs.append(line.strip())
        if sus_procs:
            findings.append(Finding(CRITICAL, "Malware",
                f"{len(sus_procs)} suspicious process(es)!",
                "\n".join(sus_procs[:10]),
                fix="Kill suspicious processes: kill -9 <PID>"))
        else:
            findings.append(Finding(OK, "Malware", "No suspicious processes"))

    # 4c. High CPU processes (potential cryptominers)
    out, _ = safe_run("ps", ["-axo", "pid,%cpu,comm", "-r"], timeout=10)
    if out:
        lines = out.strip().split("\n")[1:]  # skip header
        high_cpu = []
        for line in lines[:20]:
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                try:
                    cpu = float(parts[1])
                    proc = parts[2]
                    # Flag anything using >80% CPU that isn't known
                    if cpu > 80 and not any(k in proc.lower() for k in
                            ["windowserver", "kernel_task", "mdworker", "mds_stores",
                             "photolibraryd", "photoanalysisd", "xcode", "swift",
                             "clang", "python", "node", "ollama", "code helper"]):
                        high_cpu.append(f"PID {parts[0]}: {proc} ({cpu}% CPU)")
                except ValueError:
                    pass
        if high_cpu:
            findings.append(Finding(WARNING, "Malware",
                f"{len(high_cpu)} process(es) with unusually high CPU",
                "\n".join(high_cpu[:5]),
                fix="Investigate — could indicate cryptomining malware"))

    # 4d. Cron jobs
    out, _ = safe_run("crontab", ["-l"], timeout=10)
    if out and "no crontab" not in out.lower():
        findings.append(Finding(WARNING, "Malware",
            "User cron jobs found", out[:500],
            fix="Review with: crontab -l — remove suspicious entries with: crontab -e"))
    else:
        findings.append(Finding(OK, "Malware", "No user cron jobs"))

    # 4e. Custom periodic scripts
    periodic_dirs = ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]
    custom_scripts = []
    for d in periodic_dirs:
        p = pathlib.Path(d)
        if p.is_dir():
            for f in p.iterdir():
                if not re.match(r"^\d{3}\.", f.name):
                    custom_scripts.append(str(f))
    if custom_scripts:
        findings.append(Finding(WARNING, "Malware",
            f"{len(custom_scripts)} custom periodic script(s)",
            "\n".join(custom_scripts[:10])))
    else:
        findings.append(Finding(OK, "Malware", "No custom periodic scripts"))

    # 4f. Hidden files in home directory (dotfiles audit)
    home = pathlib.Path.home()
    known_dotfiles = {
        ".bash_history", ".bash_profile", ".bashrc", ".zshrc", ".zsh_history",
        ".zprofile", ".zsh_sessions", ".profile", ".gitconfig", ".gitignore_global",
        ".ssh", ".gnupg", ".npm", ".config", ".local", ".cache", ".docker",
        ".vscode", ".cursor", ".DS_Store", ".CFUserTextEncoding", ".Trash",
        ".cups", ".lesshst", ".python_history", ".node_repl_history",
        ".guardian", ".ollama", ".continuum", ".claude",
        ".conda", ".jupyter", ".ipython", ".matplotlib", ".keras",
        ".streamlit", ".viminfo", ".wget-hsts", ".netrc",
    }
    suspicious_dotfiles = []
    try:
        for f in home.iterdir():
            if f.name.startswith(".") and f.name not in known_dotfiles:
                suspicious_dotfiles.append(f.name)
    except Exception:
        pass
    if suspicious_dotfiles:
        findings.append(Finding(INFO, "Malware",
            f"{len(suspicious_dotfiles)} uncommon dotfile(s) in home directory",
            "\n".join(sorted(suspicious_dotfiles)[:15])))

    # 4g. Check /tmp for executables
    tmp_execs = []
    for tmp_dir in ["/tmp", "/var/tmp", "/private/tmp"]:
        p = pathlib.Path(tmp_dir)
        if not p.is_dir():
            continue
        try:
            for f in p.iterdir():
                try:
                    if f.is_file() and os.access(str(f), os.X_OK) and not f.name.startswith("."):
                        tmp_execs.append(str(f))
                except Exception:
                    pass
        except Exception:
            pass
    if tmp_execs:
        findings.append(Finding(WARNING, "Malware",
            f"{len(tmp_execs)} executable(s) in /tmp directories",
            "\n".join(tmp_execs[:10]),
            fix="Executables in /tmp are suspicious — review and delete"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5: USER ACCOUNTS
# ══════════════════════════════════════════════════════════════════════════════

def check_user_accounts():
    findings = []

    # 5a. List accounts
    out, _ = safe_run("dscl", [".", "-list", "/Users"], timeout=10)
    if out:
        users = [u.strip() for u in out.split("\n") if u.strip()]
        real_users = [u for u in users if not u.startswith("_")
                      and u not in {"daemon", "nobody", "root", "Guest"}]
        findings.append(Finding(INFO, "Accounts",
            f"User accounts: {', '.join(real_users)}"))
        if len(real_users) > 3:
            findings.append(Finding(WARNING, "Accounts",
                f"{len(real_users)} user accounts — verify all expected",
                fix="System Settings > Users & Groups — remove unknown accounts"))

    # 5b. Admin users (check who has admin rights)
    out, _ = safe_run("dscl", [".", "-read", "/Groups/admin", "GroupMembership"], timeout=10)
    if out:
        # Parse: "GroupMembership: user1 user2"
        parts = out.split(":", 1)
        if len(parts) == 2:
            admins = parts[1].strip().split()
            findings.append(Finding(INFO, "Accounts",
                f"Admin users: {', '.join(admins)}"))
            if len(admins) > 2:
                findings.append(Finding(WARNING, "Accounts",
                    f"{len(admins)} admin accounts — minimize admin users for security"))

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
            f"Auto-login is enabled for user: {out.strip()}",
            detail="Anyone who opens your Mac gets full access without a password.",
            fix="System Settings > Users & Groups > Login Options > Automatic Login OFF"))
    else:
        findings.append(Finding(OK, "Accounts", "Auto-login is disabled"))

    # 5e. SSH authorized keys
    auth_keys = pathlib.Path.home() / ".ssh" / "authorized_keys"
    if auth_keys.is_file():
        try:
            lines = auth_keys.read_text().strip().split("\n")
            keys = [l for l in lines if l.strip() and not l.strip().startswith("#")]
            if keys:
                findings.append(Finding(WARNING, "Accounts",
                    f"{len(keys)} SSH authorized key(s) — verify all yours",
                    fix=f"Review: cat {auth_keys}"))
        except Exception:
            pass
    else:
        findings.append(Finding(OK, "Accounts", "No SSH authorized_keys file"))

    # 5f. SSH key permissions
    ssh_dir = pathlib.Path.home() / ".ssh"
    if ssh_dir.is_dir():
        bad_perms = []
        try:
            dir_mode = oct(ssh_dir.stat().st_mode)[-3:]
            if dir_mode != "700":
                bad_perms.append(f"~/.ssh directory: {dir_mode} (should be 700)")
            for f in ssh_dir.iterdir():
                if f.name.startswith("id_") and not f.name.endswith(".pub"):
                    mode = oct(f.stat().st_mode)[-3:]
                    if mode != "600":
                        bad_perms.append(f"{f.name}: {mode} (should be 600)")
        except Exception:
            pass
        if bad_perms:
            findings.append(Finding(WARNING, "Accounts",
                "SSH file permissions too open",
                "\n".join(bad_perms),
                fix="chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*"))
        else:
            findings.append(Finding(OK, "Accounts", "SSH permissions are correct"))

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
        security_update = False
        for line in combined.split("\n"):
            line = line.strip()
            if line.startswith("*") or line.startswith("Label:"):
                name = line.lstrip("* ").replace("Label:", "").strip()
                updates.append(name)
                if "security" in name.lower():
                    security_update = True
        sev = CRITICAL if security_update else WARNING
        findings.append(Finding(sev, "Updates",
            f"{len(updates)} update(s) available" +
            (" (includes SECURITY update!)" if security_update else ""),
            "\n".join(updates[:10]),
            fix="Install: System Settings > General > Software Update"))
    else:
        findings.append(Finding(INFO, "Updates", "Could not determine update status"))

    # 6b. Auto-update settings
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(WARNING, "Updates",
            "Automatic update checking is DISABLED",
            fix="System Settings > General > Software Update > Automatic Updates ON"))
    else:
        findings.append(Finding(OK, "Updates", "Automatic update checking is enabled"))

    # Auto-download
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(INFO, "Updates", "Automatic update download is off"))

    # Auto-install security responses
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.SoftwareUpdate",
        "CriticalUpdateInstall"], timeout=10)
    if out and out.strip() == "0":
        findings.append(Finding(WARNING, "Updates",
            "Automatic security response updates are DISABLED",
            fix="System Settings > General > Software Update > Security Responses ON"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 7: LOCK SCREEN & AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def check_lock_screen():
    findings = []

    # 7a. Require password after sleep/screensaver
    out, _ = safe_run("defaults", ["read",
        "com.apple.screensaver", "askForPassword"], timeout=10)
    if out:
        if out.strip() == "1":
            findings.append(Finding(OK, "Lock Screen", "Password required after screensaver"))
        else:
            findings.append(Finding(CRITICAL, "Lock Screen",
                "Password NOT required after screensaver",
                detail="Anyone can access your Mac after the screensaver activates.",
                fix="System Settings > Lock Screen > Require password after screen saver begins"))

    # 7b. Password delay
    out, _ = safe_run("defaults", ["read",
        "com.apple.screensaver", "askForPasswordDelay"], timeout=10)
    if out:
        try:
            delay = int(out.strip())
            if delay > 5:
                findings.append(Finding(WARNING, "Lock Screen",
                    f"Password delay is {delay} seconds after screensaver",
                    fix="Set to 'Immediately' in System Settings > Lock Screen"))
            else:
                findings.append(Finding(OK, "Lock Screen",
                    f"Password required within {delay}s of screensaver"))
        except ValueError:
            pass

    # 7c. Screen saver timeout
    out, _ = safe_run("defaults", ["read",
        "com.apple.screensaver", "idleTime"], timeout=10)
    if out:
        try:
            idle = int(out.strip())
            if idle == 0:
                findings.append(Finding(WARNING, "Lock Screen",
                    "Screensaver is set to NEVER activate",
                    fix="System Settings > Lock Screen > Start Screen Saver when inactive"))
            elif idle > 600:
                findings.append(Finding(WARNING, "Lock Screen",
                    f"Screensaver activates after {idle // 60} minutes (recommended: 5 min)",
                    fix="System Settings > Lock Screen > Start Screen Saver when inactive > 5 minutes"))
            else:
                findings.append(Finding(OK, "Lock Screen",
                    f"Screensaver activates after {idle // 60} min"))
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
                            "Display sleep is set to NEVER",
                            fix="System Settings > Energy > Turn display off after 5 minutes"))
                    elif val > 15:
                        findings.append(Finding(INFO, "Lock Screen",
                            f"Display sleeps after {val} minutes"))
                except (ValueError, IndexError):
                    pass
                break

    # 7e. Show password hints
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"], timeout=10)
    if out:
        try:
            retries = int(out.strip())
            if retries > 0:
                findings.append(Finding(INFO, "Lock Screen",
                    f"Password hint shown after {retries} failed attempt(s)",
                    fix="Set to 0: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"))
        except ValueError:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 8: BACKUP & RECOVERY
# ══════════════════════════════════════════════════════════════════════════════

def check_backups():
    findings = []

    # 8a. Time Machine status
    out, _ = safe_run("tmutil", ["status"], timeout=15)
    if out:
        if "Running = 1" in out:
            findings.append(Finding(OK, "Backup", "Time Machine backup is currently running"))
        else:
            findings.append(Finding(OK, "Backup", "Time Machine is configured"))
    else:
        findings.append(Finding(WARNING, "Backup",
            "Time Machine may not be configured",
            fix="System Settings > General > Time Machine > Add Backup Disk"))

    # 8b. Last backup date
    out, _ = safe_run("tmutil", ["latestbackup"], timeout=15)
    if out and "/" in out:
        # Extract date from backup path (format: .../2026-03-06-120000)
        match = re.search(r"(\d{4}-\d{2}-\d{2})-(\d{6})", out)
        if match:
            try:
                date_str = match.group(1)
                backup_date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                days_ago = (datetime.datetime.now() - backup_date).days
                if days_ago > 7:
                    findings.append(Finding(WARNING, "Backup",
                        f"Last backup was {days_ago} days ago ({date_str})",
                        fix="Connect your backup disk and run Time Machine"))
                else:
                    findings.append(Finding(OK, "Backup",
                        f"Last backup: {date_str} ({days_ago} day(s) ago)"))
            except ValueError:
                findings.append(Finding(INFO, "Backup", f"Last backup: {out}"))
        else:
            findings.append(Finding(OK, "Backup", f"Last backup path: {out}"))
    else:
        findings.append(Finding(WARNING, "Backup",
            "No Time Machine backups found",
            fix="Set up Time Machine: System Settings > General > Time Machine"))

    # 8c. Time Machine encryption
    out, _ = safe_run("tmutil", ["destinationinfo"], timeout=15)
    if out:
        if "encrypted" in out.lower() or "encryption" in out.lower():
            findings.append(Finding(OK, "Backup", "Time Machine backup is encrypted"))
        elif "name" in out.lower():
            findings.append(Finding(WARNING, "Backup",
                "Time Machine backup may not be encrypted",
                fix="Enable encryption when adding backup disk in Time Machine settings"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 9: FILE SYSTEM SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def check_filesystem():
    findings = []

    # 9a. Home directory permissions
    home = pathlib.Path.home()
    try:
        home_mode = oct(home.stat().st_mode)[-3:]
        if home_mode in ("700", "750", "755"):
            findings.append(Finding(OK, "Filesystem",
                f"Home directory permissions: {home_mode}"))
        else:
            findings.append(Finding(WARNING, "Filesystem",
                f"Home directory permissions too open: {home_mode}",
                fix=f"chmod 750 {home}"))
    except Exception:
        pass

    # 9b. Check for world-writable files in sensitive locations
    sensitive_dirs = [
        pathlib.Path.home() / ".ssh",
        pathlib.Path.home() / ".gnupg",
    ]
    world_writable = []
    for d in sensitive_dirs:
        if not d.is_dir():
            continue
        try:
            for f in d.iterdir():
                if f.is_file():
                    mode = f.stat().st_mode
                    if mode & stat.S_IWOTH:
                        world_writable.append(str(f))
        except Exception:
            pass
    if world_writable:
        findings.append(Finding(WARNING, "Filesystem",
            f"{len(world_writable)} world-writable file(s) in sensitive directories",
            "\n".join(world_writable[:10]),
            fix="chmod o-w <file> for each"))

    # 9c. .netrc file (stores plaintext passwords)
    netrc = pathlib.Path.home() / ".netrc"
    if netrc.is_file():
        mode = oct(netrc.stat().st_mode)[-3:]
        if mode != "600":
            findings.append(Finding(WARNING, "Filesystem",
                f".netrc has weak permissions ({mode})",
                detail=".netrc may contain plaintext credentials",
                fix="chmod 600 ~/.netrc"))
        else:
            findings.append(Finding(INFO, "Filesystem",
                ".netrc exists (contains credentials) — permissions OK"))

    # 9d. Check for plaintext credential files
    cred_files = [
        (".env", "Environment variables (may contain API keys)"),
        (".aws/credentials", "AWS credentials"),
        (".docker/config.json", "Docker config (may contain registry tokens)"),
    ]
    for fname, desc in cred_files:
        fpath = pathlib.Path.home() / fname
        if fpath.is_file():
            mode = oct(fpath.stat().st_mode)[-3:]
            if mode not in ("600", "400"):
                findings.append(Finding(WARNING, "Filesystem",
                    f"~/{fname} permissions too open ({mode})",
                    detail=desc,
                    fix=f"chmod 600 ~/{fname}"))

    # 9e. Downloads folder scan for suspicious executables
    downloads = pathlib.Path.home() / "Downloads"
    if downloads.is_dir():
        suspicious_exts = {".command", ".sh", ".scpt", ".applescript", ".pkg", ".dmg", ".app"}
        old_threshold = time.time() - (90 * 86400)  # 90 days
        old_installers = []
        try:
            for f in downloads.iterdir():
                if f.suffix.lower() in suspicious_exts and f.stat().st_mtime < old_threshold:
                    old_installers.append(f.name)
        except Exception:
            pass
        if old_installers:
            findings.append(Finding(INFO, "Filesystem",
                f"{len(old_installers)} old installer/script(s) in Downloads",
                "\n".join(old_installers[:10]),
                fix="Review and delete old .dmg/.pkg/.command files from Downloads"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 10: HARDWARE & POWER SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def check_hardware():
    findings = []

    # 10a. Firmware password / Secure Enclave (informational)
    out, _ = safe_run("system_profiler", ["SPHardwareDataType"], timeout=15)
    if out:
        if "apple m" in out.lower() or "apple m" in out.lower():
            findings.append(Finding(OK, "Hardware", "Apple Silicon detected (Secure Enclave present)"))
        elif "t2" in out.lower():
            findings.append(Finding(OK, "Hardware", "T2 chip detected (hardware encryption)"))

        # Extract serial number presence (just confirm it's readable)
        if "serial number" in out.lower():
            for line in out.split("\n"):
                if "serial number" in line.lower():
                    findings.append(Finding(INFO, "Hardware",
                        line.strip()))
                    break

    # 10b. Power settings security
    out, _ = safe_run("pmset", ["-g"], timeout=10)
    if out:
        # Check wake on LAN
        for line in out.split("\n"):
            if "womp" in line.lower():
                parts = line.strip().split()
                try:
                    if int(parts[-1]) == 1:
                        findings.append(Finding(INFO, "Hardware",
                            "Wake on LAN is enabled",
                            fix="If not needed: sudo pmset -a womp 0"))
                except (ValueError, IndexError):
                    pass

        # Check power nap
        for line in out.split("\n"):
            if "powernap" in line.lower():
                parts = line.strip().split()
                try:
                    if int(parts[-1]) == 1:
                        findings.append(Finding(INFO, "Hardware",
                            "Power Nap is enabled (Mac wakes periodically for updates)"))
                except (ValueError, IndexError):
                    pass

    # 10c. Bluetooth discoverability
    out, _ = safe_run("defaults", ["read",
        "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"], timeout=10)
    if out and out.strip() == "1":
        findings.append(Finding(INFO, "Hardware", "Bluetooth is ON"))

    # 10d. Check disk health (SMART status)
    out, _ = safe_run("diskutil", ["info", "/"], timeout=15)
    if out:
        for line in out.split("\n"):
            if "smart status" in line.lower() or "s.m.a.r.t" in line.lower():
                if "verified" in line.lower():
                    findings.append(Finding(OK, "Hardware", "Disk SMART status: Verified"))
                elif "failing" in line.lower():
                    findings.append(Finding(CRITICAL, "Hardware",
                        "Disk SMART status: FAILING",
                        fix="BACK UP YOUR DATA IMMEDIATELY — disk may fail soon"))
                break

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  SCORING & TRENDS
# ══════════════════════════════════════════════════════════════════════════════

def calculate_score(findings):
    """Calculate security score 0-100."""
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f.severity, 0)
    return max(0, min(100, score))


def score_grade(score):
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def load_score_history():
    """Load previous scores for trend tracking."""
    if SCORES_FILE.exists():
        try:
            return json.loads(SCORES_FILE.read_text())
        except Exception:
            return []
    return []


def save_score(score, critical, warning):
    """Save current score to history."""
    history = load_score_history()
    history.append({
        "date": datetime.datetime.now().isoformat(),
        "score": score,
        "critical": critical,
        "warning": warning,
    })
    # Keep last 100 entries
    history = history[-100:]
    SCORES_FILE.write_text(json.dumps(history, indent=2))


def trend_summary(current_score):
    """Compare current score to recent history."""
    history = load_score_history()
    if len(history) < 2:
        return "First scan — no trend data yet"

    prev = history[-1]["score"]
    diff = current_score - prev
    if diff > 0:
        return f"Score improved by {diff} points (was {prev})"
    elif diff < 0:
        return f"Score decreased by {abs(diff)} points (was {prev})"
    else:
        return f"Score unchanged at {current_score}"


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(all_findings, score):
    now = datetime.datetime.now()
    macos_ver, _ = safe_run("sw_vers", ["-productVersion"])
    build_ver, _ = safe_run("sw_vers", ["-buildVersion"])
    user_out, _ = safe_run("whoami")

    counts = {CRITICAL: 0, WARNING: 0, INFO: 0, OK: 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    grade = score_grade(score)
    trend = trend_summary(score)

    lines = []
    lines.append("=" * 72)
    lines.append("  GUARDIAN — macOS Security Report")
    lines.append("=" * 72)
    lines.append(f"  Date     : {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  macOS    : {macos_ver or '?'} ({build_ver or '?'})")
    lines.append(f"  User     : {user_out or '?'}")
    lines.append(f"  Score    : {score}/100 (Grade: {grade})")
    lines.append(f"  Trend    : {trend}")
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

    # Group by category
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

    # Action items summary
    actionable = [f for f in all_findings if f.severity in (CRITICAL, WARNING) and f.fix]
    if actionable:
        lines.append("── Action Items " + "─" * 55)
        for i, f in enumerate(actionable, 1):
            lines.append(f"  {i}. [{f.severity}] {f.title}")
            lines.append(f"     → {f.fix}")
        lines.append("")

    lines.append("=" * 72)
    lines.append(f"  Guardian v2.0 — {len(all_findings)} checks completed")
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
    log.info("Guardian scan starting (v2.0 — Max Edition)")

    # All 10 check modules
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
    }

    results = {}

    def run_check(name, func):
        try:
            results[name] = func()
        except Exception as e:
            log.error(f"Check '{name}' failed: {e}")
            results[name] = [Finding(WARNING, name.title(), f"Check failed: {e}")]

    # Run all in parallel
    threads = []
    for name, func in checks.items():
        t = threading.Thread(target=run_check, args=(name, func), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=180)

    # Collect findings in module order
    module_order = ["network", "system", "privacy", "malware", "accounts",
                    "updates", "lockscreen", "backups", "filesystem", "hardware"]
    all_findings = []
    for name in module_order:
        all_findings.extend(results.get(name, []))

    # Calculate score
    score = calculate_score(all_findings)
    critical_count = sum(1 for f in all_findings if f.severity == CRITICAL)
    warning_count = sum(1 for f in all_findings if f.severity == WARNING)

    # Generate and save report
    report = generate_report(all_findings, score)
    now = datetime.datetime.now()
    report_file = REPORTS_DIR / f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    report_file.write_text(report)
    log.info(f"Report saved: {report_file}")

    # Save score history
    save_score(score, critical_count, warning_count)

    # Notifications
    grade = score_grade(score)
    if critical_count:
        titles = [f.title for f in all_findings if f.severity == CRITICAL][:3]
        notify(f"Guardian: {score}/100 ({grade}) — CRITICAL",
               "; ".join(titles))
    elif warning_count:
        titles = [f.title for f in all_findings if f.severity == WARNING][:3]
        notify(f"Guardian: {score}/100 ({grade}) — Warnings",
               f"{warning_count} warning(s): " + "; ".join(titles))
    else:
        notify(f"Guardian: {score}/100 ({grade}) — All Clear",
               "No security issues detected")

    cleanup_old_reports()

    elapsed = time.time() - start
    log.info(f"Scan complete in {elapsed:.1f}s — score {score}/100, "
             f"{critical_count} critical, {warning_count} warning")

    if critical_count:
        sys.exit(2)
    elif warning_count:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
