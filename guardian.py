#!/usr/bin/env python3
"""
Guardian v3.0 — macOS Background Security Monitor (Ultimate Edition)
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
}

# Optional tools — detected at runtime
OPTIONAL_BINS = {}

def detect_optional_tools():
    """Find optional free tools if installed."""
    candidates = {
        "osqueryi": ["/opt/homebrew/bin/osqueryi", "/usr/local/bin/osqueryi"],
        "clamscan": ["/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"],
        "freshclam": ["/opt/homebrew/bin/freshclam", "/usr/local/bin/freshclam"],
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
    script = f'display notification "{safe_msg}" with title "{safe_title}"'
    safe_run("osascript", ["-e", script], timeout=10)

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
        ".Xauthority",
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

    # Quick scan of /tmp and Downloads (lightweight, won't slow things down)
    home = pathlib.Path.home()
    scan_targets = []
    for t in ["/tmp", str(home / "Downloads")]:
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
#  SUGGESTIONS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def generate_suggestions(all_findings, score):
    """Generate personalized security suggestions based on findings."""
    suggestions = []
    sevs = {f.title: f.severity for f in all_findings}
    cats = {f.title: f.category for f in all_findings}
    titles = set(sevs.keys())

    # ── Priority fixes (based on current findings) ──

    if any(f.severity == CRITICAL for f in all_findings):
        suggestions.append({
            "priority": "HIGH",
            "title": "Fix critical issues first",
            "detail": "You have critical security issues that need immediate attention. "
                      "See the Action Items section above for exact commands."
        })

    # Firewall
    if any("firewall" in t.lower() and "disabled" in t.lower() for t in titles):
        suggestions.append({
            "priority": "HIGH",
            "title": "Enable the macOS firewall",
            "detail": "Your firewall is off. This is the single most impactful thing you can do.\n"
                      "Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
        })

    # Stealth mode
    if any("stealth" in t.lower() and "disabled" in t.lower() for t in titles):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Enable stealth mode",
            "detail": "Stealth mode makes your Mac invisible to network port scans — especially\n"
                      "important on public Wi-Fi (coffee shops, airports, hotels).\n"
                      "Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
        })

    # Updates
    if any("update" in f.title.lower() and f.severity in (CRITICAL, WARNING) for f in all_findings):
        suggestions.append({
            "priority": "HIGH",
            "title": "Install pending software updates",
            "detail": "Software updates patch security vulnerabilities that hackers actively exploit.\n"
                      "Go to: System Settings > General > Software Update"
        })

    # Backups
    if any("backup" in f.title.lower() and f.severity == WARNING for f in all_findings):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Set up regular backups",
            "detail": "Backups protect you from ransomware, disk failure, and accidental deletion.\n"
                      "Connect an external drive > System Settings > General > Time Machine.\n"
                      "An encrypted backup is even better."
        })

    # Lock screen
    if any("password not required" in t.lower() for t in titles):
        suggestions.append({
            "priority": "HIGH",
            "title": "Require password after screensaver",
            "detail": "Without this, anyone can use your Mac when you step away.\n"
                      "System Settings > Lock Screen > Require password: Immediately"
        })

    # Auto-login
    if any("auto-login" in t.lower() and "enabled" in t.lower() for t in titles):
        suggestions.append({
            "priority": "HIGH",
            "title": "Disable auto-login",
            "detail": "Auto-login means anyone who opens your Mac lid has full access.\n"
                      "System Settings > Users & Groups > Login Options > Auto Login: Off"
        })

    # ── Proactive suggestions (always shown) ──

    # DNS encryption suggestion
    if any("dns" in t.lower() and "dhcp" in t.lower() for t in titles):
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Use encrypted DNS for better privacy",
            "detail": "Your DNS is set to automatic (your ISP can see every website you visit).\n"
                      "Switch to a privacy-focused DNS:\n"
                      "  Cloudflare: networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1\n"
                      "  Google:     networksetup -setdnsservers Wi-Fi 8.8.8.8 8.8.4.4\n"
                      "  Quad9:      networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112\n"
                      "Cloudflare (1.1.1.1) is fastest and doesn't log your queries."
        })

    # Free tool suggestions
    if "osqueryi" not in OPTIONAL_BINS:
        suggestions.append({
            "priority": "LOW",
            "title": "Install osquery for deeper monitoring (free)",
            "detail": "osquery (by Meta) lets Guardian scan USB device history, process trees,\n"
                      "detailed network connections, and startup items.\n"
                      "Install: brew install osquery\n"
                      "Guardian will automatically detect and use it on next scan."
        })

    if "clamscan" not in OPTIONAL_BINS:
        suggestions.append({
            "priority": "LOW",
            "title": "Install ClamAV for antivirus scanning (free)",
            "detail": "ClamAV is a free open-source antivirus used by many organizations.\n"
                      "Guardian will automatically scan /tmp and ~/Downloads each run.\n"
                      "Install: brew install clamav\n"
                      "Then run once: sudo freshclam  (downloads virus definitions)"
        })

    # LuLu firewall suggestion
    lulu_app = pathlib.Path("/Applications/LuLu.app")
    if not lulu_app.exists():
        suggestions.append({
            "priority": "LOW",
            "title": "Install LuLu for outbound firewall protection (free)",
            "detail": "macOS firewall only blocks INCOMING connections. LuLu (by Objective-See)\n"
                      "blocks unauthorized OUTBOUND connections — catches malware phoning home.\n"
                      "Free download: https://objective-see.org/products/lulu.html"
        })

    # KnockKnock suggestion
    knockknock = pathlib.Path("/Applications/KnockKnock.app")
    if not knockknock.exists():
        suggestions.append({
            "priority": "LOW",
            "title": "Install KnockKnock for persistence scanning (free)",
            "detail": "KnockKnock (by Objective-See) scans for persistent malware — programs that\n"
                      "survive reboot. One-click scan, no background process needed.\n"
                      "Free download: https://objective-see.org/products/knockknock.html"
        })

    # OverSight suggestion
    oversight = pathlib.Path("/Applications/OverSight.app")
    if not oversight.exists():
        suggestions.append({
            "priority": "LOW",
            "title": "Install OverSight for camera/mic monitoring (free)",
            "detail": "OverSight (by Objective-See) alerts you whenever any app activates your\n"
                      "camera or microphone — catches spyware in real-time.\n"
                      "Free download: https://objective-see.org/products/oversight.html"
        })

    # Password manager
    if score >= 80:
        suggestions.append({
            "priority": "MEDIUM",
            "title": "Use a password manager",
            "detail": "If you don't already, use a password manager for unique passwords everywhere.\n"
                      "Free options: Apple Keychain (built-in), Bitwarden (free tier).\n"
                      "This protects you if any website gets breached."
        })

    # VPN on public Wi-Fi
    suggestions.append({
        "priority": "MEDIUM",
        "title": "Use a VPN on public Wi-Fi",
        "detail": "Public Wi-Fi (coffee shops, airports) can expose your traffic.\n"
                  "Free options: iCloud Private Relay (if you have iCloud+),\n"
                  "ProtonVPN (free tier), or Cloudflare WARP (free)."
    })

    # Physical security
    if score >= 85:
        suggestions.append({
            "priority": "LOW",
            "title": "Enable Find My Mac",
            "detail": "If your Mac is lost or stolen, Find My Mac can locate, lock, or erase it.\n"
                      "System Settings > Apple ID > Find My > Find My Mac: ON"
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
    lines.append("  GUARDIAN v3.0 — macOS Security Report")
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
    lines.append(f"  Guardian v3.0 — {len(all_findings)} checks | {len(suggestions)} suggestions")
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
    log.info("Guardian v3.0 scan starting")

    # Detect optional tools
    detect_optional_tools()
    if OPTIONAL_BINS:
        log.info(f"Optional tools detected: {', '.join(OPTIONAL_BINS.keys())}")

    # All 14 check modules
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
                    "browser", "certificates", "osquery", "clamav"]
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
