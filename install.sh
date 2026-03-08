#!/bin/bash
# Guardian — Install script
# Sets up LaunchAgents for automatic security scans + web dashboard

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
GUARDIAN_DIR="$HOME/.guardian"

echo "╔══════════════════════════════════════════╗"
echo "║   Guardian — macOS Security Monitor      ║"
echo "║   Installing...                          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Create runtime directories
mkdir -p "$GUARDIAN_DIR/reports"
echo "✓ Created $GUARDIAN_DIR"

# Make scripts executable
chmod +x "$SCRIPT_DIR/guardian.py"
chmod +x "$SCRIPT_DIR/dashboard.py"
echo "✓ Made guardian.py and dashboard.py executable"

# Create LaunchAgents directory if needed
mkdir -p "$LAUNCH_AGENTS_DIR"

# ── Scanner agent (runs every 3 hours) ──────────────────────────
SCAN_PLIST="com.guardian.agent.plist"
SCAN_DST="$LAUNCH_AGENTS_DIR/$SCAN_PLIST"

if launchctl list | grep -q "com.guardian.agent" 2>/dev/null; then
    launchctl unload "$SCAN_DST" 2>/dev/null || true
    echo "✓ Unloaded previous scanner agent"
fi

cp "$SCRIPT_DIR/$SCAN_PLIST" "$SCAN_DST"
launchctl load "$SCAN_DST"
echo "✓ Installed scanner agent (every 3 hours)"

# ── Dashboard agent (always running) ────────────────────────────
DASH_PLIST="com.guardian.dashboard.plist"
DASH_DST="$LAUNCH_AGENTS_DIR/$DASH_PLIST"

if launchctl list | grep -q "com.guardian.dashboard" 2>/dev/null; then
    launchctl unload "$DASH_DST" 2>/dev/null || true
    echo "✓ Unloaded previous dashboard agent"
fi

cp "$SCRIPT_DIR/$DASH_PLIST" "$DASH_DST"
launchctl load "$DASH_DST"
echo "✓ Installed dashboard agent (always on)"

echo ""
echo "════════════════════════════════════════════"
echo "  Guardian is now active!"
echo ""
echo "  Scanner  : Every 3 hours + on login"
echo "  Dashboard: http://127.0.0.1:8845"
echo "  Reports  : ~/.guardian/reports/"
echo "  Logs     : ~/.guardian/guardian.log"
echo ""
echo "  Run scan : launchctl start com.guardian.agent"
echo "  Uninstall: bash $SCRIPT_DIR/uninstall.sh"
echo "════════════════════════════════════════════"
