#!/bin/bash
# Guardian — Install script
# Sets up the LaunchAgent for automatic 3-hour security scans

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST_NAME="com.guardian.agent.plist"
PLIST_SRC="$SCRIPT_DIR/$PLIST_NAME"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_DST="$LAUNCH_AGENTS_DIR/$PLIST_NAME"
GUARDIAN_DIR="$HOME/.guardian"

echo "╔══════════════════════════════════════════╗"
echo "║   Guardian — macOS Security Monitor      ║"
echo "║   Installing...                          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Create runtime directories
mkdir -p "$GUARDIAN_DIR/reports"
echo "✓ Created $GUARDIAN_DIR"

# Make guardian.py executable
chmod +x "$SCRIPT_DIR/guardian.py"
echo "✓ Made guardian.py executable"

# Create LaunchAgents directory if needed
mkdir -p "$LAUNCH_AGENTS_DIR"

# Unload existing agent if present
if launchctl list | grep -q "com.guardian.agent" 2>/dev/null; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    echo "✓ Unloaded previous Guardian agent"
fi

# Copy plist
cp "$PLIST_SRC" "$PLIST_DST"
echo "✓ Installed LaunchAgent to $PLIST_DST"

# Load the agent
launchctl load "$PLIST_DST"
echo "✓ Loaded Guardian agent"

echo ""
echo "════════════════════════════════════════════"
echo "  Guardian is now active!"
echo ""
echo "  Schedule : Every 3 hours + on login"
echo "  Reports  : ~/.guardian/reports/"
echo "  Logs     : ~/.guardian/guardian.log"
echo ""
echo "  Run now  : launchctl start com.guardian.agent"
echo "  Uninstall: bash $SCRIPT_DIR/uninstall.sh"
echo "════════════════════════════════════════════"
