#!/bin/bash
# Guardian — Uninstall script
# Removes the LaunchAgent. Optionally removes runtime data.

set -e

PLIST_NAME="com.guardian.agent.plist"
PLIST_DST="$HOME/Library/LaunchAgents/$PLIST_NAME"
GUARDIAN_DIR="$HOME/.guardian"

echo "╔══════════════════════════════════════════╗"
echo "║   Guardian — Uninstalling...             ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Unload agent
if launchctl list | grep -q "com.guardian.agent" 2>/dev/null; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    echo "✓ Unloaded Guardian agent"
else
    echo "– Guardian agent was not loaded"
fi

# Remove plist
if [ -f "$PLIST_DST" ]; then
    rm "$PLIST_DST"
    echo "✓ Removed $PLIST_DST"
else
    echo "– Plist not found at $PLIST_DST"
fi

echo ""

# Ask about runtime data
read -p "Delete all Guardian data (~/.guardian/)? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$GUARDIAN_DIR"
    echo "✓ Removed $GUARDIAN_DIR"
else
    echo "– Kept $GUARDIAN_DIR (reports and logs preserved)"
fi

echo ""
echo "Guardian has been uninstalled."
