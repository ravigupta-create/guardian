#!/bin/bash
# Guardian — Uninstall script
# Removes the LaunchAgents. Optionally removes runtime data.

set -e

LAUNCH_DIR="$HOME/Library/LaunchAgents"
GUARDIAN_DIR="$HOME/.guardian"

echo "╔══════════════════════════════════════════╗"
echo "║   Guardian — Uninstalling...             ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Unload scanner agent
if launchctl list | grep -q "com.guardian.agent" 2>/dev/null; then
    launchctl unload "$LAUNCH_DIR/com.guardian.agent.plist" 2>/dev/null || true
    echo "✓ Unloaded scanner agent"
else
    echo "– Scanner agent was not loaded"
fi

# Unload dashboard agent
if launchctl list | grep -q "com.guardian.dashboard" 2>/dev/null; then
    launchctl unload "$LAUNCH_DIR/com.guardian.dashboard.plist" 2>/dev/null || true
    echo "✓ Unloaded dashboard agent"
else
    echo "– Dashboard agent was not loaded"
fi

# Remove plists
for plist in com.guardian.agent.plist com.guardian.dashboard.plist; do
    if [ -f "$LAUNCH_DIR/$plist" ]; then
        rm "$LAUNCH_DIR/$plist"
        echo "✓ Removed $LAUNCH_DIR/$plist"
    fi
done

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
