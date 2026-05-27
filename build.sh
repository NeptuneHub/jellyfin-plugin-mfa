#!/bin/bash
# Build and package the Jellyfin Two-Factor Authentication plugin.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/src/Jellyfin.Plugin.TwoFactorAuth"
OUTPUT_DIR="$SCRIPT_DIR/dist/TwoFactorAuth"
INSTALL_FLAG="${1:-}"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Architecture-agnostic managed build — the plugin has no native dependencies.
PUBLISH_DIR="$SCRIPT_DIR/dist/publish"
rm -rf "$PUBLISH_DIR"
echo "Building managed plugin (Release)..."
dotnet publish "$PROJECT_DIR" -c Release --self-contained false -o "$PUBLISH_DIR" --nologo

for file in \
    Jellyfin.Plugin.TwoFactorAuth.dll \
    Otp.NET.dll \
    QRCoder.dll \
; do
    if [ -f "$PUBLISH_DIR/$file" ]; then
        cp "$PUBLISH_DIR/$file" "$OUTPUT_DIR/"
    fi
done

cp "$PROJECT_DIR/meta.json" "$OUTPUT_DIR/"

echo ""
echo "Plugin built to: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

if [ "$INSTALL_FLAG" = "--install" ]; then
    PLUGIN_DIR="${JELLYFIN_DATA:-$HOME/.local/share/jellyfin}/plugins/TwoFactorAuth"
    rm -rf "$PLUGIN_DIR"
    cp -r "$OUTPUT_DIR" "$PLUGIN_DIR"
    echo ""
    echo "Installed to: $PLUGIN_DIR"
    echo "Restart Jellyfin to load the plugin."
fi
