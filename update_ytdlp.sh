#!/bin/bash

# Exit on error
set -e

echo "🔄 Checking latest yt-dlp version..."

# Get latest version from PyPI
LATEST_VERSION=$(curl -s https://pypi.org/pypi/yt-dlp/json | jq -r '.info.version')

if [ -z "$LATEST_VERSION" ]; then
    echo "❌ Error: Could not get latest version"
    exit 1
fi

echo "📦 Latest version: $LATEST_VERSION"

# Update requirements.txt
sed -i "s/yt-dlp==.*/yt-dlp==$LATEST_VERSION/" requirements.txt

echo "✅ Updated yt-dlp to version $LATEST_VERSION in requirements.txt"
echo "🚀 To apply the update, run: docker compose up -d --build" 