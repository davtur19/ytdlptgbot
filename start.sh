#!/bin/bash

# Exit on error
set -e

# Build and start the bot
echo "Building and starting containers..."
docker compose up -d --build

echo "Bot started successfully!" 