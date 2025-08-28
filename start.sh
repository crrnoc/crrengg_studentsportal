#!/bin/bash
set -e   # Exit immediately if a command fails

echo "🐍 Activating Python virtual environment..."
source .venv/bin/activate

echo "🚀 Starting Node server..."
# Ensure Node listens on Cloud Run PORT
export PORT=${PORT:-8080}
node server.js
