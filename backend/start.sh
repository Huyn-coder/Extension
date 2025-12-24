#!/bin/bash
# Start backend server

cd "$(dirname "$0")"

# Kill old processes
pkill -f "uvicorn.*app" 2>/dev/null || true

# Activate venv if exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
elif [ -d "../.venv" ]; then
    source ../.venv/bin/activate
fi

# Set MongoDB URI
export MONGO_URI="${MONGO_URI:-mongodb://localhost:27017/phishshield}"

# Start server
echo "🚀 Starting PhishShield Backend..."
echo "   MongoDB: $MONGO_URI"
echo "   Port: 8000"
echo ""

python -m uvicorn app:app --host 0.0.0.0 --port 8000

