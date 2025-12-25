#!/bin/bash
set -e

REPO_URL="https://github.com/caffienet0code/monitor-api"
PROJECT_NAME="monitor-api"

echo "🚀 Installing POST Monitor Backend..."

# Clone if not exists
if [ ! -d "$PROJECT_NAME" ]; then
    echo "📥 Cloning repository..."
    git clone "$REPO_URL"
fi

# Navigate to backend
cd "$PROJECT_NAME"

# Create venv if not exists
if [ ! -d "venv" ]; then
    echo "🔧 Setting up virtual environment..."
    python3 -m venv venv
fi

# Activate and install
echo "📦 Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

# Start server
echo "✅ Starting server on http://127.0.0.1:8000"
python main.py
