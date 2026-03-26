#!/bin/bash
# SmartGuard — One-click Startup
set -e
echo ""
echo "🛡  SmartGuard — Adaptive Authentication Engine"
echo "   Kaggle RBA Dataset · Secure · Production Ready"
echo "════════════════════════════════════════════════"

# Python check
python3 --version >/dev/null 2>&1 || { echo "❌ Python 3 not found"; exit 1; }

# Install
echo ""
echo "📦 Installing dependencies..."
pip install flask flask-cors scikit-learn pandas numpy python-dotenv -q --break-system-packages 2>/dev/null || \
pip install flask flask-cors scikit-learn pandas numpy python-dotenv -q
echo "✅ Done"

# .env check
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "⚠️  .env created from template — please edit it!"
fi

# Dataset
if [ ! -f "data/smartguard_dataset.csv" ]; then
  echo ""
  echo "📊 Generating dataset..."
  python3 scripts/dataset.py
fi

# Model
if [ ! -f "models/model.pkl" ]; then
  echo ""
  echo "🤖 Training ML model..."
  python3 models/train.py
fi

# Kill old
fuser -k 5050/tcp 2>/dev/null || true

# Start
echo ""
echo "🚀 Starting on http://localhost:5050..."
python3 backend/app.py &
SERVER_PID=$!
sleep 3

curl -s http://localhost:5050/api/health >/dev/null && echo "✅ Backend running" || echo "⚠️  Starting..."

echo ""
echo "════════════════════════════════════════════════"
echo "🌐 Open: frontend/index.html (in browser)"
echo ""
echo "👤 USER LOGIN: any email address"
echo "   (System evaluates risk automatically)"
echo ""
echo "🛡  ADMIN LOGIN:"
echo "   Username: admin"
echo "   Password: your ADMIN_SETUP_KEY from .env"
echo "   (Default: SmartGuard_Setup_2024)"
echo ""
echo "📊 Kaggle Real Data:"
echo "   Add KAGGLE_USERNAME + KAGGLE_KEY to .env"
echo "   Run: python3 scripts/dataset.py"
echo ""
echo "📧 Gmail OTP:"
echo "   Add SMTP_EMAIL + SMTP_APP_PASSWORD to .env"
echo "   Set SMTP_DEMO_MODE=false"
echo "════════════════════════════════════════════════"
echo ""
echo "Press Ctrl+C to stop."
wait $SERVER_PID
