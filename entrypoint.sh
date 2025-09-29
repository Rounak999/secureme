#!/usr/bin/env bash
set -e

# Optional: export chrome binary location so selenium can find it if needed
export CHROME_BIN=/usr/bin/chromium
export PATH=/usr/bin:$PATH

# Start Flask app in background
# If your app expects to bind to 0.0.0.0:8000, ensure app.py uses that or set FLASK_RUN_HOST
# Adjust the command below if you use gunicorn or another runner.
python /app/app.py &

FLASK_PID=$!

echo "Flask started (pid: $FLASK_PID). Starting bot loop..."

# Run bot.py every 30 seconds indefinitely
while true; do
  # Run the bot; ensure bot.py returns promptly after finishing.
  # We allow the bot to fail (|| true) so the loop continues.
  python /app/bot.py || true
  sleep 30
done
