#!/usr/bin/env bash
# Render start script

echo "🚀 Starting Eco Pantry Backend on Render..."

# Start the FastAPI server
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT