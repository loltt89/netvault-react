#!/bin/bash

echo "Stopping NetVault services..."

# Stop Django (Daphne ASGI server)
pkill -f "daphne.*netvault.asgi"
echo "✓ Stopped Django backend (Daphne)"

# Stop Celery
pkill -f "celery.*worker"
echo "✓ Stopped Celery worker"

pkill -f "celery.*beat"
echo "✓ Stopped Celery beat"

# Stop Node/React
pkill -f "react-scripts start"
pkill -f "node.*react-scripts"
echo "✓ Stopped React frontend"

echo ""
echo "All NetVault services stopped"
