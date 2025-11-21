#!/bin/bash

PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Starting NetVault..."
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping services..."
    kill $BACKEND_PID $CELERY_WORKER_PID $CELERY_BEAT_PID $FRONTEND_PID 2>/dev/null
    # Give processes time to stop gracefully
    sleep 2
    # Force kill if still running
    kill -9 $BACKEND_PID $CELERY_WORKER_PID $CELERY_BEAT_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Check if Redis is running
if ! pgrep -x redis-server > /dev/null; then
    echo "⚠ WARNING: Redis is not running!"
    echo "Celery requires Redis. Start it with: sudo systemctl start redis"
    echo ""
fi

# Start Backend (with Daphne for WebSocket support)
echo "Starting Django backend (Daphne ASGI) on 0.0.0.0:8000..."
cd "$PROJECT_DIR/backend"
source venv/bin/activate
daphne -b 0.0.0.0 -p 8000 netvault.asgi:application > ../logs/backend.log 2>&1 &
BACKEND_PID=$!
echo "✓ Backend started (PID: $BACKEND_PID)"

# Start Celery Worker
echo "Starting Celery worker..."
cd "$PROJECT_DIR/backend"
celery -A netvault worker --loglevel=info --logfile=../logs/celery-worker.log &
CELERY_WORKER_PID=$!
echo "✓ Celery worker started (PID: $CELERY_WORKER_PID)"

# Start Celery Beat
echo "Starting Celery beat scheduler..."
cd "$PROJECT_DIR/backend"
celery -A netvault beat --loglevel=info --logfile=../logs/celery-beat.log &
CELERY_BEAT_PID=$!
echo "✓ Celery beat started (PID: $CELERY_BEAT_PID)"

# Wait for backend to start
sleep 3

# Start Frontend
echo "Starting React frontend on 0.0.0.0:3000..."
cd "$PROJECT_DIR/frontend"
npm start > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "✓ Frontend started (PID: $FRONTEND_PID)"

echo ""
echo "========================================="
echo "  NetVault is running!"
echo "========================================="
echo ""
echo "Services:"
echo "  Backend:       http://localhost:8000"
echo "  Frontend:      http://localhost:3000"
echo "  Django Admin:  http://localhost:8000/admin/"
echo "  API:           http://localhost:8000/api/v1/"
echo ""
echo "Network access (192.168.100.20):"
echo "  Frontend:      http://192.168.100.20:3000"
echo "  Backend API:   http://192.168.100.20:8000/api/v1/"
echo ""
echo "Default credentials:"
echo "  Email:    admin@netvault.local"
echo "  Password: admin123"
echo ""
echo "Logs:"
echo "  Backend:       tail -f $PROJECT_DIR/logs/backend.log"
echo "  Celery Worker: tail -f $PROJECT_DIR/logs/celery-worker.log"
echo "  Celery Beat:   tail -f $PROJECT_DIR/logs/celery-beat.log"
echo "  Frontend:      tail -f $PROJECT_DIR/logs/frontend.log"
echo ""
echo "Running processes:"
echo "  Backend PID:       $BACKEND_PID"
echo "  Celery Worker PID: $CELERY_WORKER_PID"
echo "  Celery Beat PID:   $CELERY_BEAT_PID"
echo "  Frontend PID:      $FRONTEND_PID"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for processes
wait $BACKEND_PID $CELERY_WORKER_PID $CELERY_BEAT_PID $FRONTEND_PID
