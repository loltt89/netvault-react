#!/bin/bash

# NetVault Setup Script
# This script helps to set up the NetVault application

set -e

echo "========================================="
echo "NetVault Setup Script"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Note: Some commands may require sudo privileges${NC}"
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system dependencies
echo "Checking system dependencies..."
echo ""

MISSING_DEPS=()

if ! command_exists python3; then
    MISSING_DEPS+=("python3")
fi

if ! command_exists pip3; then
    MISSING_DEPS+=("python3-pip")
fi

if ! command_exists node; then
    MISSING_DEPS+=("nodejs")
fi

if ! command_exists npm; then
    MISSING_DEPS+=("npm")
fi

if ! command_exists mysql; then
    MISSING_DEPS+=("mariadb-server")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "${RED}Missing dependencies:${NC} ${MISSING_DEPS[*]}"
    echo ""
    echo "To install missing dependencies, run:"
    echo "sudo apt update"
    echo "sudo apt install -y python3 python3-pip python3-venv nodejs npm mariadb-server libmariadb-dev redis-server"
    echo ""
    read -p "Do you want to install missing dependencies now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y python3 python3-pip python3-venv nodejs npm mariadb-server libmariadb-dev redis-server
    else
        echo -e "${RED}Cannot proceed without dependencies${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}All system dependencies are installed${NC}"
fi

echo ""
echo "========================================="
echo "Setting up Backend"
echo "========================================="
echo ""

cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
else
    echo "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}Python dependencies installed${NC}"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo ""
    echo "Creating .env file..."
    cp .env.example .env

    # Generate SECRET_KEY
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    sed -i "s|SECRET_KEY=.*|SECRET_KEY=$SECRET_KEY|" .env

    # Generate ENCRYPTION_KEY
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    sed -i "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=$ENCRYPTION_KEY|" .env

    echo -e "${GREEN}.env file created with generated keys${NC}"
    echo -e "${YELLOW}Please edit .env file and update database credentials${NC}"
else
    echo ".env file already exists"
fi

# Create logs directory
mkdir -p logs

# Database setup
echo ""
read -p "Do you want to set up the database now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Database Setup"
    echo "--------------"
    read -p "Enter database name (default: netvault): " DB_NAME
    DB_NAME=${DB_NAME:-netvault}

    read -p "Enter database user (default: netvault_user): " DB_USER
    DB_USER=${DB_USER:-netvault_user}

    read -sp "Enter database password: " DB_PASSWORD
    echo

    read -sp "Enter MySQL root password: " MYSQL_ROOT_PASSWORD
    echo

    # Update .env file
    sed -i "s|DB_NAME=.*|DB_NAME=$DB_NAME|" .env
    sed -i "s|DB_USER=.*|DB_USER=$DB_USER|" .env
    sed -i "s|DB_PASSWORD=.*|DB_PASSWORD=$DB_PASSWORD|" .env

    # Create database
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

    echo -e "${GREEN}Database created successfully${NC}"
fi

# Run migrations
echo ""
echo "Running database migrations..."
python manage.py makemigrations
python manage.py migrate
echo -e "${GREEN}Migrations completed${NC}"

# Create superuser
echo ""
read -p "Do you want to create a superuser now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python manage.py createsuperuser
fi

echo ""
echo -e "${GREEN}Backend setup completed!${NC}"

# Frontend setup
echo ""
echo "========================================="
echo "Setting up Frontend"
echo "========================================="
echo ""

cd ../frontend

if [ -f "package.json" ]; then
    echo "Installing Node.js dependencies..."
    npm install
    echo -e "${GREEN}Node.js dependencies installed${NC}"

    # Create .env file for frontend
    if [ ! -f ".env" ]; then
        echo "REACT_APP_API_URL=http://localhost:8000/api/v1" > .env
        echo -e "${GREEN}Frontend .env file created${NC}"
    fi
else
    echo -e "${YELLOW}Frontend not initialized yet. Please run 'npx create-react-app .' first${NC}"
fi

cd ..

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "To start the application:"
echo ""
echo "Backend:"
echo "  cd backend"
echo "  source venv/bin/activate"
echo "  daphne -b 0.0.0.0 -p 8000 netvault.asgi:application"
echo ""
echo "Frontend:"
echo "  cd frontend"
echo "  npm start"
echo ""
echo "Access the application:"
echo "  Frontend: http://localhost:3000"
echo "  Backend API: http://localhost:8000/api/v1/"
echo "  Django Admin: http://localhost:8000/admin/"
echo ""
echo -e "${GREEN}Happy coding!${NC}"
