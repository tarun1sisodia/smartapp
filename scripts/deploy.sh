#!/bin/bash

# Exit on any error
set -e

echo "Starting deployment process..."

# Database credentials
DB_USER="root"
DB_PASSWORD="root1234"
DB_HOST="localhost"
DB_PORT="3306"

# Security settings
JWT_SECRET="Yw6Pn3PkxZfFvM+vxsxKzH8jQ9xJGJj2fqwHDuYz9AM="

# Create database and tables
echo "Setting up database..."
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" < ./db/schema.sql

# Build the application
echo "Building application..."
mkdir -p bin
go build -o bin/server ./cmd/server/main.go

# Set up systemd service
echo "Setting up systemd service..."
sudo tee /etc/systemd/system/smart-attendance.service << EOF
[Unit]
Description=Smart Attendance Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/bin/server
Restart=always
Environment=GIN_MODE=release
Environment=DB_USER=root
Environment=DB_PASSWORD=root1234
Environment=DB_HOST=localhost
Environment=DB_PORT=3306
Environment=DB_NAME=smart_attendance
Environment=JWT_SECRET=${JWT_SECRET}
Environment=JWT_EXPIRATION=24h
Environment=SMTP_HOST=smtp.gmail.com
Environment=SMTP_PORT=587
Environment=SMTP_USERNAME=theunusualcharon@gmail.com
Environment=SMTP_PASSWORD=#include<coco>
Environment=FROM_EMAIL=theunusualcharon@gmail.com

[Install]
WantedBy=multi-user.target
EOF

# Create a secure .env file
echo "Creating .env file..."
cat > .env << EOF
PORT=8080
GIN_MODE=release

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=root1234
DB_NAME=smart_attendance

# JWT Configuration
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION=24h

# Server Configuration
SERVER_HOST=localhost
ALLOWED_ORIGINS=*

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=example@gmail.com
SMTP_PASSWORD=password  
FROM_EMAIL=example@gmail.com
EOF

# Set proper permissions for .env file
chmod 600 .env

# Reload systemd and start service
echo "Starting service..."
sudo systemctl daemon-reload
sudo systemctl enable smart-attendance
sudo systemctl start smart-attendance

echo "Deployment completed successfully!" 
