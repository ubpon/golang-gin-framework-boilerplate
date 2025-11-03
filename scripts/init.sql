-- scripts/init.sql
-- Create database if it doesn't exist
CREATE DATABASE myapp;

-- Connect to the database
\c myapp;

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE myapp TO postgres;

-- scripts/setup.sh
#!/bin/bash

echo "Creating database..."

# Check if PostgreSQL is running
if ! pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
    echo "PostgreSQL is not running. Please start PostgreSQL first."
    echo "Run: docker-compose up -d postgres"
    exit 1
fi

# Create database
PGPASSWORD=postgres psql -h localhost -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'myapp'" | grep -q 1 || PGPASSWORD=postgres psql -h localhost -U postgres -c "CREATE DATABASE myapp"

echo "Database created successfully!"
echo "You can now run: make run"