.PHONY: run build test clean migrate setup

setup:
	@echo "Setting up the project..."
	@echo "1. Starting PostgreSQL..."
	docker-compose up -d postgres
	@echo "2. Waiting for PostgreSQL to be ready..."
	@sleep 3
	@echo "3. Database will be created automatically on first run"
	@echo "Setup complete! Run 'make run' to start the application"

run:
	go run cmd/api/main.go

build:
	go build -o bin/api cmd/api/main.go

test:
	go test -v ./...

clean:
	rm -rf bin/

migrate:
	go run cmd/api/main.go

install:
	go mod download
	go mod tidy

docker-build:
	docker build -t myapp-api .

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f api

db-reset:
	docker-compose down -v
	docker-compose up -d postgres
	@sleep 3
	@echo "Database reset complete. Run 'make run' to start"