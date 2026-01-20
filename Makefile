.PHONY: build run test test-cover lint fmt clean migrate help

# Build the standalone server
build:
	go build -o bin/simple-idm ./cmd/simple-idm

# Run the standalone server
run:
	go run ./cmd/simple-idm

# Run all tests
test:
	go test ./...

# Run tests with coverage
test-cover:
	go test -cover ./...

# Run tests with coverage report
test-cover-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
fmt:
	go fmt ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Tidy dependencies
tidy:
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run database migration (requires DB_URL or individual DB_* env vars)
migrate:
	psql -d $${DB_NAME:-simple_idm} -f migrations/001_initial_schema.sql

# Show help
help:
	@echo "Available targets:"
	@echo "  build          - Build the standalone server"
	@echo "  run            - Run the standalone server"
	@echo "  test           - Run all tests"
	@echo "  test-cover     - Run tests with coverage summary"
	@echo "  test-cover-html- Run tests and generate HTML coverage report"
	@echo "  fmt            - Format code"
	@echo "  lint           - Run linter (requires golangci-lint)"
	@echo "  tidy           - Tidy go.mod dependencies"
	@echo "  clean          - Remove build artifacts"
	@echo "  migrate        - Run database migration"
	@echo "  help           - Show this help"
