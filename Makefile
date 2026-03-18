.PHONY: help build run test clean docker-build docker-up docker-down docker-logs fmt lint vet deps

# Variables
APP_NAME=authserver
BINARY_NAME=authserver
DOCKER_IMAGE=mac-authserver
DOCKER_COMPOSE=docker-compose
GO=go
GOFLAGS=-v
BUILD_DIR=./build
SRC_DIR=./src/cmd/authserver

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	@echo "Building $(APP_NAME)..."
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)

build-linux: ## Build the application for Linux
	@echo "Building $(APP_NAME) for Linux..."
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)

run: ## Run the application locally
	@echo "Running $(APP_NAME)..."
	$(GO) run $(SRC_DIR)/main.go

test:
	@echo "Running tests with Allure..."
	mkdir -p ./tests/allure-results && rm -rf ./tests/allure-results/*
	export ALLURE_OUTPUT_PATH=$(PWD)/tests && $(GO) test -coverprofile=./tests/coverage.out -v ./...
	$(GO) tool cover -html=./tests/coverage.out -o ./tests/coverage.html

allure:
	@echo "Clearing Allure report dirs..."
	mkdir -p ./tests/allure-report && rm -rf ./tests/allure-report/*
	@echo "Generating Allure report..."
	allure generate ./tests/allure-results --clean -o ./tests/allure-report

test-open:
	@echo "Opening tests coverage..."
	open ./tests/coverage.html
	@echo "Running Allure server..."
	allure serve ./tests/allure-results

test-all: test allure test-open

fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install it from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

vet:
	@echo "Running go vet..."
	$(GO) vet ./...

deps:
	@echo "Downloading dependencies..."
	$(GO) mod download

# Docker targets
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):latest .

docker-up: ## Start services with docker-compose
	@echo "Starting services..."
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop services with docker-compose
	@echo "Stopping services..."
	$(DOCKER_COMPOSE) down

docker-restart: docker-down docker-up ## Restart services

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(BUILD_DIR)/$(BINARY_NAME)
	rm -f coverage.out coverage.html

clean-all: clean ## Clean all artifacts including Docker
	@echo "Cleaning Docker resources..."
	$(DOCKER_COMPOSE) down -v --remove-orphans
	docker rmi $(DOCKER_IMAGE):latest 2>/dev/null || true

dev: fmt vet lint build

vul:
	govulncheck