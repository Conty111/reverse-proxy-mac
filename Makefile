.PHONY: build clean test deps install-tinygo

# Build the WASM plugin using standard Go
build:
	@echo "Building Kerberos auth WASM plugin with standard Go..."
	GOOS=wasip1 GOARCH=wasm go build -o mac-filter.wasm src/cmd/main.go
	@echo "Build complete: mac-filter.wasm"
	@ls -lh mac-filter.wasm

# Build the WASM plugin using TinyGo (alternative)
build-tiny:
	@echo "Building Kerberos auth WASM plugin with TinyGo..."
	@if ! command -v tinygo >/dev/null 2>&1; then \
		echo "Error: TinyGo is not installed. Run 'make install-tinygo' or visit https://tinygo.org/getting-started/install/"; \
		exit 1; \
	fi
	tinygo build -o mac-filter.wasm -scheduler=none -target=wasi -no-debug src/cmd/main.go
	@echo "Build complete: mac-filter.wasm"
	@ls -lh mac-filter.wasm

# Build with optimizations (smaller binary)
build-opt:
	@echo "Building optimized Kerberos auth WASM plugin with TinyGo..."
	@if ! command -v tinygo >/dev/null 2>&1; then \
		echo "Error: TinyGo is not installed. Run 'make install-tinygo' or visit https://tinygo.org/getting-started/install/"; \
		exit 1; \
	fi
	tinygo build -o mac-filter.wasm -scheduler=none -target=wasi -opt=2 -no-debug src/cmd/main.go
	@echo "Build complete: mac-filter.wasm"
	@ls -lh mac-filter.wasm

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f mac-filter.wasm mca-filter.wasm
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	go test ./... -v
	@echo "Tests complete"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy
	@echo "Dependencies installed"

# Install TinyGo (macOS with Homebrew)
install-tinygo:
	@echo "Installing TinyGo..."
	@if [[ "$$(uname)" == "Darwin" ]]; then \
		if command -v brew >/dev/null 2>&1; then \
			brew tap tinygo-org/tools; \
			brew install tinygo; \
		else \
			echo "Homebrew not found. Please install from https://brew.sh/"; \
			exit 1; \
		fi \
	else \
		echo "Please install TinyGo manually from https://tinygo.org/getting-started/install/"; \
		exit 1; \
	fi
	@echo "TinyGo installed successfully"

# Check TinyGo installation
check-tinygo:
	@if command -v tinygo >/dev/null 2>&1; then \
		echo "TinyGo is installed:"; \
		tinygo version; \
	else \
		echo "TinyGo is not installed. Run 'make install-tinygo'"; \
		exit 1; \
	fi
