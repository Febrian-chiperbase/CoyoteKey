# CoyoteKey Makefile

# Variables
BINARY_NAME=coyotekey
SOURCE_FILE=CoyoteKey.go
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=${VERSION}"

# Default target
.PHONY: all
all: clean build

# Build the binary
.PHONY: build
build:
	@echo "🔨 Building CoyoteKey..."
	@mkdir -p ${BUILD_DIR}
	go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ${SOURCE_FILE}
	@echo "✅ Build complete: ${BUILD_DIR}/${BINARY_NAME}"

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "🔨 Building for multiple platforms..."
	@mkdir -p ${BUILD_DIR}
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 ${SOURCE_FILE}
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64 ${SOURCE_FILE}
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe ${SOURCE_FILE}
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64 ${SOURCE_FILE}
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-arm64 ${SOURCE_FILE}
	
	@echo "✅ Multi-platform build complete!"
	@ls -la ${BUILD_DIR}/

# Install dependencies
.PHONY: deps
deps:
	@echo "📦 Installing dependencies..."
	go mod tidy
	go mod download
	@echo "✅ Dependencies installed"

# Run tests
.PHONY: test
test:
	@echo "🧪 Running tests..."
	go test -v ./...
	@echo "✅ Tests complete"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf ${BUILD_DIR}
	rm -f ${BINARY_NAME}
	@echo "✅ Clean complete"

# Install the binary to system PATH
.PHONY: install
install: build
	@echo "📦 Installing CoyoteKey to system..."
	sudo cp ${BUILD_DIR}/${BINARY_NAME} /usr/local/bin/
	sudo chmod +x /usr/local/bin/${BINARY_NAME}
	@echo "✅ CoyoteKey installed to /usr/local/bin/"

# Uninstall the binary from system PATH
.PHONY: uninstall
uninstall:
	@echo "🗑️  Uninstalling CoyoteKey from system..."
	sudo rm -f /usr/local/bin/${BINARY_NAME}
	@echo "✅ CoyoteKey uninstalled"

# Run the tool with sample parameters
.PHONY: demo
demo: build
	@echo "🚀 Running demo with sample wordlist..."
	./${BUILD_DIR}/${BINARY_NAME} -u https://httpbin.org/headers -w sample_wordlist.txt -v -t 5 -r 2

# Run multi-target demo
.PHONY: demo-multi
demo-multi: build
	@echo "🚀 Running multi-target demo..."
	./${BUILD_DIR}/${BINARY_NAME} -targets targets.example.txt -w sample_wordlist.txt -v -t 5 -r 1 -retries 2

# Run comprehensive multi-target demo
.PHONY: demo-full
demo-full: build
	@echo "🎯 Running comprehensive multi-target demo..."
	./demo_multi_target.sh

# Run smart evasion demo
.PHONY: demo-evasion
demo-evasion: build
	@echo "🛡️  Running smart evasion demo..."
	./demo_smart_evasion.sh

# Run API discovery demo
.PHONY: demo-discovery
demo-discovery: build
	@echo "🔍 Running API discovery demo..."
	./demo_api_discovery.sh

# Run advanced authentication demo
.PHONY: demo-auth
demo-auth: build
	@echo "🔐 Running advanced authentication demo..."
	./demo_advanced_auth.sh

# Run machine learning demo
.PHONY: demo-ml
demo-ml: build
	@echo "🤖 Running machine learning demo..."
	./demo_machine_learning.sh

# Run database integration demo
.PHONY: demo-db
demo-db: build
	@echo "💾 Running database integration demo..."
	./demo_database_integration.sh

# Run web dashboard demo
.PHONY: demo-web
demo-web: build
	@echo "🌐 Running web dashboard demo..."
	./demo_web_dashboard.sh

# Run GUI demo
.PHONY: demo-gui
demo-gui: build
	@echo "🖥️ Running GUI demo..."
	./demo_gui.sh

# Format code
.PHONY: fmt
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...
	@echo "✅ Code formatted"

# Lint code
.PHONY: lint
lint:
	@echo "🔍 Linting code..."
	golangci-lint run
	@echo "✅ Linting complete"

# Show help
.PHONY: help
help:
	@echo "CoyoteKey - API Key Brute Force Tool"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  build-all  - Build for multiple platforms"
	@echo "  deps       - Install dependencies"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install to system PATH"
	@echo "  uninstall  - Remove from system PATH"
	@echo "  demo       - Run demo with sample data"
	@echo "  demo-multi - Run multi-target demo"
	@echo "  demo-full  - Run comprehensive multi-target demo"
	@echo "  demo-evasion - Run smart evasion demo"
	@echo "  demo-discovery - Run API discovery demo"
	@echo "  demo-auth  - Run advanced authentication demo"
	@echo "  demo-ml    - Run machine learning demo"
	@echo "  demo-db    - Run database integration demo"
	@echo "  demo-web   - Run web dashboard demo"
	@echo "  demo-gui   - Run GUI demo"
	@echo "  fmt        - Format code"
	@echo "  lint       - Lint code"
	@echo "  help       - Show this help message"

# Version info
.PHONY: version
version:
	@echo "CoyoteKey version: ${VERSION}"
