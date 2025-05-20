BINARY=sandbox
BIN_DIR=bin

.PHONY: all build test clean

all: build

# Create bin directory and build the binary
build: $(BIN_DIR)
	@echo "Building $(BINARY)..."
	go build -o $(BIN_DIR)/$(BINARY) main.go

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Run all tests
test:
	@echo "Running tests..."
	go test ./...

# Clean up build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BIN_DIR)
