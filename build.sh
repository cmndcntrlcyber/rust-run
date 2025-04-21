#!/bin/bash

echo "=== Rust Dictionary-Based Shellcode Execution Utility Build Script ==="

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "Error: Rust is not installed! Please install Rust first."
    echo "Visit https://rustup.rs for installation instructions."
    exit 1
fi

# Display versions
echo "Using Rust version:"
rustc --version

echo "Using Cargo version:"
cargo --version

echo "Checking dependencies..."
cargo check

# Build options
echo "Select build type:"
echo "1) Debug build (faster compilation, better for development)"
echo "2) Release build (optimized, smaller binary)"
read -p "Select option [2]: " BUILD_TYPE

# Default to release build
BUILD_TYPE=${BUILD_TYPE:-2}

if [ "$BUILD_TYPE" = "1" ]; then
    echo "Building debug version..."
    cargo build
    BINARY_PATH="target/debug/rust-run"
else
    echo "Building release version with maximum optimizations..."
    RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo build --release
    BINARY_PATH="target/release/rust-run"
fi

# Check if build was successful
if [ -f "$BINARY_PATH" ]; then
    echo "Build successful!"
    
    # Binary info
    echo "Binary information:"
    ls -la "$BINARY_PATH"
    
    # Ask to run the program
    read -p "Run the program now? (y/n) [n]: " RUN_NOW
    RUN_NOW=${RUN_NOW:-n}
    
    if [[ $RUN_NOW =~ ^[Yy]$ ]]; then
        echo "Running the program..."
        read -p "Enable debug logging? (y/n) [n]: " DEBUG_LOG
        DEBUG_LOG=${DEBUG_LOG:-n}
        
        if [[ $DEBUG_LOG =~ ^[Yy]$ ]]; then
            RUST_LOG=debug ./"$BINARY_PATH"
        else
            ./"$BINARY_PATH"
        fi
    else
        echo "To run the program manually:"
        echo "./$BINARY_PATH"
        echo "For debug logging: RUST_LOG=debug ./$BINARY_PATH"
    fi
else
    echo "Build failed! Binary not found at $BINARY_PATH"
    exit 1
fi
