#!/bin/bash

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Rust Dictionary-Based Shellcode Execution Utility Build Script ===${NC}"

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo -e "${RED}Error: Rust is not installed! Please install Rust first.${NC}"
    echo "Visit https://rustup.rs for installation instructions."
    exit 1
fi

# Display Rust version
echo -e "${BLUE}Using Rust version:${NC}"
rustc --version

# Display Cargo version
echo -e "${BLUE}Using Cargo version:${NC}"
cargo --version

echo -e "${BLUE}Checking dependencies...${NC}"
cargo check

# Build options
echo -e "${BLUE}Select build type:${NC}"
echo "1) Debug build (faster compilation, better for development)"
echo "2) Release build (optimized, smaller binary)"
read -p "Select option [2]: " BUILD_TYPE
BUILD_TYPE=${BUILD_TYPE:-2}

if [ "$BUILD_TYPE" = "1" ]; then
    echo -e "${BLUE}Building debug version...${NC}"
    cargo build
    BINARY_PATH="./target/debug/rust-run"
else
    echo -e "${BLUE}Building release version...${NC}"
    cargo build --release
    BINARY_PATH="./target/release/rust-run"
fi

# Check if build was successful
if [ -f "$BINARY_PATH" ]; then
    echo -e "${GREEN}Build successful!${NC}"
    
    # Binary info
    echo -e "${BLUE}Binary information:${NC}"
    ls -lh "$BINARY_PATH"
    
    # Ask to run the program
    read -p "Run the program now? (y/n) [n]: " RUN_NOW
    RUN_NOW=${RUN_NOW:-n}
    
    if [[ $RUN_NOW =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Running the program...${NC}"
        read -p "Enable debug logging? (y/n) [n]: " DEBUG_LOG
        DEBUG_LOG=${DEBUG_LOG:-n}
        
        if [[ $DEBUG_LOG =~ ^[Yy]$ ]]; then
            RUST_LOG=debug "$BINARY_PATH"
        else
            "$BINARY_PATH"
        fi
    else
        echo -e "${GREEN}To run the program manually:${NC}"
        echo "$BINARY_PATH"
        echo -e "For debug logging: ${BLUE}RUST_LOG=debug $BINARY_PATH${NC}"
    fi
else
    echo -e "${RED}Build failed! Binary not found at $BINARY_PATH${NC}"
    exit 1
fi
