# Rust Dictionary-Based Shellcode Execution Utility

A streamlined and secure Rust application that downloads, decodes, and executes shellcode using a dictionary-based encoding scheme.

## Features

- Efficient dictionary caching mechanism
- Secure HTTPS communication with retry and exponential backoff
- Direct Windows NT syscall execution to bypass API monitoring
- Comprehensive error handling with proper context
- Structured logging system
- Numeric fallback for decoder (handles dictionary words and direct byte values)
- Memory-safe implementation with proper checks
- Unit tests for core functionality

## Project Structure

This project uses a deliberate single-file implementation for simplicity and portability:

```
rust-run/
├── Cargo.toml       # Project dependencies and build settings
├── src/
│   └── main.rs      # All application functionality
├── build.bat        # Windows build script
├── build.sh         # Unix build script
└── README.md        # Project documentation
```

## Build Instructions

### Prerequisites

- Rust toolchain (1.60.0 or newer)
- Cargo package manager
- Windows environment (the code uses Windows-specific APIs)

### Building

```bash
# Development build
cargo build

# Release build with optimizations
cargo build --release
```

You can also use the provided build scripts:
- Windows: `.\build.bat`
- Unix: `./build.sh`

The compiled binary will be available at `target/release/rust-run.exe`.

## Running

```bash
# Run with default settings
./target/release/rust-run

# Run with environment variable to enable debug logs
RUST_LOG=debug ./target/release/rust-run
```

## How It Works

1. The application first checks for a cached dictionary file, downloading it if not present
2. It downloads the encoded payload from the specified URL
3. The payload is decoded using the dictionary (each word maps to a byte value)
4. Memory is allocated using direct NT syscalls rather than standard Windows APIs
5. The shellcode is placed in memory and executed

## Security Considerations

This application implements several security-enhancing techniques:

1. Memory safety through Rust's ownership model and proper error handling
2. Direct NT syscalls to bypass API hooking/monitoring
3. HTTPS-only communication for secure data transfer
4. Exponential backoff for failed network requests
5. Validation of inputs to prevent potential issues

## Testing

```bash
# Run all tests
cargo test

# Run with detailed output
cargo test -- --nocapture
```

## License

This project is intended for educational and research purposes only.
