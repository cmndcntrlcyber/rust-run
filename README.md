# Rust-Run

A secure and optimized utility for executing encoded shellcode through a dictionary-based decoding mechanism.

## Key Features

### Memory Handling Optimizations

- **Two-phase memory allocation**: First allocates with RW permissions for safer copying, then switches to execute-only permissions
- **Memory alignment**: Ensures 16-byte alignment for optimal cache performance
- **Memory protection**: Uses the principle of least privilege with PAGE_EXECUTE rather than PAGE_EXECUTE_READWRITE
- **Memory barriers**: Implements memory barriers to prevent instruction reordering during execution

### Performance Optimizations

- **HashMap-based dictionary lookup**: O(1) lookups instead of O(n) linear searches for significant speed improvement
- **Local file caching**: Automatically caches dictionary and payload locally to reduce network dependency
- **Proper memory cleanup**: Ensures allocated memory is properly released even when execution fails
- **Fallback execution method**: Provides alternative execution path if primary method fails

### Security Enhancements

- **HTTPS-only URL validation**: Enforces secure connections for dictionary and payload retrieval
- **Detailed error reporting**: Captures and reports Windows error codes for better diagnostics
- **Debug mode**: Optional debug mode for detailed shellcode inspection with logging
- **Missing token tracking**: Counts and reports missing dictionary tokens

## Build System

### Release Profile Optimizations

The project's release profile is configured with the following optimizations in `Cargo.toml`:

```toml
[profile.release]
opt-level = 3       # Maximum optimization level
lto = true          # Link-time optimization for smaller binaries
codegen-units = 1   # Slower compilation but better optimization
panic = "abort"     # Smaller binary size by removing panic unwinding
strip = true        # Removes debug symbols
```

### Build Instructions

#### Windows
```
build.bat
```

#### Unix-based Systems
```
./build.sh
```

Both build scripts:
- Check for Rust installation and display version information
- Offer interactive selection between debug and release builds
- Apply platform-specific optimizations (target-cpu=native on Unix systems)
- Provide options to run the program after building
- Support enabling debug logging

### Release Build Specifics

The release build applies additional optimizations:
- On Unix systems: Uses RUSTFLAGS="-C target-cpu=native -C opt-level=3" for CPU-specific optimizations
- Generates a significantly smaller binary compared to debug builds
- Strips debugging information while maintaining error reporting capabilities

## Usage

The application will automatically:

1. Download (or load cached) dictionary and encoded payload
2. Decode the payload using the optimized HashMap-based dictionary lookup
3. Allocate properly aligned and protected memory
4. Copy and execute the decoded shellcode with appropriate memory protection

### Environment Variables

- `RUST_LOG=debug` - Enable detailed logging for execution information and shellcode debugging

## Technical Implementation

### Memory Protection Workflow

1. Allocate memory with `PAGE_READWRITE` permissions
2. Copy shellcode bytes to allocated memory
3. Change protection to `PAGE_EXECUTE` (execute-only) using `VirtualProtect`
4. Insert memory barriers before and after execution
5. Execute shellcode with proper function signature
6. Release memory with `VirtualFree`

### Dictionary Decoding Process

1. Create a HashMap from the dictionary for O(1) lookups
2. Process each token from the encoded payload
3. Look up token in dictionary or try parsing as direct byte value
4. Track and report any missing tokens
5. Return the decoded shellcode bytes

### Fallback Execution

If the primary execution method fails, the system falls back to a more permissive approach using `PAGE_EXECUTE_READWRITE` memory protection for maximum compatibility.

## Requirements

- Rust 1.67.0 or higher
- Windows operating system (primary target)
- Linux/macOS (supported for development and building)
