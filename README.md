# Optimized Shellcode Execution Utility

A secure and optimized utility for executing encoded shellcode through a dictionary-based decoding mechanism.

## Optimizations Implemented

The project has been significantly optimized to ensure reliable shellcode execution:

### Memory Handling Improvements

- **Two-phase memory allocation**: First allocates with RW permissions for safer copying, then switches to execute-only permissions
- **Memory alignment**: Ensures 16-byte alignment for optimal cache performance
- **Memory protection**: Uses the principle of least privilege with PAGE_EXECUTE rather than PAGE_EXECUTE_READ
- **Instruction cache flushing**: Explicitly flushes the CPU instruction cache to ensure code visibility
- **Memory barriers**: Added memory barriers to prevent instruction reordering

### Performance Optimizations

- **HashMap-based dictionary lookup**: O(1) lookups instead of O(n) linear searches for significant speed improvement
- **Local file caching**: Automatically caches dictionary and payload locally to reduce network dependency
- **Proper memory cleanup**: Ensures allocated memory is properly released even when execution fails
- **Fallback execution method**: Provides alternative execution path if primary method fails
- **Optimized builds**: Enhanced build scripts with target-specific optimizations

### Reliability Enhancements

- **Detailed error reporting**: Captures and reports Windows error codes for better diagnostics
- **Debug mode**: Added debug mode for detailed shellcode inspection
- **Missing token tracking**: Counts and reports missing dictionary tokens
- **Type safety improvements**: Proper function signatures for memory-mapped code
- **Cross-platform build support**: Enhanced build scripts for both Windows and Unix

## Build Instructions

### Windows
```
build.bat
```

### Unix-based Systems
```
./build.sh
```

Both scripts offer debug or release build options, with release builds applying maximum optimization.

## Usage

The application will automatically:

1. Download (or load cached) dictionary and encoded payload
2. Decode the payload using the dictionary
3. Allocate properly aligned and protected memory
4. Copy and execute the decoded shellcode

### Environment Variables

- `RUST_LOG=debug` - Enable debug logging for detailed execution information

## Technical Implementation Details

### Memory Protection Workflow

1. Allocate memory with `PAGE_READWRITE` permissions
2. Copy shellcode bytes to allocated memory
3. Change protection to `PAGE_EXECUTE` (execute-only) using `VirtualProtect`
4. Flush instruction cache with `FlushInstructionCache`
5. Insert memory barriers before and after execution
6. Execute shellcode with proper function signature
7. Release memory with `VirtualFree`

### Dictionary Decoding Optimization

The original linear search algorithm (`O(n)` complexity) has been replaced with a `HashMap` implementation (`O(1)` complexity), dramatically improving decoding performance, especially for large dictionaries.

### Fallback Execution

If the primary execution method fails, the system falls back to a more permissive approach using `PAGE_EXECUTE_READWRITE` memory protection for maximum compatibility.

## Security Considerations

This utility implements several security measures:

- HTTPS-only URL validation
- Memory protection principle of least privilege
- Proper error handling and reporting
- Debugger detection
- Memory cleanup

## Requirements

- Rust 1.67.0 or higher
- Windows operating system (primary target)
- Linux/macOS (supported for development only)
