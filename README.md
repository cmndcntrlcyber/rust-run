# Rust-Runner

A sophisticated shellcode execution framework written in Rust, designed to demonstrate advanced evasion techniques and memory manipulation.

## ⚠️ Educational Purpose Only

This tool is provided strictly for **educational and research purposes**. It demonstrates various techniques that could be misused. Only use this in controlled environments with proper authorization.

## Overview

Rust-Runner is a framework that demonstrates various techniques for shellcode execution while implementing multiple evasion methods. It showcases how malware might attempt to bypass security controls through techniques like:

- Indirect syscalls
- Dictionary-based payload encoding
- Anti-analysis checks
- Memory protection manipulation
- Remote payload retrieval

## Features

- **Dictionary-based Encoding/Decoding**: Uses a Spanish word dictionary to encode binary payloads as text
- **Indirect Syscalls**: Executes Windows syscalls indirectly to avoid detection
- **Anti-Analysis**: Implements timing checks to detect virtualized environments
- **Flexible Payload Loading**: Can load shellcode from local files or remote sources
- **Memory Protection Manipulation**: Uses syscalls to allocate and protect memory
- **HTTP Client with Evasive Properties**: Configures requests to appear more legitimate

## Components

### Main Components

- **src/main.rs**: Core Rust implementation with shellcode execution logic
- **encoder.py**: Python script for encoding binary payloads using the dictionary
- **es-dictionary.txt**: Spanish word dictionary used for encoding/decoding
- **Cargo.toml**: Project configuration and dependencies

### Key Structures and Functions

- `Decoder`: Handles dictionary-based decoding of payloads
- `execute_shellcode()`: Allocates memory and executes shellcode using indirect syscalls
- `indirect_syscall()`: Performs syscalls indirectly to avoid detection
- `detect_analysis_environment()`: Checks for virtualized environments
- `get_syscall_info()`: Resolves syscall numbers and addresses from ntdll.dll

## Usage

### Building

```bash
cargo build --target x86_64-pc-windows-gnu --release
```

The release profile includes optimizations for better evasion:
- Maximum optimization level (opt-level = 3)
- Link-time optimization (lto = true)
- Single codegen unit for better optimization
- Panic abort to reduce binary size
- Binary stripping to remove debug symbols

### Encoding Payloads

To encode a binary payload:

```bash
python encoder.py
```

This will:
1. Attempt to download a binary from the configured URL
2. Encode it using the Spanish dictionary
3. Save the encoded payload to `load.txt`

### Execution

When executed, the program will:

1. Check for analysis environments (and exit silently if detected)
2. Look for a local binary payload at `cs/beacon_x64.bin`
3. If not found, download the dictionary and encoded payload
4. Decode the payload
5. Allocate memory with proper protections
6. Execute the shellcode

## Technical Details

### Syscall Implementation

The program uses indirect syscalls to avoid detection:

1. Resolves syscall numbers and addresses from ntdll.dll
2. Uses assembly to perform syscalls indirectly
3. Implements NtAllocateVirtualMemory and NtProtectVirtualMemory

### Dictionary Encoding

The encoding system:
1. Maps 256 Spanish words to byte values (0-255)
2. Encodes each byte of the binary as a word
3. Joins words with spaces to create the encoded payload

## Dependencies

- **reqwest**: HTTP client for downloading payloads
- **winapi**: Windows API bindings with specific features:
  - winuser
  - libloaderapi
  - winnt

## Security Considerations

This tool demonstrates techniques that could be misused. It should only be used in controlled environments with proper authorization. Some security products may flag this as malicious due to the techniques it employs.

## License

This project is provided for educational purposes only. Use responsibly.
