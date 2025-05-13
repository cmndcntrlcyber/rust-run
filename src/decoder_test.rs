use std::collections::HashMap;
use std::fs;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read dictionary and encoded payload
    let dictionary_text = fs::read_to_string("es-dictionary.txt")?;
    let encoded_payload = fs::read_to_string("load.txt")?;
    
    // Create dictionary mapping
    let dictionary: HashMap<String, u8> = dictionary_text
        .lines()
        .enumerate()
        .map(|(i, word)| (word.trim().to_string(), i as u8))
        .collect();
    
    println!("[+] Dictionary loaded with {} entries", dictionary.len());
    
    // Decode
    let shellcode: Vec<u8> = encoded_payload
        .split_whitespace()
        .filter_map(|word| {
            // Try to get from dictionary first
            if let Some(&byte) = dictionary.get(word) {
                Some(byte)
            } else {
                // If not in dictionary, try to parse as a number
                word.parse::<u8>().ok()
            }
        })
        .collect();
    
    println!("[+] Decoded payload size: {} bytes", shellcode.len());
    
    // Print as Rust array initialization code
    let mut output = String::new();
    output.push_str("// Decoded shellcode from load.txt\n");
    output.push_str("static EMBEDDED_SHELLCODE: &[u8] = &[\n    ");
    
    for (i, &byte) in shellcode.iter().enumerate() {
        output.push_str(&format!("0x{:02x}, ", byte));
        if (i + 1) % 12 == 0 && i > 0 {
            output.push_str("\n    ");
        }
    }
    
    output.push_str("\n];\n");
    
    // Print and write to a file
    println!("{}", output);
    let mut file = fs::File::create("shellcode_output.rs")?;
    file.write_all(output.as_bytes())?;
    
    println!("[+] Shellcode written to shellcode_output.rs");
    
    Ok(())
}
