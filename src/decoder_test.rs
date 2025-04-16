use std::collections::HashMap;
use std::error::Error;
use std::fs;

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

fn main() -> Result<(), Box<dyn Error>> {
    println!("[*] Testing decoder with numeric fallback handling...");
    
    // Read the dictionary file
    let dictionary_text = fs::read_to_string("es-dictionary.txt")?;
    let decoder = Decoder::new(&dictionary_text);
    println!("[+] Dictionary loaded with {} entries", decoder.dictionary.len());
    
    // Read the encoded payload
    let encoded_payload = fs::read_to_string("../c-run/load.txt")?;
    
    println!("[*] Decoding payload...");
    let shellcode = decoder.decode(&encoded_payload);
    println!("[+] Payload size: {} bytes", shellcode.len());
    
    // Print first 20 bytes of the decoded shellcode in hex format for verification
    println!("[+] First 20 bytes of decoded payload:");
    for (i, &byte) in shellcode.iter().take(20).enumerate() {
        print!("{:02X} ", byte);
        if (i + 1) % 8 == 0 {
            println!();
        }
    }
    println!("\n[+] Decoding successful!");
    
    // Count the numeric fallbacks vs dictionary words
    let numeric_count = encoded_payload.split_whitespace()
        .filter(|word| word.parse::<u8>().is_ok())
        .count();
    
    let word_count = encoded_payload.split_whitespace().count();
    
    println!("[+] Statistics:");
    println!("    - Total tokens: {}", word_count);
    println!("    - Dictionary words: {}", word_count - numeric_count);
    println!("    - Numeric fallbacks: {} ({}%)", 
             numeric_count, 
             (numeric_count as f64 / word_count as f64 * 100.0) as u32);
    
    Ok(())
}
