#!/usr/bin/env python3
"""
Optimized encoder script for dictionary-based binary encoding.
This script encodes a binary file using a dictionary of words,
converting each byte to a corresponding word from the dictionary.
"""

import os
import random
import argparse
from typing import List, Dict, Union, BinaryIO
import sys

# Constants
DEFAULT_DICTIONARY_PATH = "jajajaja.txt"
DEFAULT_OUTPUT_PATH = "qwertytext.txt"
DEFAULT_BINARY_PATH = "mal-bin/beacon_x64.bin"

def load_dictionary(dictionary_path: str) -> List[str]:
    """Load dictionary words from a file."""
    try:
        with open(dictionary_path, 'r', encoding='utf-8') as dict_file:
            words = [word.strip() for word in dict_file.readlines() if word.strip()]
            
        if not words:
            print(f"Error: Dictionary file {dictionary_path} is empty.")
            sys.exit(1)
            
        return words
    except FileNotFoundError:
        print(f"Error: Dictionary file {dictionary_path} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading dictionary: {e}")
        sys.exit(1)

def read_binary_file(binary_path: str) -> bytes:
    """Read binary data from a file."""
    try:
        with open(binary_path, 'rb') as binary_file:
            return binary_file.read()
    except FileNotFoundError:
        print(f"Error: Binary file {binary_path} not found.")
        # Create a mock binary file for testing if file doesn't exist
        return create_mock_binary_file(binary_path)
    except Exception as e:
        print(f"Error reading binary file: {e}")
        sys.exit(1)

def create_mock_binary_file(binary_path: str) -> bytes:
    """Create a mock binary file for testing and return its contents."""
    print(f"Creating mock binary file at {binary_path} for testing...")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(binary_path), exist_ok=True)
    
    # Generate some test binary data (simulating a shellcode)
    # This is just for testing - in a real scenario you would use actual shellcode
    mock_data = bytes([random.randint(0, 255) for _ in range(256)])
    
    try:
        with open(binary_path, 'wb') as binary_file:
            binary_file.write(mock_data)
        print(f"Mock binary file created successfully at {binary_path}")
        return mock_data
    except Exception as e:
        print(f"Error creating mock binary file: {e}")
        sys.exit(1)

def encode_binary_with_dictionary(
    words: List[str], 
    binary_data: bytes, 
    output_path: str
) -> None:
    """Encode binary data using dictionary words and save to output file."""
    print(f"Encoding {len(binary_data)} bytes of binary data...")
    
    # Ensure we have enough words (at least 256 for all possible byte values)
    if len(words) < 256:
        print(f"Warning: Dictionary has only {len(words)} words, which is less than 256 required for unique mapping.")
        print("Some byte values will share the same word encoding.")
    
    # Create a mapping from byte values to words
    byte_to_word = {}
    for byte_val in range(256):
        # Use modulo to handle dictionaries with fewer than 256 words
        word_index = byte_val % len(words)
        byte_to_word[byte_val] = words[word_index]
    
    # Encode each byte of the binary data
    encoded_words = [byte_to_word[byte] for byte in binary_data]
    
    # Write the encoded result to the output file
    try:
        with open(output_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(encoded_words))
        print(f"Binary data encoded successfully and saved to {output_path}")
        print(f"Encoded {len(binary_data)} bytes into {len(encoded_words)} words")
    except Exception as e:
        print(f"Error writing to output file: {e}")
        sys.exit(1)

def main():
    """Main function to parse arguments and run the encoder."""
    parser = argparse.ArgumentParser(description='Dictionary-based binary encoder.')
    parser.add_argument('--dictionary', '-d', default=DEFAULT_DICTIONARY_PATH,
                        help=f'Path to the dictionary file (default: {DEFAULT_DICTIONARY_PATH})')
    parser.add_argument('--binary', '-b', default=DEFAULT_BINARY_PATH,
                        help=f'Path to the binary file to encode (default: {DEFAULT_BINARY_PATH})')
    parser.add_argument('--output', '-o', default=DEFAULT_OUTPUT_PATH,
                        help=f'Path to the output file (default: {DEFAULT_OUTPUT_PATH})')
    parser.add_argument('--create-mock', '-m', action='store_true',
                        help='Create a mock binary file even if the binary file exists')
    
    args = parser.parse_args()
    
    # Display program information
    print(f"Dictionary-based Binary Encoder")
    print(f"================================")
    print(f"Dictionary file: {args.dictionary}")
    print(f"Binary file: {args.binary}")
    print(f"Output file: {args.output}")
    
    # Load the dictionary
    words = load_dictionary(args.dictionary)
    print(f"Loaded {len(words)} words from dictionary")
    
    # Read the binary data or create mock data
    if args.create_mock or not os.path.exists(args.binary):
        binary_data = create_mock_binary_file(args.binary)
    else:
        binary_data = read_binary_file(args.binary)
    
    # Encode the binary data and save to output
    encode_binary_with_dictionary(words, binary_data, args.output)
    
    print("Encoding completed successfully!")
    print(f"The encoded file can now be used with the Rust decoder in src/main.rs")

if __name__ == "__main__":
    main()
