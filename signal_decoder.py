import sys
import hashlib

def derive_key(passphrase: str) -> bytes:
    """Hash the passphrase using SHA-256 to get a 32-byte key."""
    return hashlib.sha256(passphrase.encode('utf-8')).digest()

def keystream_xor(data: bytes, key: bytes) -> bytes:
    """XOR data with a simple hash-chain keystream derived from the key."""
    out = bytearray()
    state = key
    for i in range(len(data)):
        state = hashlib.sha256(state).digest()
        out.append(data[i] ^ state[0])
    return bytes(out)

def hide_message(bmp_path: str, output_path: str, msg_bytes: bytes, passphrase: str):
    """Embeds encrypted bytes into the LSBs of BMP pixel data."""
    with open(bmp_path, 'rb') as f:
        bmp_data = bytearray(f.read())
    
    # Encrypt the message
    key = derive_key(passphrase)
    encrypted_msg = keystream_xor(msg_bytes, key)
    
    # Payload: 4 bytes length + encrypted message
    payload = len(encrypted_msg).to_bytes(4, byteorder='big') + encrypted_msg
    
    # Read pixel data offset from BMP header (offset 10, 4 bytes)
    pixel_offset = int.from_bytes(bmp_data[10:14], byteorder='little')
    
    # Check if image has enough capacity (1 bit per byte starting from offset)
    max_bits = len(bmp_data) - pixel_offset
    required_bits = len(payload) * 8
    
    if required_bits > max_bits:
        raise ValueError(f"BMP file too small. Need {required_bits} bits, but only have {max_bits} bits capacity.")
    
    # Write payload bits into the LSBs of BMP bytes
    bit_idx = 0
    for byte_val in payload:
        for bit_pos in range(8):
            # Extract bit starting from the MSB (bit 7) down to LSB (bit 0)
            bit = (byte_val >> (7 - bit_pos)) & 1
            idx = pixel_offset + bit_idx
            # Modify LSB
            bmp_data[idx] = (bmp_data[idx] & 0xFE) | bit
            bit_idx += 1
            
    with open(output_path, 'wb') as f:
        f.write(bmp_data)

def extract_message(bmp_path: str, passphrase: str) -> bytes:
    """Extracts encrypted bytes from the LSBs of BMP pixel data and decrypts them."""
    with open(bmp_path, 'rb') as f:
        bmp_data = f.read()
        
    pixel_offset = int.from_bytes(bmp_data[10:14], byteorder='little')
    
    # Extract 4-byte length (32 bits)
    len_bytes = bytearray()
    bit_idx = 0
    for _ in range(4):
        byte_val = 0
        for _ in range(8):
            idx = pixel_offset + bit_idx
            bit = bmp_data[idx] & 1
            byte_val = (byte_val << 1) | bit
            bit_idx += 1
        len_bytes.append(byte_val)
        
    length = int.from_bytes(len_bytes, byteorder='big')
    
    # Bounds check
    max_possible_len = (len(bmp_data) - pixel_offset) // 8 - 4
    if length < 0 or length > max_possible_len:
        # If the length is invalid, return garbage (key is wrong or not stego)
        length = max(0, min(100, max_possible_len))
    
    # Extract encrypted message
    encrypted_msg = bytearray()
    for _ in range(length):
        byte_val = 0
        for _ in range(8):
            idx = pixel_offset + bit_idx
            bit = bmp_data[idx] & 1
            byte_val = (byte_val << 1) | bit
            bit_idx += 1
        encrypted_msg.append(byte_val)
        
    # Decrypt the message
    key = derive_key(passphrase)
    decrypted_msg = keystream_xor(encrypted_msg, key)
    return decrypted_msg

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Signal Decoder Utility")
        print("Usage:")
        print("  python signal_decoder.py extract <input.bmp> <passphrase>")
        sys.exit(1)
        
    cmd = sys.argv[1]
    if cmd == 'extract':
        bmp_file = sys.argv[2]
        passphrase = sys.argv[3]
        try:
            extracted = extract_message(bmp_file, passphrase)
            # Write to stdout as raw bytes
            sys.stdout.buffer.write(extracted)
        except Exception as e:
            sys.stderr.write(f"Extraction failed: {e}\n")
            sys.exit(1)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
