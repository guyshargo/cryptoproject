from utils import sha256

# SHA-256 block size is 64 bytes
BLOCK_SIZE = 64

# Computes HMAC-SHA256 according to RFC 2104.
# Formula: H((K' ^ opad) || H((K' ^ ipad) || message))
def hmac_sha256(key_bytes, message_bytes):

    # Keys longer than block size are hashed
    if len(key_bytes) > BLOCK_SIZE:
        key_hex = sha256(key_bytes)
        key_bytes = bytes.fromhex(key_hex)
    
    # Keys shorter than block size are padded with zeros
    if len(key_bytes) < BLOCK_SIZE:
        key_bytes = key_bytes + b'\x00' * (BLOCK_SIZE - len(key_bytes))

    # Prepare Inner (ipad) and Outer (opad) Pads.
    # The pads (0x36, 0x5c) generate two distinct keys from the single secret key to create a nested hash:
    # H(K_outer || H(K_inner || msg)). This prevents Length Extension Attacks.
    ipad = bytearray((x ^ 0x36) for x in key_bytes)
    opad = bytearray((x ^ 0x5c) for x in key_bytes)

    # Inner Hash calculation
    inner_data = ipad + message_bytes
    inner_hash_hex = sha256(inner_data)
    # Convert hex string result back to bytes for the outer hash
    inner_hash_bytes = bytes.fromhex(inner_hash_hex)

    # Outer Hash calculation with inner hash result
    outer_data = opad + inner_hash_bytes
    hmac_result = sha256(outer_data)
    
    return hmac_result

# Reads a file (image) in binary mode and returns its HMAC.
# Returns None if file doesn't exist.
def calculate_file_mac(file_path, key_bytes):

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        return hmac_sha256(key_bytes, file_data)
    except FileNotFoundError:
        return None

# Receiving user verifies if the file matches the received MAC using the secret key.
# Returns True if valid, False otherwise.
def verify_file_mac(file_path, received_mac, key_bytes):

    # Calculate MAC of the file with the shared secret key
    calculated_mac = calculate_file_mac(file_path, key_bytes)
    
    if calculated_mac is None:
        return False
        
    # If calculated MAC matches the received MAC, the file is valid
    return calculated_mac == received_mac