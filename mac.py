from utils import sha256

# SHA-256 block size is 64 bytes
BLOCK_SIZE = 64

# Computes HMAC-SHA256 according to RFC 2104.
# Formula: H((K' ^ opad) || H((K' ^ ipad) || message))
def hmac_sha256(key_bytes, message_bytes):

    # Keys longer than block size are hashed
    if len(key_bytes) > BLOCK_SIZE:
        key_bytes = sha256(key_bytes)
    
    # Keys shorter than block size are padded with zeros
    if len(key_bytes) < BLOCK_SIZE:
        key_bytes = key_bytes + b'\x00' * (BLOCK_SIZE - len(key_bytes))

    # Prepare Inner (ipad) and Outer (opad) Pads
    ipad = bytearray((x ^ 0x36) for x in key_bytes)
    opad = bytearray((x ^ 0x5c) for x in key_bytes)

    # Inner Hash calculation
    inner_data = ipad + message_bytes
    inner_hash_bytes = sha256(inner_data) # Returns bytes directly

    # Outer Hash calculation with inner hash result
    outer_data = opad + inner_hash_bytes
    hmac_result = sha256(outer_data) # Returns bytes
    
    return hmac_result
