from utils import xor_bytes, pkcs7_pad, pkcs7_unpad, randbytes, BLOCK_SIZE_IDEA
from idea import idea_key_schedule, idea_encrypt_block, idea_decrypt_block

# IDEA uses 64-bit blocks (8 bytes)
# (Assumed imported or defined as 8)

def cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using IDEA in CBC mode.
    AUTO-GENERATES a random IV and prepends it to the result.
    Returns: [IV (8 bytes)] + [Ciphertext]
    """
    # 1. Generate random IV inside the function
    iv = randbytes(BLOCK_SIZE_IDEA)
    
    # 2. Key schedule & Padding
    subkeys = idea_key_schedule(key)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE_IDEA)

    ciphertext = bytearray()
    previous_block = iv  # IV is the first 'previous block'

    # 3. Encryption Loop
    for i in range(0, len(padded), BLOCK_SIZE_IDEA):
        block = padded[i : i + BLOCK_SIZE_IDEA]
        
        # XOR with previous
        input_block = xor_bytes(block, previous_block)
        
        # Encrypt with IDEA
        encrypted_block = idea_encrypt_block(input_block, subkeys)
        
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block # Update for next loop

    # 4. Return IV attached to the front!
    return iv + bytes(ciphertext)


def cbc_decrypt(key: bytes, full_data: bytes) -> bytes:
    """
    Decrypts data using IDEA in CBC mode.
    Expects input format: [IV (8 bytes)] + [Ciphertext]
    """
    # 1. Extract IV from the beginning
    if len(full_data) < BLOCK_SIZE_IDEA:
        raise ValueError("Data too short")
        
    iv = full_data[:BLOCK_SIZE_IDEA]
    actual_ciphertext = full_data[BLOCK_SIZE_IDEA:]

    subkeys = idea_key_schedule(key)
    
    plaintext = bytearray()
    previous_block = iv

    # 2. Decryption Loop
    for i in range(0, len(actual_ciphertext), BLOCK_SIZE_IDEA):
        encrypted_block = actual_ciphertext[i : i + BLOCK_SIZE_IDEA]
        
        # Decrypt with IDEA
        decrypted_x = idea_decrypt_block(encrypted_block, subkeys)
        
        # XOR with previous (Unchaining)
        original_block = xor_bytes(decrypted_x, previous_block)
        
        plaintext.extend(original_block)
        previous_block = encrypted_block # Must use the CIPHERTEXT as prev for next step

    # 3. Remove padding
    return pkcs7_unpad(bytes(plaintext), BLOCK_SIZE_IDEA)