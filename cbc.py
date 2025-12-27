# cbc.py
from utils import xor_bytes, pkcs7_pad, pkcs7_unpad, BLOCK_SIZE_IDEA
from idea import idea_key_schedule, idea_encrypt_block, idea_decrypt_block


def cbc_encrypt(data: bytes, key16: bytes, iv8: bytes) -> bytes:
    # Encrypt data using IDEA in CBC mode
    if len(iv8) != BLOCK_SIZE_IDEA:
        raise ValueError("IV must be 8 bytes")

    subkeys = idea_key_schedule(key16)
    padded = pkcs7_pad(data, BLOCK_SIZE_IDEA)

    ciphertext = bytearray()
    prev = iv8  # IV for first block

    for i in range(0, len(padded), BLOCK_SIZE_IDEA):
        block = padded[i:i + BLOCK_SIZE_IDEA]
        x = xor_bytes(block, prev)              # CBC chaining
        c = idea_encrypt_block(x, subkeys)      # IDEA encryption
        ciphertext += c
        prev = c

    return bytes(ciphertext)


def cbc_decrypt(ciphertext: bytes, key16: bytes, iv8: bytes) -> bytes:
    # Decrypt data using IDEA in CBC mode
    if len(iv8) != BLOCK_SIZE_IDEA:
        raise ValueError("IV must be 8 bytes")

    if len(ciphertext) % BLOCK_SIZE_IDEA != 0:
        raise ValueError("Ciphertext length must be multiple of block size")

    subkeys = idea_key_schedule(key16)

    plaintext = bytearray()
    prev = iv8  # IV for first block

    for i in range(0, len(ciphertext), BLOCK_SIZE_IDEA):
        c = ciphertext[i:i + BLOCK_SIZE_IDEA]
        x = idea_decrypt_block(c, subkeys)      # IDEA decryption
        p = xor_bytes(x, prev)                  # CBC unchaining
        plaintext += p
        prev = c

    return pkcs7_unpad(bytes(plaintext), BLOCK_SIZE_IDEA)

