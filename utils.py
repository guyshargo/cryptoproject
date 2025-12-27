# utils.py
import secrets
import hashlib

BLOCK_SIZE_IDEA = 8  # IDEA block size (64-bit)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    # Byte-wise XOR 
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    # Add PKCS#7 padding
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes, block_size: int) -> bytes:
    # Validate and remove PKCS#7 padding
    if not padded or (len(padded) % block_size) != 0:
        raise ValueError("Invalid padding length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding value")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return padded[:-pad_len]

def int_from_bytes(b: bytes) -> int:
    # Convert bytes to integer 
    return int.from_bytes(b, "big")

def int_to_bytes(x: int, length: int) -> bytes:
    # Convert integer to fixed-length bytes 
    return x.to_bytes(length, "big")

def egcd(a: int, b: int):
    # Extended Euclidean Algorithm
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def modinv(a: int, n: int) -> int:
    # Modular inverse of a mod n
    a %= n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % n

def sha256(data: bytes) -> bytes:
    # SHA-256 hash
    return hashlib.sha256(data).digest()

def randbytes(n: int) -> bytes:
    # Cryptographically secure random bytes
    return secrets.token_bytes(n)


IDEA_MOD = 65537  # 2^16 + 1

def idea_mul(a: int, b: int) -> int:
    """
    IDEA multiplication:
    multiplication modulo 65537, where 0 represents 65536.
    """
    if a == 0:
        a = IDEA_MOD - 1
    if b == 0:
        b = IDEA_MOD - 1

    r = (a * b) % IDEA_MOD

    if r == IDEA_MOD - 1:
        return 0
    return r


IDEA_ADD_MOD = 65536  # 2^16

def idea_add(a: int, b: int) -> int:
    """
    IDEA addition:
    addition modulo 2^16 (65536).
    """
    return (a + b) % IDEA_ADD_MOD
