# utils.py
import io
import os
import secrets
import hashlib
import matplotlib.pyplot as plt
import numpy as np
import math
from PIL import Image

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
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a: int, n: int) -> int:
    # Modular inverse of a mod n
    a %= n
    g, x, y = egcd(a, n)
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

# Computes the additive inverse modulo 2^16. In IDEA, addition is mod 65536.
def add_inverse_idea(x):
    return (IDEA_ADD_MOD - x) % IDEA_ADD_MOD

# Computes the multiplicative inverse modulo 2^16 + 1. 0 is treated as 2^16.
def mul_inverse_idea(x):
    if x == 0:
        x = IDEA_ADD_MOD
    
    # 65537 is prime, so inverse always exists for x != 0
    inv = modinv(x, IDEA_MOD)
    
    # Convert back to IDEA representation (2^16 becomes 0)
    if inv == IDEA_ADD_MOD:
        return 0
    return inv


def read_image_binary(filepath: str) -> bytes:
    """
    Reads a binary file from disk.
    Mode 'rb' ensures we get raw bytes without encoding issues.
    Returns: The raw byte content of the file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Image not found: {filepath}")
    
    with open(filepath, "rb") as f:
        file_content = f.read()
    
    return file_content

def write_image_binary(filepath: str, data: bytes):
    """
    Writes raw bytes to a file on disk.
    Mode 'wb' is used to write binary data 
    """
    with open(filepath, "wb") as f:
        f.write(data)
    print(f" [System] Image saved successfully to: {filepath}")

# ==========================================
# Visualization Functions
# ==========================================

def show_image_from_bytes(data: bytes, title="Image"):
    """
    Decodes and displays a valid image (JPG/PNG) from raw bytes.
    Used for: Original Image and Decrypted Image.
    """
    # Convert raw bytes to a file-like object in memory
    image_stream = io.BytesIO(data)
    
    # Open the image using PIL (to interpret the JPG/PNG format)
    img = Image.open(image_stream)
    
    # Plot using Matplotlib
    plt.figure(figsize=(6, 6))
    plt.imshow(img)
    plt.title(title)
    plt.axis('off') # Hide X and Y axes
    plt.show()
    

def show_encrypted_noise(data_bytes: bytes, title="Encrypted Data (Visualized)"):
    """
    Visualizes raw encrypted bytes as a grayscale noise image.
    Used for: The Encrypted Image (Ciphertext).
    Since ciphertext looks like random noise, we treat bytes as pixel intensity.
    """
    # 1. Convert bytes to a numpy array of integers (0-255)
    data_array = np.frombuffer(data_bytes, dtype=np.uint8)
    
    # 2. Calculate the dimensions of the square (Side * Side)
    length = len(data_array)
    side = int(math.ceil(math.sqrt(length)))
    
    # 3. Pad with zeros if necessary to form a perfect square
    padding_needed = (side * side) - length
    if padding_needed > 0:
        data_array = np.pad(data_array, (0, padding_needed), mode='constant', constant_values=0)
        
    # 4. Reshape 1D array to 2D matrix (Image)
    image_matrix = data_array.reshape((side, side))
    
    # 5. Plot
    plt.figure(figsize=(6, 6))
    plt.imshow(image_matrix, cmap='gray', vmin=0, vmax=255)
    plt.title(title)
    plt.axis('off')
    plt.show()