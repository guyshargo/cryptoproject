import random
from utils import int_from_bytes, int_to_bytes
# Importing from your fixed ecc.py file
from ecc import (
    ECPoint, 
    scalar_mult, 
    point_add, 
    point_neg, 
    keygen, 
    G, N, P, A, B, O
)

# --- Helper Math Functions ---

def is_quad_residue(n, p):
    """Checks if n is a quadratic residue mod p."""
    return pow(n, (p - 1) // 2, p) == 1

def sqrt_mod_p(n, p):
    """Finds a square root of n modulo p (for Secp256k1)."""
    if not is_quad_residue(n, p):
        return None
    return pow(n, (p + 1) // 4, p)

def point_sub(p1, p2):
    """Subtracts point p2 from p1: P1 - P2 = P1 + (-P2)"""
    return point_add(p1, point_neg(p2))

# --- Encoding / Decoding (Symmetric Key <-> ECPoint) ---

def key_to_point(symmetric_key_bytes):
    """
    Maps the Symmetric Key (raw bytes) to a valid ECPoint.
    Usage: Converts the IDEA/AES key into a geometric point so ElGamal can encrypt it.
    """
    key_int = int_from_bytes(symmetric_key_bytes)
    
    # Validation: The key must fit into the curve field with room for padding
    # We reserve 16 bits for the counter.
    if key_int >= (P >> 16):
        raise ValueError("Key is too long to encode directly on this curve")

    # Shift left to make room for a counter (16 bits)
    x_prefix = key_int << 16 
    
    # Try to find a valid coordinate on the curve
    for counter in range(2**16):
        x = x_prefix + counter
        
        # Curve equation: y^2 = x^3 + ax + b
        rhs = (pow(x, 3, P) + (A * x) + B) % P
        
        # Check if we can find a 'y' (is RHS a square?)
        y = sqrt_mod_p(rhs, P)
        
        if y is not None:
            # Success: The symmetric key is now encoded as a point
            return ECPoint(x, y)
            
    raise Exception("Failed to map key to point (try a different key)")

def point_to_key(point):
    """
    Extracts the Symmetric Key bytes from the ECPoint.
    """
    if point is O or point is None:
        raise ValueError("Cannot decode point at infinity")

    # Remove the padding (counter) to get the original key value
    key_int = point.x >> 16
    
    # Convert back to 16 bytes (assuming 128-bit symmetric key like IDEA)
    return int_to_bytes(key_int, 16) 

# --- Key Encapsulation (Encryption of the Key) ---

def generate_keys():
    """
    Generates Alice/Bob's asymmetric keys for the key exchange.
    Returns (private_key, public_key_point).
    """
    return keygen()

def encrypt_key(public_key, symmetric_key_bytes):
    """
    Encrypts the SYMMETRIC KEY using the receiver's Public Key.
    
    Args:
        public_key: The receiver's (Bob's) EC public key.
        symmetric_key_bytes: The secret session key (e.g., 16 bytes for IDEA).
        
    Returns:
        (C1, C2): A pair of points representing the encrypted key.
    """
    # 1. Map the secret key bytes to a point on the curve
    key_point = key_to_point(symmetric_key_bytes)
    
    # 2. Choose random k (ephemeral key for this transmission)
    k = random.SystemRandom().randint(1, N - 1)
    
    # 3. Calculate C1 = k * G (The hint for Bob)
    C1 = scalar_mult(k, G)
    
    # 4. Calculate C2 = key_point + Shared_Secret
    # Shared secret S = k * Public_Key
    S = scalar_mult(k, public_key)
    
    # Hide the key point by adding the shared secret
    C2 = point_add(key_point, S)
    
    return C1, C2

def decrypt_key(private_key, C1, C2):
    """
    Decrypts the SYMMETRIC KEY using the receiver's Private Key.
    
    Args:
        private_key: The receiver's (Bob's) private integer.
        C1, C2: The pair of points received from the sender.
        
    Returns:
        symmetric_key_bytes: The raw bytes of the secret session key.
    """
    # 1. Recreate shared secret: S = d * C1
    S = scalar_mult(private_key, C1)
    
    # 2. Recover the Key Point: key_point = C2 - S
    key_point = point_sub(C2, S)
    
    # 3. Decode the point back to raw key bytes
    symmetric_key_bytes = point_to_key(key_point)
    
    return symmetric_key_bytes