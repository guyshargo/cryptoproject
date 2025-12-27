import random
from utils import int_from_bytes, int_to_bytes
from ecc import (
    ECPoint, 
    scalar_mult, 
    point_add, 
    point_neg, 
    keygen, 
    G, N, P, A, B, O
)

# Checks if n is a quadratic residue mod p.
def is_quad_residue(n, p):
    return pow(n, (p - 1) // 2, p) == 1

# Finds a square root of n modulo p.
# For Secp256k1, p = 3 mod 4, so we can use the simplified formula.
def sqrt_mod_p(n, p):
    if not is_quad_residue(n, p):
        return None
    return pow(n, (p + 1) // 4, p)

# Subtracts point p2 from p1: P1 - P2 = P1 + (-P2)
def point_sub(p1, p2):
    return point_add(p1, point_neg(p2))

# --- Encoding / Decoding (Bytes <-> ECPoint) ---

# Maps arbitrary bytes (e.g., an IDEA key) to a valid ECPoint.
# Method: Koblitz Encoding (padding message into x coordinate)
def msg_to_point(message_bytes):
    
    msg_int = int_from_bytes(message_bytes)
    
    # Check if message is too large for the padding strategy
    # We reserve 16 bits for the counter, so message must fit in remaining bits
    if msg_int >= (P >> 16):
        raise ValueError("Message too long to encode as point")

    # Shift left to make room for a counter (16 bits)
    x_prefix = msg_int << 16 
    
    for counter in range(2**16):
        x = x_prefix + counter
        
        # Calculate RHS = x^3 + ax + b (mod p)
        rhs = (pow(x, 3, P) + (A * x) + B) % P
        
        # Check if RHS is a square (Quadratic Residue)
        y = sqrt_mod_p(rhs, P)
        
        if y is not None:
            # Found a valid point! Return as ECPoint object
            return ECPoint(x, y)
            
    raise Exception("Failed to map message to point (try simpler/shorter message)")

# Extracts the original bytes from the ECPoint.
def point_to_msg(point):
    if point is O or point is None:
        raise ValueError("Cannot decode point at infinity")

    # Reverse the padding: remove the 16-bit counter
    msg_int = point.x >> 16
    
    # Convert back to bytes (16 bytes for 128-bit key)
    # Note: We assume the key is 16 bytes (128 bits) as used in IDEA
    return int_to_bytes(msg_int, 16) 

# --- Core ElGamal Functions ---

# Generates a private/public key pair.
# Uses the keygen wrapper from ecc.py which defaults to Secp256k1 generator G
def generate_keys():
    # Returns (d, Q) where Q = d*G
    return keygen()

# Alice encrypts a message to Bob.
# Returns pair of ECPoints (C1, C2)
def encrypt(public_key, message_bytes):

    # 1. Encode message bytes to a Point PM
    PM = msg_to_point(message_bytes)
    
    # 2. Choose random k (ephemeral key)
    k = random.SystemRandom().randint(1, N - 1)
    
    # 3. Calculate C1 = k * G (The hint)
    C1 = scalar_mult(k, G)
    
    # 4. Calculate C2 = PM + S (The masked message)
    # First calc shared secret: S = k * Public_Key
    S = scalar_mult(k, public_key)
    
    # Add points geometrically
    C2 = point_add(PM, S)
    
    return C1, C2

# Bob decrypts the message.
# Returns the original message bytes
def decrypt(private_key, C1, C2):

    # 1. Recreate shared secret: S = d * C1
    S = scalar_mult(private_key, C1)
    
    # 2. Recover Message Point: PM = C2 - S
    PM = point_sub(C2, S)
    
    # 3. Decode point back to bytes
    message_bytes = point_to_msg(PM)
    
    return message_bytes