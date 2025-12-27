import random
from utils import sha256, modinv, egcd, int_from_bytes

def is_prime(n, k=40):
    """
    Tests if n is prime using the Miller-Rabin primality test.
    k is the number of tests (higher k = less chance of error).
    """
    if n == 2 or n == 3: return True
    if n % 2 == 0 or n < 2: return False

    # Find r and d such that n - 1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Run k witness tests
    for _ in range(k):
        a = random.SystemRandom().randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
            
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # Composite
            
    return True  # Probably prime

def generate_large_prime(keysize):
    """Generates a random prime number of keysize bits."""
    while True:
        # Generate random odd number
        num = random.SystemRandom().getrandbits(keysize)
        if num % 2 == 0: 
            num += 1
            
        # Test for primality
        if is_prime(num):
            return num

# ==========================================
#           RSA KEY GENERATION
# ==========================================

def generate_rsa_keypair(keysize=2048):
    """
    Generates an RSA keypair with the specified bit size.
    Returns: ((e, n), (d, n)) -> (Public Key, Private Key)
    """
    # 1. Choose public exponent e (usually 65537)
    e = 65537
    
    # 2. Generate two large primes p and q
    # We want n = p * q to be 'keysize' bits, so p and q are keysize/2
    size_per_prime = keysize // 2
    
    p = generate_large_prime(size_per_prime)
    q = generate_large_prime(size_per_prime)
    
    # Ensure p != q
    while p == q:
        q = generate_large_prime(size_per_prime)

    # 3. Calculate n (Modulus)
    n = p * q
    
    # 4. Calculate phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # 5. Calculate private exponent d
    # d is the modular inverse of e modulo phi
    # Note: If gcd(e, phi) != 1, we must regenerate (very rare with e=65537)
    try:
        d = modinv(e, phi)
    except:
        # Fallback in the super rare case e is not coprime to phi
        return generate_rsa_keypair(keysize)

    # Return keys: Public=(e,n), Private=(d,n)
    return ((e, n), (d, n))

# User hides message with blinding factor
def blind_message(message_bytes, e, n):

    # Turning message into a unique integer
    # Using utils.int_from_bytes because utils.sha256 returns raw bytes
    msg_hash = int_from_bytes(sha256(message_bytes))

    # Generating random r (Blinding Factor)
    while True:
        r = random.SystemRandom().randint(2, n - 1)
        if egcd(r, n)[0] == 1: # Check if r is coprime to n
            break

    # Formula for blinded message: m' = (m * r^e) mod n
    blinded_msg = (msg_hash * pow(r, e, n)) % n
    
    return blinded_msg, r

# Server signs the blinded message without knowing the original message
def sign_blinded_message(blinded_msg, d, n):

    # Formula for signed blinded message: s' = (m')^d mod n
    signed_blinded_msg = pow(blinded_msg, d, n)
    return signed_blinded_msg

# User removes blinding to get valid signature
def unblind_signature(signed_blinded_msg, r, n):
    # Finding r^-1 mod n for unblinding
    r_inv = modinv(r, n)
    # Formula for unblinded signature: s = (s' * r^-1) mod n
    signature = (signed_blinded_msg * r_inv) % n
    return signature

# Verification of the signature (if it matches the original message) by User B
def verify_signature(message_bytes, signature, e, n):
    # Hashing the original message to compare
    msg_hash = int_from_bytes(sha256(message_bytes))

    # Check: s^e mod n == hash(m)
    calculated_hash = pow(signature, e, n)
    
    return calculated_hash == msg_hash