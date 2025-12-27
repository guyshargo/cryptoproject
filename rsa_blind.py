import random
from utils import sha256, modinv, egcd

# User hides message with blinding factor, result is randomized gibberish because of r
def blind_message(message_bytes, e, n):

    # Turning message into a unique integer (hashing)
    msg_hash = int(sha256(message_bytes).hexdigest(), 16)

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
    # Hashing the original message
    msg_hash = int(sha256(message_bytes).hexdigest(), 16)

    # Check: s^e mod n == hash(m)
    calculated_hash = pow(signature, e, n)
    
    return calculated_hash == msg_hash