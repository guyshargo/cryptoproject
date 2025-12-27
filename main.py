import users as user_module

from utils import randbytes
from cbc import cbc_encrypt, cbc_decrypt
from ecc import EllipticCurve, ECPoint
from ec_elgamal import ec_elgamal_encrypt_key, ec_elgamal_decrypt_key
from idea import idea_key_schedule
# ------------------ Security checks ------------------
    #Checks if an IDEA key is considered 'weak'.
    #Criteria:
    #1. Trivial patterns (sequence of zeros or ones).
    #2. Too many subkeys that are 0, 1, or 0xFFFF.
def is_strong_idea_key(key_bytes):

    # 1. Trivial Check - All zeros or all ones
    if key_bytes == b'\x00' * 16:
        print("[Security Warning] Weak Key Detected: All Zeros.")
        return False
        
    if key_bytes == b'\xFF' * 16:
        print("[Security Warning] Weak Key Detected: All Ones.")
        return False
    # 2. Deep Check based on Subkeys
    # Generate the subkeys to analyze the key's internal structure
    subkeys = idea_key_schedule(key_bytes)
    
    weak_elements_count = 0    
    for val in subkeys:
        # In IDEA:
        # 0 is treated as 2^16 (in multiplication) or 0 (in addition)
        # 1 is the identity element for multiplication (x * 1 = x)
        # 65535 (0xFFFF) represents -1 (in modular addition)
        if val == 0 or val == 1 or val == 65535:
            weak_elements_count += 1
            
    # If more than 25% of the subkeys are "weak", the entire key is considered weak.
    if weak_elements_count > 13:
        print(f"[Security Warning] Weak Key Detected: Too many weak subkeys ({weak_elements_count}).")
        return False
    return True

def generate_strong_idea_key() -> bytes:
    """
    Generate IDEA key until it passes strength checks
    """
    while True:
        key = randbytes(16)
        if is_strong_idea_key(key):
            return key


# ------------------ Login ------------------

def login():
    print("Please log in")
    username = input("Enter username: ")
    password = input("Enter password: ")

    if user_module.verify_user(username, password):
        print(f"Access granted to {username}. You can now use the system.")
        return True
    else:
        print("Invalid username or password.")
        return False


# ------------------ Main flow ------------------

def main():
    # Create initial users
    user_module.create_initial_users()
    print("Welcome to the Secure System")

    # Login
    if not login():
        return

    print("\n--- System initialized ---")

    # ---------- ECC setup (Bob) ----------
    # Define elliptic curve (parameters chosen elsewhere / configuration)
    curve = EllipticCurve(p=23, a=1, b=1)
    base_point = ECPoint(3, 10)

    # Bob generates ECC key pair (repeat if weak / invalid)
    while True:
        bob_private_key, bob_public_key = curve.keygen(base_point)
        if bob_private_key != 0:
            break

    print("Bob's ECC keys generated")

    # ---------- Alice generates IDEA key ----------
    idea_key = generate_strong_idea_key()
    print("Alice generated a strong IDEA key")

    # ---------- Alice generates IV ----------
    iv = randbytes(8)
    print("Alice generated IV")

    # ---------- Alice encrypts data ----------
    plaintext = b"Secret image data (example)"
    ciphertext = cbc_encrypt(plaintext, idea_key, iv)
    print("Data encrypted using IDEA in CBC mode")

    # ---------- Alice encrypts IDEA key using EC-ElGamal ----------
    C1, C2 = ec_elgamal_encrypt_key(idea_key, bob_public_key)
    print("IDEA key encrypted using EC ElGamal")

    # ---------- Bob decrypts IDEA key ----------
    recovered_idea_key = ec_elgamal_decrypt_key(C1, C2, bob_private_key)

    if recovered_idea_key != idea_key:
        print("Key recovery failed!")
        return

    print("Bob successfully recovered IDEA key")

    # ---------- Bob decrypts data ----------
    decrypted_plaintext = cbc_decrypt(ciphertext, recovered_idea_key, iv)
    print("Bob decrypted the data successfully")

    print("\nDecrypted content:")
    print(decrypted_plaintext.decode())


# Entry point
main()
