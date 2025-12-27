import users as user_module

from utils import randbytes
from cbc import cbc_encrypt, cbc_decrypt
from ecc import EllipticCurve, ECPoint
from ec_elgamal import ec_elgamal_encrypt_key, ec_elgamal_decrypt_key


# ------------------ Security checks ------------------

def is_strong_idea_key(key: bytes) -> bool:
    """
    Check if IDEA key is strong enough:
    - correct length
    - not all bytes identical
    """
    if len(key) != 16:
        return False
    if all(b == key[0] for b in key):
        return False
    return True


def generate_strong_idea_key() -> bytes:
    """
    Generate a strong IDEA key (repeat until valid)
    """
    while True:
        key = randbytes(16)
        if is_strong_idea_key(key):
            return key


# ------------------ Login ------------------

def login() -> bool:
    print("Please log in")
    username = input("Enter username: ")
    password = input("Enter password: ")

    if user_module.verify_user(username, password):
        print(f"Access granted to {username}.")
        return True
    else:
        print("Invalid username or password.")
        return False


# ------------------ ECC / Bob side ------------------

def setup_bob_ecc():
    """
    Initialize elliptic curve and generate Bob's ECC key pair
    """
    curve = EllipticCurve(p=23, a=1, b=1)
    base_point = ECPoint(3, 10)

    while True:
        bob_private_key, bob_public_key = curve.keygen(base_point)
        if bob_private_key != 0:
            break

    print("Bob's ECC keys generated")
    return curve, bob_private_key, bob_public_key


# ------------------ Alice side ------------------

def alice_encrypt_data(plaintext: bytes, bob_public_key: ECPoint):
    """
    Alice:
    - generates IDEA key
    - generates IV
    - encrypts data with CBC
    - encrypts IDEA key using EC ElGamal
    """
    idea_key = generate_strong_idea_key()
    print("Alice generated a strong IDEA key")

    iv = randbytes(8)
    print("Alice generated IV")

    ciphertext = cbc_encrypt(plaintext, idea_key, iv)
    print("Data encrypted using IDEA in CBC mode")

    C1, C2 = ec_elgamal_encrypt_key(idea_key, bob_public_key)
    print("IDEA key encrypted using EC ElGamal")

    return ciphertext, iv, C1, C2, idea_key


# ------------------ Bob side ------------------

def bob_decrypt_data(ciphertext: bytes, iv: bytes,
                     C1: bytes, C2: bytes,
                     bob_private_key: int) -> bytes:
    """
    Bob:
    - decrypts IDEA key
    - decrypts data using CBC
    """
    recovered_idea_key = ec_elgamal_decrypt_key(C1, C2, bob_private_key)
    print("Bob recovered IDEA key")

    plaintext = cbc_decrypt(ciphertext, recovered_idea_key, iv)
    print("Bob decrypted the data")

    return plaintext


# ------------------ Main flow ------------------

def main():
    user_module.create_initial_users()
    print("Welcome to the Secure System")

    if not login():
        return

    print("\n--- System initialized ---")

    # Bob setup
    curve, bob_private_key, bob_public_key = setup_bob_ecc()

    # Alice encrypts
    plaintext = b"Secret image data (example)"
    ciphertext, iv, C1, C2, _ = alice_encrypt_data(
        plaintext, bob_public_key
    )

    # Bob decrypts
    decrypted_plaintext = bob_decrypt_data(
        ciphertext, iv, C1, C2, bob_private_key
    )

    print("\nDecrypted content:")
    print(decrypted_plaintext.decode())


# Entry point
main()
