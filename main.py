import os
import struct
import users as user_module

from utils import randbytes, read_image_binary,show_image_from_bytes,show_encrypted_noise, int_from_bytes, int_to_bytes
from cbc import cbc_encrypt, cbc_decrypt
from ecc import ECPoint, keygen
from ec_elgamal import ec_elgamal_encrypt_key, ec_elgamal_decrypt_key
from idea import idea_key_schedule
from mac import hmac_sha256
from rsa_blind import generate_rsa_keypair, blind_message, unblind_signature, sign_blinded_message, verify_signature

# ==========================================
#         SYSTEM & AUTHORITY SETUP
# ==========================================

#(Authority public and private keys)
AUTH_PRIV_KEY = None # (d, n)
AUTH_PUB_KEY = None  # (e, n)

def setup_authority():
    #sets public and private keys for the simulated authority
    global AUTH_PRIV_KEY, AUTH_PUB_KEY
    print(" > Setting up Virtual Certificate Authority (RSA)...")
    pub, priv = generate_rsa_keypair(keysize=2048)
    AUTH_PUB_KEY = pub
    AUTH_PRIV_KEY = priv
    print(" > Authority ready.")

def simulated_authority_sign_request(blinded_msg_int):
    # Simulates the authority signing the blinded message
    d, n = AUTH_PRIV_KEY
    return sign_blinded_message(blinded_msg_int, d, n)

# ------------------ Security checks ------------------
    #Checks if an IDEA key is considered 'weak'.
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

#------------------ Sender Flow ------------------

def run_sender_process(source_file_path: str, receiver_public_key: ECPoint):
    """
    Simulates the SENDER actions:
    1. RSA Blind Sign: Get approval from Authority.
    2. IDEA Key Gen: Create strong key.
    3. Encrypt: IDEA-CBC (Image + Signature).
    4. MAC: Integrity check on Ciphertext.
    5. Key Exchange: Encrypt IDEA key using EC-ElGamal.
    """
    print(f"\n--- [Sender] Processing file: {source_file_path} ---")
    
    # A. Load Data
    try:
        image_data = read_image_binary(source_file_path)
        print(f" > File loaded. Size: {len(image_data)} bytes.")
        print(f" > Image Data Sample (first 64 bytes): {image_data[:64].hex()}...")
    except FileNotFoundError:
        print(" > Error: Source file not found.")
        return None
    
    show_image_from_bytes(image_data, title="[Sender] Original Image")

    # B. RSA Blind Signature (Authentication)
    print(" > 1. Requesting Blind Signature from Authority...")
    auth_e, auth_n = AUTH_PUB_KEY
    
    # Blinding
    blinded_msg, r_factor = blind_message(image_data, auth_e, auth_n)
    # Signing (Simulated Server)
    signed_blinded_msg = simulated_authority_sign_request(blinded_msg)
    # Unblinding
    rsa_signature_int = unblind_signature(signed_blinded_msg, r_factor, auth_n)
    # Convert sig to bytes (256 bytes for 2048-bit key)
    rsa_signature_bytes = int_to_bytes(rsa_signature_int, 256)
    print(f" >    RSA Signature: {rsa_signature_bytes.hex()[:64]}...")

    # C. Prepare Payload (Pack Signature + Image)
    sig_len = len(rsa_signature_bytes)
    # Format: [4 bytes length][Signature][Image]
    payload = struct.pack('>I', sig_len) + rsa_signature_bytes + image_data
    # D. Encrypt Data (IDEA-CBC)
    print(" > 2. Encrypting Payload (Image + Signature)...")
    idea_key = generate_strong_idea_key()
    print(f" >    Generated Strong IDEA Key: {idea_key.hex()}")
    
    full_ciphertext = cbc_encrypt(idea_key, payload)
    
    # Show noise just for visual confirmation
    # We take a slice just to show noise, as full_ciphertext has IV at start
    show_encrypted_noise(full_ciphertext[8:], title="[Sender] Encrypted Image")
    print(f" >    Encrypted Image Bytes Sample (first 64 bytes): {full_ciphertext[8:72].hex()}...")
    # E. MAC (Integrity) - Encrypt-then-MAC
    print(" > 3. Generating MAC on Ciphertext...")
    mac_tag = hmac_sha256(idea_key, full_ciphertext)
    print(f" >    MAC Tag: {mac_tag.hex()}")
    # F. Encrypt Key (EC-ElGamal)
    print(" > 4. Encrypting IDEA Key for Receiver with EC-ElGamal...")
    enc_elgamal_points = ec_elgamal_encrypt_key(receiver_public_key, idea_key)
    print(f" >    Encrypted Key Points: C1={enc_elgamal_points[0]}")
    print(f" >                          C2={enc_elgamal_points[1]}")
    # Return the network package
    package = {
        'enc_key': enc_elgamal_points,
        'ciphertext': full_ciphertext,
        'mac': mac_tag
    }
    return package


#------------------ Receiver Flow ------------------

def run_receiver_process(package, receiver_private_key):
    print(f"\n--- [Receiver] Package Received ---")
    
    enc_key_points = package['enc_key']
    full_ciphertext = package['ciphertext']
    received_mac = package['mac']
    
    C1, C2 = enc_key_points

    # 1. Decrypt IDEA Key (ECC)
    print(" > 1. Decrypting Session Key with EC-ElGamal...")
    print(f" >    Encrypted Key Points: C1={enc_key_points[0]}")
    print(f" >                          C2={enc_key_points[1]}")
    try:
        session_key = ec_elgamal_decrypt_key(receiver_private_key, C1, C2)
        print(f" >    Key Recovered: {session_key.hex()}")
    except Exception as e:
        print(f" > Error decrypting key: {e}")
        return

    # 2. Verify MAC (Integrity)
    print(" > 2. Verifying MAC on Ciphertext...")
    print(f" >    MAC Received: {received_mac.hex()}")
    calc_mac = hmac_sha256(session_key, full_ciphertext)
    if calc_mac != received_mac:
        print(" > SECURITY ALERT: MAC Mismatch! File Corrupted.")
        return
    print(" >    MAC Verified.")

    # 3. Decrypt Payload (IDEA-CBC)
    print(" > 3. Decrypting Payload (Signature + Image)...")
    try:
        decrypted_payload = cbc_decrypt(session_key, full_ciphertext)
    except Exception as e:
        print(f" > Decryption failed: {e}")
        return

    # 4. Unpack and Verify Signature
    print(" > 4. Verifying Signature...")
    try:
        # Read first 4 bytes for length
        sig_len = struct.unpack('>I', decrypted_payload[:4])[0]
        # Extract components
        rsa_sig_bytes = decrypted_payload[4 : 4+sig_len]
        image_data = decrypted_payload[4+sig_len :]
        
        rsa_sig_int = int_from_bytes(rsa_sig_bytes)
    except:
        print(" > Error unpacking payload.")
        return

    print (f" >    Extracted Signature: {rsa_sig_bytes.hex()[:64]}...")
    # Verify against Authority
    auth_e, auth_n = AUTH_PUB_KEY
    is_valid = verify_signature(image_data, rsa_sig_int, auth_e, auth_n)
    
    if is_valid:
        print(" >    SUCCESS: Signature is VALID. Image is Authentic.")
        show_image_from_bytes(image_data, title="[Receiver] Decrypted & Verified Image")
        print(f" >    Decrypted Image Data Sample (first 64 bytes): {image_data[:64].hex()}...")
    else:
        print(" > WARNING: Signature is INVALID!")


# ------------------ Main flow ------------------

def main():
    # 1. Setup Users
    user_module.create_initial_users()
    print("\nWelcome to the Secure System")

    # 2. Login
    if not login():
        return
    print("\n--- System Initialized ---")

    # 3. Setup Authority (RSA)
    setup_authority()

    # 4. Setup Receiver (ECC - Secp256k1)
    print(" > Generating Receiver's ECC Keys...")
    rec_priv, rec_pub = keygen()
    print(f" > Public Key: {rec_pub}")
    print(f" > Private Key: {rec_priv}")
    # 5. Setup Source File
    source_file = "images.jpg"
    
    # Sender Sends
    package = run_sender_process(source_file, rec_pub)
    
    if package:
        print("\n" + "="*30 + "\n   Sending Image To Receiver   \n" + "="*30)
    
        # Receiver Receives
        run_receiver_process(package, rec_priv)


# Entry point
main()
