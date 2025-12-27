from utils import idea_mul, idea_add, add_inverse_idea, mul_inverse_idea

# Decrypt a single 8-byte block using IDEA
def idea_decrypt_block(block, subkeys):
    # Generate decryption subkeys from encryption subkeys
    decryption_subkeys = Idea_decryption_subkeys(subkeys)
    # Use the same cryptographic function with decryption subkeys
    return idea_encrypt_block(block, decryption_subkeys)

# invert subkeys for decryption
def Idea_decryption_subkeys(encryption_subkeys):
    
    # Initialize a list of 52 zeros to hold the new keys
    decryption_subkeys = [0] * 52
    
    # Loop through the 8 rounds of decryption (0 to 7)
    for dec_round in range(8):
        
        # Calculate the starting index for the current decryption round
        dec_base_index = dec_round * 6
        
        if dec_round == 0:
            # --- Decryption Round 0 ---
            # This round must undo the Final Transformation of the encryption.
            # We take the last 4 encryption keys (48-51) and invert them.
            
            # Key 1: Multiplicative Inverse of the 1st final key
            decryption_subkeys[dec_base_index + 0] = mul_inverse_idea(encryption_subkeys[48])
            
            # Key 2: Additive Inverse of the 2nd final key
            decryption_subkeys[dec_base_index + 1] = add_inverse_idea(encryption_subkeys[49])
            
            # Key 3: Additive Inverse of the 3rd final key
            decryption_subkeys[dec_base_index + 2] = add_inverse_idea(encryption_subkeys[50])
            
            # Key 4: Multiplicative Inverse of the 4th final key
            decryption_subkeys[dec_base_index + 3] = mul_inverse_idea(encryption_subkeys[51])
            
            # Keys 5 & 6: 
            # These are the XOR keys from the last encryption round (Round 8).
            decryption_subkeys[dec_base_index + 4] = encryption_subkeys[46]
            decryption_subkeys[dec_base_index + 5] = encryption_subkeys[47]
            
        else:
            # --- Decryption Rounds 1 to 7 ---
            # These rounds undo Encryption Rounds 7 down to 1.
            
            # Calculate the corresponding encryption round we are reversing
            # e.g., If dec_round is 1, we look at encryption round 7.
            enc_round_index = 8 - dec_round
            
            # Calculate the base index for that encryption round
            enc_base_index = enc_round_index * 6
            
            # Key 1: Multiplicative Inverse
            decryption_subkeys[dec_base_index + 0] = mul_inverse_idea(encryption_subkeys[enc_base_index + 0])
            
            #Swap Keys 2 and 3
            # Key 2 and Key 3 must be swapped compared to encryption.
            # This is because the block cipher swaps block X2 and X3 at the end of each round.
            # To decrypt correctly, we must apply the additive inverse to the swapped positions.
            
            # Decryption Key 2 gets the inverse of Encryption Key 3
            decryption_subkeys[dec_base_index + 1] = add_inverse_idea(encryption_subkeys[enc_base_index + 2])
            
            # Decryption Key 3 gets the inverse of Encryption Key 2
            decryption_subkeys[dec_base_index + 2] = add_inverse_idea(encryption_subkeys[enc_base_index + 1])
            
            # Key 4: Multiplicative Inverse
            decryption_subkeys[dec_base_index + 3] = mul_inverse_idea(encryption_subkeys[enc_base_index + 3])
            
            # Keys 5 & 6 (Layer):
            # We take the keys from the PREVIOUS encryption round.
            # (Indices are -2 and -1 relative to the current encryption base)
            decryption_subkeys[dec_base_index + 4] = encryption_subkeys[enc_base_index - 2]
            decryption_subkeys[dec_base_index + 5] = encryption_subkeys[enc_base_index - 1]

    # Final Transformation 
    # After the 8 rounds, we must undo the first input transformation of encryption.
    # We take the first 4 keys of encryption (0-3) and invert them.
    last_keys_index = 48
    decryption_subkeys[48] = mul_inverse_idea(encryption_subkeys[0])
    decryption_subkeys[49] = add_inverse_idea(encryption_subkeys[1])
    decryption_subkeys[50] = add_inverse_idea(encryption_subkeys[2])
    decryption_subkeys[51] = mul_inverse_idea(encryption_subkeys[3])
    
    return decryption_subkeys

# Generates the 52 subkeys required for IDEA encryption.
# Input: key_bytes (16 bytes / 128 bits)
# Output: List of 52 integers (16-bit each)
def idea_key_schedule(key_bytes):
    # checlk key length
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 bytes (128 bits)")

    #  Convert key bytes to a single integer 
    current_key_val = int.from_bytes(key_bytes, 'big')
    # List to hold the 52 subkeys
    subkeys = []
    
    # Generate subkeys until we have 52
    while len(subkeys) < 52:
        
       # extract 8 subkeys from the current key value
        for i in range(8):
            # 16-bit shift amount
            # the shift amount is calculated as 112 - (i * 16)
            # 112 , 96, 80, 64, 48, 32, 16, 0
            shift_amount = 112 - (i * 16)
            
            # extract the 16-bit subkey
            subkey = (current_key_val >> shift_amount) & 0xFFFF
            subkeys.append(subkey)

        # Rotate the key left by 25 bits for the next iteration
        # ((x << 25) | (x >> (128 - 25)))
    
        high_part = (current_key_val << 25)
        low_part = (current_key_val >> (128 - 25)) 
        # mask for 128 bits
        mask_128 = (1 << 128) - 1  
        # combine and mask to 128 bits
        current_key_val = (high_part | low_part) & mask_128

    # Return exactly the 52 subkeys 
    return subkeys[:52]

def idea_encrypt_block(block, subkeys):
    # initialize variables
    # block is  8 bytes
    # splitting block into four 16-bit values
    # combine two bytes to form a 16-bit integer
    x1 = (block[0] << 8) | block[1]
    x2 = (block[2] << 8) | block[3]
    x3 = (block[4] << 8) | block[5]
    x4 = (block[6] << 8) | block[7]
    # perform 8 rounds
    for round in range(8):
        # each round uses 6 subkeys
        k = round * 6
    # Group operations: Addition (mod 2^16) and Multiplication (mod 2^16 + 1)
        x1 = idea_mul(x1, subkeys[k + 0])
        x2 = idea_add(x2, subkeys[k + 1])
        x3 = idea_add(x3, subkeys[k + 2])
        x4 = idea_mul(x4, subkeys[k + 3])
        # Calculate the XOR between X1 and X3, X2 and X4
        x1_x3_xor = x1 ^ x3
        x2_x4_xor = x2 ^ x4
        #calculate multiplaction (mod 2^16 + 1) X1_X3_XOR with subkey 5
        x1_x3_xor = idea_mul(x1_x3_xor, subkeys[k + 4])
        # calculate addition (mod 2^16) X2_X4_XOR with X1_X3_XOR
        x2_x4_xor = idea_add(x2_x4_xor, x1_x3_xor)
         # calculate multiplication (mod 2^16 + 1) X2_X4_XOR with subkey 6
        x2_x4_xor = idea_mul(x2_x4_xor, subkeys[k + 5])
        # calculate addition (mod 2^16) X2_X4_XOR with X1_X3_XOR
        x1_x3_xor = idea_add(x1_x3_xor, x2_x4_xor)
        #combine results back to x1, x2, x3, x4
        x1 = x1 ^ x2_x4_xor
        x3 = x3 ^ x2_x4_xor
        x2 = x2 ^ x1_x3_xor
        x4 = x4 ^ x1_x3_xor
        # swap x2 and x3 except for the last round
        if round < 7:
            tmp = x2; x2 = x3; x3 = tmp
    # final transformation with last 4 subkeys
    k = 48
    x1 = idea_mul(x1, subkeys[k + 0])
    x2 = idea_add(x2, subkeys[k + 1])
    x3 = idea_add(x3, subkeys[k + 2])
    x4 = idea_mul(x4, subkeys[k + 3])
    # combine back to 8 bytes
    # prepare result byte array
    res = bytearray(8)
    res[0], res[1] = x1 >> 8, x1 & 0xFF
    res[2], res[3] = x2 >> 8, x2 & 0xFF
    res[4], res[5] = x3 >> 8, x3 & 0xFF
    res[6], res[7] = x4 >> 8, x4 & 0xFF
    return bytes(res)

