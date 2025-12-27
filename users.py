import json
import hashlib
import os

USERS_FILE = "users.json"
PEPPER = "hennessy_vsop"
#Hashing function with salt and pepper
# Returns the hashed password
def HashPassword(password, salt):
    return hashlib.sha256((password + salt + PEPPER).encode()).hexdigest()

# Verifies if the username and password are correct
# Returns True if correct, False otherwise
def verify_user(username, password):
    if not os.path.exists(USERS_FILE):
        return False
    # Load users database
    with open(USERS_FILE, "r") as f:
        users_db = json.load(f)
    if username not in users_db:
        return False
    # Retrieve the stored salt and hash
    salt = users_db[username]["salt"]
    stored_hash = users_db[username]["hash"]
    # Calculate the hash with the provided password and stored salt
    return HashPassword(password, salt) == stored_hash

# Creates initial users if the users file does not exist
# Each user has a username, salt, and hashed password
# Creates users: guy, yarden, shelly
# Stores them in users.json
def create_initial_users():
    # Check if users file exists
    if not os.path.exists(USERS_FILE):
        users_db = {}
        # Create users with salts and hashed passwords
        salt1 = os.urandom(16).hex()
        pwd1 = "GuyPass123*"
        hash1 = HashPassword(pwd1, salt1)
        users_db["guy"] = {"salt": salt1, "hash": hash1}
        salt2 = os.urandom(16).hex()
        pwd2 = "YardenPass123*"
        hash2 = HashPassword(pwd2, salt2)
        users_db["yarden"] = {"salt": salt2, "hash": hash2}
        salt3 = os.urandom(16).hex()
        pwd3 = "ShellyPass123*"
        hash3 = HashPassword(pwd3, salt3)
        users_db["shelly"] = {"salt": salt3, "hash": hash3}
        # Save to users file
        with open(USERS_FILE, "w") as f:
            json.dump(users_db, f)
