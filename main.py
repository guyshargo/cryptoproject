import users as user_module

#login function to authenticate user
def login():
    print("Please log in")
    username = input("Enter username: ")
    password = input("Enter password: ")
    # Verify user credentials
    if user_module.verify_user(username, password):
        print(f"Access granted to {username}. You can now use the system.")
        return True
    else:
        print("Invalid username or password.")
        return False

def main():
    # Create initial users
    user_module.create_initial_users()
    print("Welcome to the Secure System")
    # Login
    accessGranted = login()
    # If access is not granted, exit
    if( not accessGranted):
        return
    
    

main()