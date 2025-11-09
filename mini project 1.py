import bcrypt
import os

def hash_password(plain_password):
    #converts the string to bytes
    passwordBytes = plain_password.encode("utf-8")
    #generates a random salt with bcrypt
    salt = bcrypt.gensalt()
    #hashes the password with salt
    hashed_password = bcrypt.hashpw(passwordBytes, salt)
    #returns the hashed password
    return hashed_password


#defining function to verify a password matched with stored bcrypt hash
def verify_password(plain_password, hashed_password,):
    passwordBytes = plain_password.encode("utf-8")
    hashed_password_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(passwordBytes, hashed_password_bytes)


#defining the function to register the user
def register_user(username, password):
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False

#calling function hash_password
    hashed_password = hash_password(password).decode("utf-8")

#oppening file users.txt to append the users details
    with open("users.txt", "a") as f:
        f.write(f'{username},{hashed_password}\n')
    print(f"User '{username}' registered.")


#defining function to login user if it already exists
def login_user(username, password):
    #checking if the user is not registered
    if not os.path.exists("users.txt"):
        print("Error: No users registered yet.")
        return False

#read the stored data for users credentials
    with open("users.txt", "r") as f:
        for line in f.readlines():
            #removing blank spaces between stored username and hashed password then separating with " , "
             stored_username, hashed_password = line.strip().split(',', 1)
             if stored_username == username:
                  if verify_password(password, hashed_password):
                      return True
                  else:
                      print("wrong password. try again.")
                      return False
    print("username not found")
    return False

#defining function to tell the user that a username already exists
def user_exists(username):
    if not os.path.exists("users.txt"):
        return False

    with open("users.txt", "r") as f:
        for line in f:
            stored_username, _ = line.strip().split(",",1)
            if stored_username == username:
                return True
    return False

#function for checking if the username entered meets the parameters
def validate_username(username):

    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."
    if not username.isalnum():
        return False, "Username must contain only letters and numbers."
    return True, ""

#function to validate the password
def validate_password(password):

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if len(password) > 50:
        return False, "Password must be shorter than 50 characters."
    if not any(c.islower() for c in password):
        return False, "Password must contain a lowercase letter."
    if not any(c.isupper() for c in password):
        return False, "Password must contain an uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, ""

#menu to be displayed to the user
def display_menu():
    print("\n" + "=" * 30)
    print(" Secure Authentication System ")
    print("=" * 30)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 30)

# loop that will run
def main():
    print("\nWelcome to authentication system ")
    #tarting a while loop
    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            print("\n--- USER REGISTRATION ---")
            #taking in a username and removing blank spaces
            username = input("Enter a username: ").strip()

            #calling function to validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            #taking in a password
            password = input("Enter a password: ").strip()

            #calling function to validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            #prompting the user to enter password again to check if both the passwords are same
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            #calling function to store user details
            register_user(username, password)

        #if users chooses 2nd option then it gets to login
        elif choice == '2':
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            #calling function to check the users.txt file for users credentials
            if login_user(username, password):
                print("\nYou are now logged in.")
                input("\nPress Enter to return to main menu...")

        #if users chooses 3rd option the while  loop breaks
        elif choice == '3':
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()