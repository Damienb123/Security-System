import bcrypt  # Importing bcrypt for password hashing
import logging  # Importing logging module for logging access attempts

class SecuritySystem:
    def __init__(self):
        self.users = {}  # Dictionary to store username-password pairs

    def add_user(self, username, password):
        # Hashing the password before storing it in the dictionary
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.users[username] = hashed_password  # Storing the hashed password

    def authenticate(self, username, password):
        if username in self.users:  # Check if the username exists in the dictionary
            hashed_password = self.users[username]  # Retrieving the hashed password
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                # Checking if the entered password matches the hashed password
                if not any(char in "!@#$%^&*()-_+=~`[]{}|;:'\",.<>?/" for char in password):
                    # Checking if the password contains special characters
                    print("Access granted. Welcome, {}!".format(username))
                    logging.info("Successful login attempt by user: {}".format(username))
                    return True  # Access granted if password is correct and doesn't contain special characters
                else:
                    print("Access denied. Password contains special characters.")
            else:
                print("Access denied. Incorrect password!")  # Access denied if password is incorrect
        else:
            print("Access denied. Username not found!")  # Access denied if username doesn't exist
        logging.warning("Failed login attempt by user: {}".format(username))
        return False  # Access denied for any other cases

# Setup logging
logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Example usage:
if __name__ == "__main__":
    security_system = SecuritySystem()

    # Adding users
    security_system.add_user('admin', 'adminpassword')
    security_system.add_user('user1', 'password123')

    login_attempts = 0  # Counter for login attempts
    max_attempts = 3  # Maximum allowed login attempts
    while login_attempts < max_attempts:
        username = input("Enter username: ")
        password = input("Enter password: ")
        if security_system.authenticate(username, password):
            break  # Exit the loop if authentication is successful
        login_attempts += 1  # Increment login attempts counter
        print("Access denied. Please try again.")
    
    if login_attempts == max_attempts:
        print("Maximum login attempts reached. System locked.")  # Lock the system after maximum attempts
