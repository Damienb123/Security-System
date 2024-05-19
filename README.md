# Security-System

## Table of Contents

1. [Table of Contents](#Table-of-Contents)
2. [Overview](#Overview)
3. [Main Features](#Main-features)
4. [Setup Instructions](#Setup-Instructions)
5. [Usage](#Usage)
6. [Purpose and functionality](#Purpose-and-Functionality)
    - Imports
    - Class Definition
    - Add User Method
    - Authenticate Method
    - Logging Setup
7. [Example Usage](#Example-Usage)
8. [Example Ouput](#Example-Output) 
9. [Logging](#Logging)
10. [Conclusion](#Conclusion)

## Overview

This Security System is designed to manage user authentication through username and password verification. The system uses bcrypt for hashing passwords and includes logging functionality to monitor access attempts.

## Main Features

- Password hashing using bcrypt for enhanced security.
- User authentication with password and username checks.
- Restriction on passwords containing special characters.
- Logging of successful and failed login attempts.
- Limited login attempts with a system lock after maximum attempts are reached.


## Setup Features

1. **Install bycrypt:**
```
pip install bcrypt
```
2. **Setup the logging configuration:**
Ensure that you have write permissions for the directory where the log file will be created (access.log).

## Usage

1. **Run the script:**
```
python security_system.py
```
2. **Adding users:**
- The system allows for adding users through the add_user method.
- Usernames and passwords are stored in a hashed format for security.

3. **Authenticating users:**
- Users will be prompted to enter their username and password.
- Passwords are verified against the stored hashed values.
- Special characters in passwords are not allowed for authentication.

## Purpose and Functionality

### Imports

```
import bcrypt  # Importing bcrypt for password hashing
import logging  # Importing logging module for logging access attempts
```
- **bcrypt:** Used for hashing passwords to ensure they are stored securely.
- **logging:** Used to log successful and failed login attempts.

### Class Definition

```
class SecuritySystem:
    def __init__(self):
        self.users = {}  # Dictionary to store username-password pairs
```
- **SecuritySystem:** Main class to handle user management and authentication.
- **Self.users:** Dictionary to store usernames and their corresponding hashed passwords.

### Add User Method

```
def add_user(self, username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    self.users[username] = hashed_password  # Storing the hashed password
```
- Hashes the password using bcrypt and stores the username and hashed password in the self.users dictionary.

### Authenticate Method

```
def authenticate(self, username, password):
    if username in self.users:
        hashed_password = self.users[username]
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            if not any(char in "!@#$%^&*()-_+=~`[]{}|;:'\",.<>?/" for char in password):
                print("Access granted. Welcome, {}!".format(username))
                logging.info("Successful login attempt by user: {}".format(username))
                return True
            else:
                print("Access denied. Password contains special characters.")
        else:
            print("Access denied. Incorrect password!")
    else:
        print("Access denied. Username not found!")
    logging.warning("Failed login attempt by user: {}".format(username))
    return False
```
- Verifies if the username exists.
- Checks if the provided password matches the stored hashed password.
- Ensures the password does not contain special characters.
- Logs the result of the authentication attempt.
- 
### Logging Setup

```
logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s - %(message)s')
```
Configures logging to record events in the **access.log** file with timestamps.

## Example Usage

```
if __name__ == "__main__":
    security_system = SecuritySystem()

    # Adding users
    security_system.add_user('admin', 'adminpassword')
    security_system.add_user('user1', 'password123')

    login_attempts = 0
    max_attempts = 3
    while login_attempts < max_attempts:
        username = input("Enter username: ")
        password = input("Enter password: ")
        if security_system.authenticate(username, password):
            break
        login_attempts += 1
        print("Access denied. Please try again.")
    
    if login_attempts == max_attempts:
        print("Maximum login attempts reached. System locked.")
```
- Demonstrates how to use the **SecuritySystem** class to add users and authenticate login attempts.
- Limits login attempts to three, locking the system after reaching the maximum number of attempts.

## Example Output

When the script is run, the following outputs are examples of what might be seen based on user interaction:

```
Enter username: admin
Enter password: adminpassword
Access granted. Welcome, admin!

Enter username: user1
Enter password: wrongpassword
Access denied. Incorrect password!
Access denied. Please try again.

Enter username: unknownuser
Enter password: anypassword
Access denied. Username not found!
Access denied. Please try again.

Enter username: user1
Enter password: password123!
Access denied. Password contains special characters.
Access denied. Please try again.

Enter username: user1
Enter password: password123
Access granted. Welcome, user1!
```
If the maximum number of attempts is reached:
```
Enter username: user1
Enter password: wrongpassword
Access denied. Incorrect password!
Access denied. Please try again.

Enter username: user1
Enter password: wrongpassword
Access denied. Incorrect password!
Access denied. Please try again.

Enter username: user1
Enter password: wrongpassword
Access denied. Incorrect password!
Access denied. Please try again.

Maximum login attempts reached. System locked.
```
## Logging

- **Successful Login:**
```
2024-05-18 14:30:00 - Successful login attempt by user: admin
```
- **Failed Login:**
```
2024-05-18 14:31:00 - Failed login attempt by user: admin
```

## Conclusion

This Security System provides a robust mechanism for managing user authentication, ensuring passwords are securely hashed and logging access attempts. The system is designed to be secure, user-friendly, and easy to set up and use.
