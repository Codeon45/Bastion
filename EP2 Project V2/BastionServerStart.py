"""
Bastion - Secure Mail Fortress

This is the server side of Bastion, running this code starts the server or registers a new user to the users.db file.
By writting "register" a new menu prompts where username and password need to be input. 
When done adding users, run the code again and write "server" to start the server, it will run the code from the
BastionServer.py file. 

Author: Ryan Forster
"""
import bcrypt
import json
import getpass

USER_DATABASE = "users.db"

def register_user():
    users = {}
    try:
        with open(USER_DATABASE, "r") as f:
            users = json.load(f)
    except:
        pass

    print("=== Register New User ===")
    username = input("Enter new username: ").strip()
    if username in users:
        print("Username already exists.")
        return

    while True:
        password = getpass.getpass("Enter password: ").strip()
        confirm = getpass.getpass("Confirm password: ").strip()
        if password == confirm:
            break
        print("Passwords do not match. Try again.")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed

    with open(USER_DATABASE, "w") as f:
        json.dump(users, f)
    print("User registered successfully.")

if __name__ == "__main__":
    mode = input("Start server or register user? (server/register): ").strip().lower()
    if mode == "register":
        register_user()
    else:
        from BastionServer import start_server
        start_server()
