import socket
import ssl
import bcrypt
import json
from cryptography.fernet import Fernet
import os

# Pre-shared symmetric key (must be the same on client and server)
PRE_SHARED_KEY = b'2zEOPsWXVWGDo8tCiz2_Dmlw1G-Qht2q5ISYja3X8X8='
USER_DATABASE = "users.db"

# Function to Load Users
def load_users():
    if not os.path.exists(USER_DATABASE):
        return {}
    with open(USER_DATABASE, "r") as file:
        return json.load(file)

# Function to Save Users
def save_users(users):
    with open(USER_DATABASE, "w") as file:
        json.dump(users, file)

# User Registration
def register():
    print("\n[Bastion Client] User Registration")
    username = input("Enter a username: ").strip()
    password = input("Enter a password: ").strip()
    
    if not username or not password:
        print("[Bastion Client] Username and password cannot be empty.")
        return
    
    users = load_users()
    if username in users:
        print("[Bastion Client] Username already exists. Please log in.")
        return
    
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed_password
    save_users(users)
    print("[Bastion Client] Registration successful. Please log in.")

# User Login
def login():
    print("\n[Bastion Client] User Login")
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    users = load_users()
    if username in users:
        if bcrypt.checkpw(password.encode(), users[username].encode()):
            print("[Bastion Client] Login successful.")
            return username
        else:
            print("[Bastion Client] Incorrect password.")
    else:
        print("[Bastion Client] Username not found.")
    
    return None

# Secure Client (Authenticated)
def bastion_client(username):
    """
    A secure client for Bastion Protocol that connects to the Bastion server, encrypts a message,
    and sends it securely using SSL/TLS. The client can send multiple messages and receive responses.
    """
    # Setting up the encryption
    cipher = Fernet(PRE_SHARED_KEY)
    print("[Bastion] Encryption key is set.")

    # Setting up a secure client socket with SSL/TLS (forcing TLS 1.2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")  # The same certificate as the server
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # Connecting to the server
    try:
        with socket.create_connection(('localhost', 4443)) as client_socket:
            with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
                print("[Bastion Client] Secure connection established with server.")

                while True:
                    print("\n[Bastion Client] Menu:")
                    print("1. Send a message")
                    print("2. Logout")

                    choice = input("Choose an option (1 or 2): ").strip()
                    
                    if choice == "1":
                        message = input("Enter your message: ").strip()
                        if message:
                            # Encrypting the message
                            encrypted_message = cipher.encrypt(message.encode())
                            print("[Bastion Client] Encrypted Message:", encrypted_message)

                            # Sending the encrypted message
                            secure_socket.sendall(encrypted_message)
                            print("[Bastion Client] Encrypted message sent successfully.")

                            # Receiving the server's response
                            response = secure_socket.recv(4096).decode()
                            print("[Bastion Client] Server Response:", response)
                        else:
                            print("[Bastion Client] Message cannot be empty.")
                    elif choice == "2":
                        print("[Bastion Client] Logging out...")
                        break
                    else:
                        print("[Bastion Client] Invalid option. Please choose 1 or 2.")
    
    except ssl.SSLCertVerificationError:
        print("[Bastion Client] SSL Certificate verification failed. Is the server certificate correct?")
    except ConnectionRefusedError:
        print("[Bastion Client] Unable to connect to the server. Is the server running?")
    except Exception as e:
        print(f"[Bastion Client] Error: {str(e)}")

# Main Program (Login and Registration System)
if __name__ == '__main__':
    print("\n[Bastion Client] Welcome to the Bastion Protocol")
    
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Quit")
        choice = input("Choose an option (1, 2, or 3): ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            username = login()
            if username:
                bastion_client(username)
        elif choice == "3":
            print("[Bastion Client] Exiting...")
            break
        else:
            print("[Bastion Client] Invalid option. Please choose 1, 2, or 3.")
