"""
Bastion - Secure Mail Fortress

This is the server side of Bastion, for secure communication. It replaces insecure plain-text messaging
It provides TLS secured connections, user authentication by using bcrypt, Diffie-Hellman key exchange, 
and encrypted messaging using Fernet plus HKDF

Author: Ryan Forster
"""
import socket
import ssl
import threading
import bcrypt
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import hashlib
import base64
import time
from datetime import datetime, timedelta


USER_DATABASE = "users.db"
MESSAGE_DATABASE = "messages.db"
FAILED_LOG_FILE = "failed_logings_log"
LOGIN_ATTEMPTS = {} # This will track failed attempts per username/IP
LOCKED_USERS = {} # Temp blocks usernames
LOCKED_USERS_FILE = "locked_users.json"
SUCCESS_LOG_FILE = "sucessfull_logins.log"

def load_messages():
    """
    This is for loading stored messages for all users from local JSON file
    Returns: dict where the keys are usernames and values are list of messages
    """
    if not os.path.exists(MESSAGE_DATABASE):
        return {}
    try:
        with open(MESSAGE_DATABASE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print("[Server] Warning: messages.db is empty or corrupted. Resetting it.")
        return {}
    
def save_messages(messages):
    """
    Saves the current message state to the local JSON file
    Args: messages (dict): Updated message database to write
    """
    with open(MESSAGE_DATABASE, "w") as file:
        json.dump(messages, file, indent=2)

def derive_keys(shared_key):
    """
    It derives a Fernet-compatible encryption key from a shared DH secret
    Also derives for HMAC as well
    
    Args: shared_key : The raw shared key from DH key exchange
    
    Returns: 32-byte base64-encoded key that is suitable for Fernet and HMAC
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'bastion-session',
        backend=default_backend()
    ).derive(shared_key)

    fernet_key = base64.urlsafe_b64encode(hkdf[:32])
    hmac_key = hkdf[32:]
    return fernet_key, hmac_key

def load_users():
    """
    Load the user credential from a local JSON file
    
    Returns: dict: Dictionary that maps usernames to hashed passwords
    """
    if not os.path.exists(USER_DATABASE):
        return {}
    with open(USER_DATABASE, "r") as file:
        return json.load(file)

def save_locked_users():
    """
    Saves the currently locked users and also their unlock times.
    """
    to_save = {user: unlock_time.isoformat() for user, unlock_time in LOCKED_USERS.items()}
    with open(LOCKED_USERS_FILE, "w") as file:
        json.dump(to_save,file)

def load_locked_users():
    """
    Loads locked users from disk at server start
    """
    if os.path.exists(LOCKED_USERS_FILE):
        try:
            with open(LOCKED_USERS_FILE, "r") as file:
                raw = json.load(file)
                for user, timestr in raw.items():
                    dt = datetime.fromisoformat(timestr)
                    if dt > datetime.now(): #Still locked
                        LOCKED_USERS[user] = dt
        except Exception as e:
            print("[Server] Warning: Failed to load locked users:", e)

def log_failed_login(username, ip, reason="FAILED"):
    """
    Logs any failed login atempt with timestamps and IP address.
    """
    with open(FAILED_LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} | {ip} | {username} | {reason}\n")

def log_sucessfull_login(username, ip):
    """
    It logs sucessfull login attempts with timestamp and IP
    """
    with open(SUCCESS_LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} | {ip} | {username} | SUCESS\n")

def authenticate_client(sock):
    """
    Authenticates connection client by using username and password
    
    Args: sock (ssl.SSLSocket): TLS wrapped client socket
    
    Returns: str or None: The username if login is sucessfull; None otherwise"""
    users = load_users()
    sock.sendall("LOGIN: ".encode())
    username = sock.recv(1024).decode().strip()
    password = sock.recv(1024).decode().strip()
    client_ip = sock.getpeername()[0]

    # Checks if user is blocked
    if username in LOCKED_USERS and datetime.now() < LOCKED_USERS[username]:
        sock.sendall("Too many failed attempts. Try again later.".encode())
        log_failed_login(username, client_ip, reason="LOCKED")
        return None
    # Checks for the credentials
    if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
        log_sucessfull_login(username, client_ip)
        LOGIN_ATTEMPTS[username] = 0 # Reset attempts on sucess
        sock.sendall("Login successful.".encode())
        return username
    else:
        log_failed_login(username, client_ip)
        # Count failed attempts
        LOGIN_ATTEMPTS[username] = LOGIN_ATTEMPTS.get(username, 0) + 1

        # Lock account after 3 failures for 30 seconds
        if LOGIN_ATTEMPTS[username] >= 3:
            LOCKED_USERS[username] = datetime.now() + timedelta(seconds=30)
            save_locked_users()
            sock.sendall("Too many failed attempts. User locked for 30 seconds.".encode())
        else:
            sock.sendall("Invalid username or password.".encode())
            time.sleep(2) # A small delay to slow down brute forcing
            return None 

def perform_dh_key_exchange(sock):
    """
    Does a secure DH key exchange and derives a Fernet cipher
    
    Args: sock (sslSSLSocket): TLS connection to the client
    
    Returns: Cipher object for secure messaging (fernet)
    """
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    param_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    sock.sendall(len(param_bytes).to_bytes(4, 'big'))
    sock.sendall(param_bytes)

    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()
    server_public_bytes = server_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.sendall(len(server_public_bytes).to_bytes(4, 'big'))
    sock.sendall(server_public_bytes)

    client_public_length = int.from_bytes(sock.recv(4), 'big')
    client_public_bytes = sock.recv(client_public_length)
    client_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())

    shared_key = server_private_key.exchange(client_public_key)
    fernet_key, hmac_key = derive_keys(shared_key)
    return Fernet(fernet_key), hmac_key

def verify_hmac(message, received_hmac, key):
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(received_hmac, expected)

def handle_client(secure_sock, addr):
    """
    It manages one client session: authenticates, establishes session key, handles encrypted messages
    
    Args: secure_sock (ssl.SSLSocket): Secure client socket
          addr (tuple): IP and Port of client
    """
    try:
        print("[Server] Connection from", addr)
        user = authenticate_client(secure_sock)
        if not user:
            secure_sock.close()
            return

        cipher, hmac_key = perform_dh_key_exchange(secure_sock)
        print("[Server] Secure session established with", user)

        messages = load_messages() # This loads inbox database at the start of session

        while True:
            encrypted_msg = secure_sock.recv(4096)
            if not encrypted_msg:
                break
            try:
                received_hmac = encrypted_msg[:32] # First 32 bytes = HMAC digest
                actual_encrypted = encrypted_msg[32:]

                if not verify_hmac(actual_encrypted, received_hmac, hmac_key):
                    print("[Warning] HMAC Check failed - possibly tampering going on.")
                    break
                msg = cipher.decrypt(actual_encrypted).decode()

                if msg.startswith("SENDTO:"):
                    try:
                        parts = msg.split(":", 2)
                        recipient = parts[1].strip()
                        message = parts[2].strip()

                        if recipient not in messages:
                            messages[recipient] = []
                        messages[recipient].append(f"From {user}: {message}")
                        save_messages(messages)
                        response = "Message sent to " + recipient
                    except Exception:
                        response = "Invalid SENDTO format. Use SENDTO:username:message"

                elif msg == "INBOX":
                    inbox = messages.get(user, [])
                    if inbox:
                        response = "\n".join(inbox)
                        messages[user] = [] # Clear the inbox after viewing
                        save_messages(messages)
                    else:
                        response = "Inbox is empty."
                else:
                    response = "Message received securely."

                secure_sock.send(cipher.encrypt(response.encode()))

            except Exception as e:
                print("[Error decrypting message]", e)
                break

    except Exception as e:
        print("[Server error]", e)
    finally:
        secure_sock.close()

def start_server():
    """
    Starts the Bastion Server, it listens for TLS connections and makes a thread per client
    
    It uses certificate-based TLS for transport security
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="bastion_cert.pem", keyfile="bastion_key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 4443))
    server_socket.listen(5)
    print("[Server] Listening on port 4443...")

    load_locked_users()
    print(f"[Server] Loaded locked users: {list(LOCKED_USERS.keys())}")

    while True:
        client_sock, addr = server_socket.accept()
        try:
            secure_sock = context.wrap_socket(client_sock, server_side=True)
            threading.Thread(target=handle_client, args=(secure_sock, addr)).start()
        except ssl.SSLError as e:
            print(f"[Server] TLS handshake failed from {addr}: {e}")
            client_sock.close() # Close unwrapped socket

if __name__ == "__main__":
    start_server()
