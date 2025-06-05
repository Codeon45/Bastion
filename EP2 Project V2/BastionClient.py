"""
Bastion - Secure Mail Fortress

This module implements the client-side part for Bastion, a safe and secure communication system,
designed to replace insecure plain-text messaging protocols.

Bastion Features:
- TLS wrapped around the connection
- Bcrypt for hashing, user authentication
- Diffie-Hellman key exchange
- Fernet with HKDF-derived session keys

Author: Ryan Forster"""

import socket
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import hashlib
import base64
import getpass

def derive_keys(shared_key):
    """
    Derives a Fernet-compatible key by using HKDF from the shared DH secret
    It also does it for HMAC. 
    
    Args: shared_key : The result of DH key exchange
    
    Returns: a base64-encoded 32-byte Fernet key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64, # 32 bits for Fernet and 32 for HMAC
        salt=None,
        info=b'bastion-session',
        backend=default_backend()
    ).derive(shared_key)
    return base64.urlsafe_b64encode(hkdf[:32]), hkdf[32:]

def receive_block(sock):
    """
    Receives a block of data where the first 4 bytes define the length
    
    Args: sock (socket.socket): The socket to read from
    
    Returns: The received data block
    """
    length = int.from_bytes(sock.recv(4), 'big')
    return sock.recv(length)

def perform_dh_key_exchange(sock):
    """
    Performs DH key exchange, returns Fernet cipher and HMAC key.
    """
    param_bytes = receive_block(sock)
    parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    server_public_bytes = receive_block(sock)
    server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())

    client_public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.sendall(len(client_public_bytes).to_bytes(4, 'big'))
    sock.sendall(client_public_bytes)

    shared_key = private_key.exchange(server_public_key)
    fernet_key, hmac_key = derive_keys(shared_key)
    return Fernet(fernet_key), hmac_key

def attach_hmac(message_bytes, key):
    """
    This creates an HMAC of the message and prepends it to the encrypted message
    """
    mac = hmac.new(key, message_bytes, hashlib.sha256).digest()
    return mac + message_bytes

def bastion_client():
    """
    Connects to the Bastion Server, it logs in safely, does the key exchange and,
    allows the user to send encrypted messages over a secured channel.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    server_ip = input("Enter the IP address of the Bastion server (leave empty for localhost): ").strip()
    if not server_ip:
        server_ip = "localhost"

    try:
        with socket.create_connection((server_ip, 4443)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as secure_sock:
                print("[Client] Connected securely to server.")
                response = secure_sock.recv(1024).decode()
                print("[Client]", response)
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ").strip()
                secure_sock.sendall(username.encode())
                secure_sock.sendall(password.encode())

                login_status = secure_sock.recv(1024).decode()
                print("[Client]", login_status)
                if "successful" not in login_status:
                    return

                cipher, hmac_key = perform_dh_key_exchange(secure_sock)
                print("[Client] Secure session established.")

                while True:
                    print("\n[Client] Menu:")
                    print("1. Send a message")
                    print("2. View inbox")
                    print("3. Quit")
                    choice = input("Choose an option (1, 2, or 3): ").strip()

                    if choice == "1":
                        recipient = input("Enter recipient username: ").strip()
                        message = input("Enter your message: ").strip()
                        if recipient and message:
                            full_msg = f"SENDTO:{recipient}:{message}"
                            encrypted = cipher.encrypt(full_msg.encode())
                            secure_sock.sendall(attach_hmac(encrypted, hmac_key))
                            response = secure_sock.recv(4096)
                            print("[Client]", cipher.decrypt(response).decode())
                        else:
                            print("[Client] Recipient and message cannot be empty.")
                    elif choice == "2":
                        encrypted = cipher.encrypt("INBOX".encode())
                        secure_sock.sendall(attach_hmac(encrypted, hmac_key))
                        response = secure_sock.recv(4096)
                        inbox = cipher.decrypt(response).decode()
                        print("\n[Client] Inbox:\n" + inbox)
                    elif choice == "3":
                        print("[Client] Exiting secure session.")
                        break
                    else:
                        print("[Client] Invalid choice. Try 1, 2, or 3.")
    except Exception as e:
        print(f"[Client] Connection failed: {e}")

if __name__ == "__main__":
    bastion_client()
