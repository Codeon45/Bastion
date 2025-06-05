
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
import base64

USER_DATABASE = "users.db"

def derive_fernet_key(shared_key):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'bastion-session',
        backend=default_backend()
    ).derive(shared_key)
    return base64.urlsafe_b64encode(derived_key)

def load_users():
    if not os.path.exists(USER_DATABASE):
        return {}
    with open(USER_DATABASE, "r") as file:
        return json.load(file)

def authenticate_client(sock):
    users = load_users()
    sock.sendall("LOGIN: ".encode())
    username = sock.recv(1024).decode().strip()
    password = sock.recv(1024).decode().strip()

    if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
        sock.sendall("Login successful.".encode())
        return username
    else:
        sock.sendall("Invalid username or password.".encode())
        return None

def perform_dh_key_exchange(sock):
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
    fernet_key = derive_fernet_key(shared_key)
    return Fernet(fernet_key)

def handle_client(secure_sock, addr):
    try:
        print("[Server] Connection from", addr)
        user = authenticate_client(secure_sock)
        if not user:
            secure_sock.close()
            return

        cipher = perform_dh_key_exchange(secure_sock)
        print("[Server] Secure session established with", user)

        while True:
            encrypted_msg = secure_sock.recv(4096)
            if not encrypted_msg:
                break
            try:
                msg = cipher.decrypt(encrypted_msg).decode()
                print(f"[{user}] {msg}")
                response = cipher.encrypt("Message received securely.".encode())
                secure_sock.send(response)
            except Exception as e:
                print("[Error decrypting message]", e)
                break

    except Exception as e:
        print("[Server error]", e)
    finally:
        secure_sock.close()

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="bastion_cert.pem", keyfile="bastion_key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 4443))
    server_socket.listen(5)
    print("[Server] Listening on port 4443...")

    while True:
        client_sock, addr = server_socket.accept()
        secure_sock = context.wrap_socket(client_sock, server_side=True)
        threading.Thread(target=handle_client, args=(secure_sock, addr)).start()

if __name__ == "__main__":
    start_server()
