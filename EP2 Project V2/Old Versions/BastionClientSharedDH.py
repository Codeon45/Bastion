
import socket
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

def derive_fernet_key(shared_key):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'bastion-session',
        backend=default_backend()
    ).derive(shared_key)
    return base64.urlsafe_b64encode(derived_key)

def receive_block(sock):
    length = int.from_bytes(sock.recv(4), 'big')
    return sock.recv(length)

def perform_dh_key_exchange(sock):
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
    fernet_key = derive_fernet_key(shared_key)
    return Fernet(fernet_key)

def bastion_client():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection(('localhost', 4443)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as secure_sock:
            print("[Client] Connected securely to server.")

            response = secure_sock.recv(1024).decode()
            print("[Client]", response)
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            secure_sock.sendall(username.encode())
            secure_sock.sendall(password.encode())

            login_status = secure_sock.recv(1024).decode()
            print("[Client]", login_status)
            if "successful" not in login_status:
                return

            cipher = perform_dh_key_exchange(secure_sock)
            print("[Client] Secure session established.")

            while True:
                msg = input("Message ('quit' to exit): ").strip()
                if msg.lower() == 'quit':
                    break
                encrypted = cipher.encrypt(msg.encode())
                secure_sock.sendall(encrypted)
                response = secure_sock.recv(4096)
                print("[Client] Server:", cipher.decrypt(response).decode())

if __name__ == "__main__":
    bastion_client()
