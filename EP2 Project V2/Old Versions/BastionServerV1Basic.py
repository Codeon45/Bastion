import socket
import ssl
from cryptography.fernet import Fernet

# Pre-shared symmetric key (must be the same on client and server)
PRE_SHARED_KEY = b'2zEOPsWXVWGDo8tCiz2_Dmlw1G-Qht2q5ISYja3X8X8='

def start_bastion_server():
    """
    Starts the Bastion Server using SSL/TLS encryption.
    Listens for client connections, receives an encrypted message, and decrypts it.
    """
    cipher = Fernet(PRE_SHARED_KEY)
    print("[Bastion] Encryption key is set.")

    # Setting up a secure server socket using SSL/TLS (using the new certificate)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="bastion_cert.pem", keyfile="bastion_key.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # Creating and starting the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 4443))
    server_socket.listen(5)
    print("[Bastion] Secure Server is Running... Listening on port 4443.")

    while True:
        client_socket, address = server_socket.accept()
        print(f"[Bastion] Connection established with {address}")
        
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        print("[Bastion] Secure connection established using SSL/TLS.")
        
        encrypted_message = secure_socket.recv(4096)
        print("[Bastion] Received Encrypted Message:", encrypted_message)

        decrypted_message = cipher.decrypt(encrypted_message)
        print("[Bastion] Decrypted Message:", decrypted_message.decode())

        secure_socket.close()
        print("[Bastion] Connection closed.")

# ✅ Run the Server
if __name__ == '__main__':
    start_bastion_server()
