import socket
import ssl
from cryptography.fernet import Fernet

# Pre-shared symmetric key (must be the same on client and server)
PRE_SHARED_KEY = b'2zEOPsWXVWGDo8tCiz2_Dmlw1G-Qht2q5ISYja3X8X8='

# Client-side of Bastion Protocol
def bastion_client(message: str):
    """
    A secure client for Bastion Protocol that connects to the Bastion server, encrypts a message,
    and sends it securely using SSL/TLS.
    """
    cipher = Fernet(PRE_SHARED_KEY)
    print("[Bastion] Encryption key is set.")

    # Encrypt the message using the symmetric key
    encrypted_message = cipher.encrypt(message.encode())
    print("[Bastion Client] Encrypted Message:", encrypted_message)

    # Setting up a secure client socket with SSL/TLS (forcing TLS 1.2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")  # The same certificate as the server
    context.check_hostname = True  # Verify hostname (localhost)
    context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

    with socket.create_connection(('localhost', 4443)) as client_socket:
        with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
            print("[Bastion Client] Secure connection established with server.")
            # Sending the encrypted message
            secure_socket.sendall(encrypted_message)
            print("[Bastion Client] Encrypted message sent successfully.")

if __name__ == '__main__':
    message = input("Enter the message you want to send securely: ")
    bastion_client(message)
