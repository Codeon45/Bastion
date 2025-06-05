import socket # This is a python library, this will enable me to createa a network connection. I use it to create the server that can receive message
import ssl # SSL is Secure Sockets Layer, this will be the encryption for the network connection.
from cryptography.fernet import Fernet # I've installed this librabry, which I will be using to implement AES (Advanced Encryption Standard). Fernet uses symmetric key. 

# Client-side of the Protocol
def bastion_client(message: str):
    """
    This is a secure client for Bastion that connects to the Bastion Server, encrypts the message,
    and sends it securely by using SSL/TLS
    
    Args:
        message (str): The plain text to be sent securely.
    """

    # Generate the same symmetric key as the server for example
    key = b'2zEOPsWXVWGDo8tCiz2_Dmlw1G-Qht2q5ISYja3X8X8='  # Same key in both client and server
    cipher = Fernet(key) # we make a cypher object with the key, which will be used for encryption before sending and decrypt if we receive one

    # Encrypt the message with the key
    encrypted_message = cipher.encrypt(message.encode()) # Converts text to bytes, because encryption works on bytes and not text, then its encrypted with the symmetric key (Fernet)
    print("[Bastion Client] Encrypted message:", encrypted_message)

    # Secure SSL/TLS Configuration (Forcing TLS 1.2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # Setting up secure client socket with SSL/TLS
    context = ssl.create_default_context() # Wrap the connection in SSL
    with socket.create_connection(('localhost', 4443)) as client_socket: # Makes the network connection, on localhost and port 4443 which we used in the server config
        with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket: # We grab the normal connection and make it secure and we specifiy the server is in our own computer (localhost)
            print("[Bastion Client] Secure connection made with server.")
            # Send encrypted message
            secure_socket.sendall(encrypted_message) # The encrypted message is safely sent. 
            print("[Bastion Client] Encrypted message sent sucessfully.")

# How to use
if __name__ == '__main__':
    message = input ("Enter your message here: ")
    bastion_client(message)