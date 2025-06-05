import socket
import ssl
import threading
import logging
from cryptography.fernet import Fernet

#  Configuration
PRE_SHARED_KEY = b'2zEOPsWXVWGDo8tCiz2_Dmlw1G-Qht2q5ISYja3X8X8='
LOG_FILE = "bastion_server.log"

#  Setup Logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

#  Function to Handle Each Client
def handle_client(secure_socket, address):
    try:
        logging.info(f"Connection established with {address}")
        print(f"[Bastion] Connection established with {address}")

        # Using the pre-shared symmetric key
        cipher = Fernet(PRE_SHARED_KEY)

        # Receiving and decrypting the encrypted message
        encrypted_message = secure_socket.recv(4096)
        logging.info(f"Encrypted Message from {address}: {encrypted_message}")
        print("[Bastion] Received Encrypted Message:", encrypted_message)

        decrypted_message = cipher.decrypt(encrypted_message)
        logging.info(f"Decrypted Message from {address}: {decrypted_message.decode()}")
        print("[Bastion] Decrypted Message:", decrypted_message.decode())

        # Sending a response to the client (acknowledgment)
        response = f"Message received: {decrypted_message.decode()}"
        secure_socket.sendall(response.encode())

    except Exception as e:
        logging.error(f"Error with {address}: {str(e)}")
        print(f"[Bastion] Error with {address}: {str(e)}")
    finally:
        secure_socket.close()
        logging.info(f"Connection closed with {address}")
        print(f"[Bastion] Connection closed with {address}")

#  Function to Start the Server
def start_bastion_server():
    """
    Starts the Bastion Server using SSL/TLS encryption.
    Listens for multiple client connections, receives and logs encrypted messages, and responds.
    """
    print("[Bastion] Attempting to start the secure server...")

    try:
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
        logging.info("Bastion Secure Server Started...")

        while True:
            print("[Bastion] Waiting for incoming connections...")
            client_socket, address = server_socket.accept()
            print(f"[Bastion] Incoming connection from {address}")
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            thread = threading.Thread(target=handle_client, args=(secure_socket, address))
            thread.start()

    except Exception as e:
        print(f"[Bastion] Error starting server: {str(e)}")
        logging.error(f"Error starting server: {str(e)}")
    except KeyboardInterrupt:
        print("\n[Bastion] Server shutdown.")
        logging.info("Server shut down manually.")

#  Run the Server
if __name__ == '__main__':
    start_bastion_server()
