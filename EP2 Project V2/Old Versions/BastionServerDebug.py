
import socket
import ssl
import threading
import logging
import bcrypt
import json
import os

LOG_FILE = "server_debug.log"
USER_DATABASE = "users.db"

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(message)s')

def load_users():
    if not os.path.exists(USER_DATABASE):
        return {}
    with open(USER_DATABASE, "r") as file:
        return json.load(file)

def save_users(users):
    with open(USER_DATABASE, "w") as file:
        json.dump(users, file, indent=4)

def authenticate_client(secure_socket):
    users = load_users()
    secure_socket.sendall("LOGIN: ".encode())
    username = secure_socket.recv(1024).decode().strip()
    password = secure_socket.recv(1024).decode().strip()
    print(f"[Server] Login attempt: {username}")

    if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
        secure_socket.sendall("Login successful.".encode())
        return username
    else:
        secure_socket.sendall("Invalid username or password.".encode())
        return None

def handle_client(secure_socket, address):
    logging.info(f"Secure connection established with {address}")
    print(f"[Server] Secure connection with {address}")

    try:
        username = authenticate_client(secure_socket)
        if not username:
            print("[Server] Authentication failed. Closing connection.")
            logging.info("Authentication failed. Connection closed.")
            secure_socket.close()
            return

        print(f"[Server] User '{username}' authenticated.")
        logging.info(f"User '{username}' authenticated.")

        while True:
            message = secure_socket.recv(1024).decode()
            if not message:
                print("[Server] Client disconnected.")
                logging.info("Client disconnected.")
                break

            print(f"[Server] Received from {username}: {message}")
            logging.info(f"Received from {username}: {message}")

            response = f"Message received (from {username})"
            secure_socket.send(response.encode())
            logging.info(f"Sent to client: {response}")

    except Exception as e:
        print(f"[Server] Error: {str(e)}")
        logging.error(f"Error: {str(e)}")

    secure_socket.close()
    logging.info(f"Secure connection closed with {address}")
    print(f"[Server] Secure connection closed with {address}")

def start_server():
    print("[Server] Starting Secure SSL Server with Debug...")
    logging.info("SSL Server with Debug started.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="bastion_cert.pem", keyfile="bastion_key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 4443))
    server_socket.listen(5)
    print("[Server] Listening on port 4443 (SSL)...")

    while True:
        client_socket, address = server_socket.accept()
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        thread = threading.Thread(target=handle_client, args=(secure_socket, address))
        thread.start()

if __name__ == "__main__":
    start_server()
