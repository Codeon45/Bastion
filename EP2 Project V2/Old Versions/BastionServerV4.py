import socket
import ssl
import threading
import logging

logging.basicConfig(filename="server_debug.log", level=logging.DEBUG, format='%(asctime)s - %(message)s')

def handle_client(secure_socket, address):
    logging.info(f"Secure connection established with {address}")
    print(f"[Server] Secure connection with {address}")

    try:
        while True:
            message = secure_socket.recv(1024).decode()
            if not message:
                break
            print(f"[Server] Received: {message}")
            logging.info(f"Received from client: {message}")

            # Echoing the message back
            response = f"Server received (SSL): {message}"
            secure_socket.send(response.encode())
            logging.info(f"Sent to client: {response}")

    except Exception as e:
        print(f"[Server] Error: {str(e)}")
        logging.error(f"Error: {str(e)}")

    secure_socket.close()
    logging.info(f"Secure connection closed with {address}")
    print(f"[Server] Secure connection closed with {address}")

def start_server():
    print("[Server] Starting Secure SSL Server...")
    logging.info("SSL Server started.")

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
