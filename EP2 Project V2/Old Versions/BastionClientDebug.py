import socket
import ssl
import logging

logging.basicConfig(filename="client_debug.log", level=logging.DEBUG, format='%(asctime)s - %(message)s')

def bastion_client():
    print("\n[Client] Secure SSL Client with Debug")
    logging.info("Client started.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(('localhost', 4443)) as client_socket:
            with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
                print("[Client] Secure SSL connection established.")

                # Expecting "LOGIN:" from server
                response = secure_socket.recv(1024).decode()
                print(f"[Client] {response}")
                logging.info(f"Received from server: {response}")

                if "LOGIN" in response:
                    username = input("Username: ").strip()
                    password = input("Password: ").strip()
                    secure_socket.sendall(username.encode())
                    secure_socket.sendall(password.encode())

                    # Wait for success/fail
                    result = secure_socket.recv(1024).decode()
                    print(f"[Client] {result}")
                    if "successful" not in result:
                        return  # Don't continue if login failed

                while True:
                    message = input("Enter a message (or 'quit' to exit): ").strip()
                    if message.lower() == 'quit':
                        break

                    secure_socket.sendall(message.encode())
                    response = secure_socket.recv(1024).decode()
                    print(f"[Client] Server response: {response}")

    except Exception as e:
        print(f"[Client] Error: {str(e)}")
        logging.error(f"Error: {str(e)}")

if __name__ == "__main__":
    bastion_client()
