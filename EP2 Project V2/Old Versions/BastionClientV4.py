import socket
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Client-side of Bastion Protocol
def bastion_client():
    """
    A secure client for Bastion Protocol that connects to the Bastion server, securely logs in,
    and sends encrypted messages using a dynamic session key (Diffie-Hellman).
    """
    print("\n[Bastion Client] Welcome to the Bastion Protocol")

    # Setting up a secure client socket with SSL/TLS (forcing TLS 1.2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")  # The same certificate as the server
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(('localhost', 4443)) as client_socket:
            with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
                print("[Bastion Client] Secure connection established with server.")

                # User Authentication (Server-Side)
                while True:
                    print("\n1. Register")
                    print("2. Login")
                    print("3. Quit")
                    choice = input("Choose an option (1, 2, or 3): ").strip()

                    secure_socket.sendall(choice.encode())
                    response = secure_socket.recv(1024).decode()  # Wait for server response
                    print(f"[Bastion Client] {response}")

                    if choice == "1":
                        if "OK" in response:
                            username = input("Enter username: ").strip()
                            password = input("Enter password: ").strip()
                            secure_socket.sendall(username.encode())
                            secure_socket.sendall(password.encode())
                            response = secure_socket.recv(1024).decode()
                            print(f"[Bastion Client] {response}")
                    
                    elif choice == "2":
                        if "OK" in response:
                            username = input("Enter username: ").strip()
                            password = input("Enter password: ").strip()
                            secure_socket.sendall(username.encode())
                            secure_socket.sendall(password.encode())
                            response = secure_socket.recv(1024).decode()
                            print(f"[Bastion Client] {response}")

                            if "Login successful" in response:
                                print(f"[Bastion Client] Welcome, {username}.")
                                secure_communication(secure_socket, username)
                        else:
                            print("[Bastion Client] Login failed.")

                    elif choice == "3":
                        print("[Bastion Client] Exiting...")
                        break
                    else:
                        print("[Bastion Client] Invalid option. Please choose 1, 2, or 3.")
    
    except ssl.SSLCertVerificationError:
        print("[Bastion Client] SSL Certificate verification failed. Is the server certificate correct?")
    except ConnectionRefusedError:
        print("[Bastion Client] Unable to connect to the server. Is the server running?")
    except Exception as e:
        print(f"[Bastion Client] Error: {str(e)}")

# Secure Communication After Login
def secure_communication(secure_socket, username):
    """
    Manages secure communication with the server using a dynamically generated session key (DHE).
    """
    print("\n[Bastion Client] Establishing a secure session...")

    # Diffie-Hellman Key Exchange (DHE)
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()

    # Send Client Public Key to Server
    secure_socket.sendall(client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    # Receive Server Public Key
    server_public_bytes = secure_socket.recv(4096)
    server_public_key = dh.DHPublicKey.from_encoded_point(parameters, server_public_bytes)

    # Generate a shared session key
    shared_key = client_private_key.exchange(server_public_key)
    session_key = Fernet.generate_key()
    cipher = Fernet(session_key)
    print("[Bastion Client] Secure session established using DHE.")

    while True:
        print("\n[Bastion Client] Menu:")
        print("1. Send a message")
        print("2. View Inbox")
        print("3. Logout")

        choice = input("Choose an option (1, 2, or 3): ").strip()

        if choice == "1":
            message = input("Enter your message: ").strip()
            if message:
                # Encrypting the message with the session key
                encrypted_message = cipher.encrypt(message.encode())
                secure_socket.sendall(encrypted_message)
                print("[Bastion Client] Encrypted message sent.")

                # Receiving the server's response
                response = secure_socket.recv(4096).decode()
                print("[Bastion Client] Server Response:", response)

        elif choice == "2":
            # Requesting the inbox from the server
            secure_socket.sendall("INBOX".encode())
            inbox = secure_socket.recv(4096).decode()
            print(f"\n[Bastion Client] Inbox for {username}:\n{inbox}")

        elif choice == "3":
            print("[Bastion Client] Logging out...")
            break
        else:
            print("[Bastion Client] Invalid option. Please choose 1, 2, or 3.")
