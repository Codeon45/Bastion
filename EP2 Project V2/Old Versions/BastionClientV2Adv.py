import socket
import ssl
from cryptography.fernet import Fernet

#  Pre-shared symmetric key (must be the same on client and server)
PRE_SHARED_KEY = b'2zEOPsWXVWGDo8tCiz2_Dmlw1G-Qht2q5ISYja3X8X8='

#  Client-side of Bastion Protocol
def bastion_client():
    """
    A secure client for Bastion Protocol that connects to the Bastion server, encrypts a message,
    and sends it securely using SSL/TLS. The client can send multiple messages and receive responses.
    """
    # Setting up the encryption
    cipher = Fernet(PRE_SHARED_KEY)
    print("[Bastion] Encryption key is set.")

    # Setting up a secure client socket with SSL/TLS (forcing TLS 1.2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("bastion_cert.pem")  # The same certificate as the server
    context.check_hostname = True  #  Verify hostname (localhost)
    context.verify_mode = ssl.CERT_REQUIRED  #  Require certificate verification

    # Connecting to the server
    try:
        with socket.create_connection(('localhost', 4443)) as client_socket:
            with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
                print("[Bastion Client] Secure connection established with server.")

                while True:
                    print("\n[Bastion Client] Menu:")
                    print("1. Send a message")
                    print("2. Quit")

                    choice = input("Choose an option (1 or 2): ").strip()
                    
                    if choice == "1":
                        message = input("Enter your message: ").strip()
                        if message:
                            # Encrypting the message
                            encrypted_message = cipher.encrypt(message.encode())
                            print("[Bastion Client] Encrypted Message:", encrypted_message)

                            # Sending the encrypted message
                            secure_socket.sendall(encrypted_message)
                            print("[Bastion Client] Encrypted message sent successfully.")

                            # Receiving the server's response
                            response = secure_socket.recv(4096).decode()
                            print("[Bastion Client] Server Response:", response)
                        else:
                            print("[Bastion Client] Message cannot be empty.")
                    elif choice == "2":
                        print("[Bastion Client] Closing connection...")
                        break
                    else:
                        print("[Bastion Client] Invalid option. Please choose 1 or 2.")
    
    except ssl.SSLCertVerificationError:
        print("[Bastion Client] SSL Certificate verification failed. Is the server certificate correct?")
    except ConnectionRefusedError:
        print("[Bastion Client] Unable to connect to the server. Is the server running?")
    except Exception as e:
        print(f"[Bastion Client] Error: {str(e)}")

#  Run the Client
if __name__ == '__main__':
    bastion_client()
