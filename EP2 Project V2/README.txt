
Bastion - Secure Mail Fortress
==============================

Bastion is a custom-built secure communication protocol designed to simulate encrypted email communication.
It includes TLS encryption, Diffie-Hellman key exchange, Fernet encryption, HMAC integrity, and user authentication with bcrypt.

IMPORTANT NOTICE:
-----------------
A GUI client was considered but removed due to complexity and stability concerns. The final solution focuses on robust, secure, and clear terminal-based interaction, which ensures consistent behavior across systems and simplifies deployment.

SYSTEM REQUIREMENTS:
--------------------
- Python 3.10 or newer
- Required Python libraries:
  - cryptography
  - bcrypt
  - tkinter (optional, used only during GUI development)
- Tested on: Ubuntu 22.04 and Kali Linux 2023.1

SETUP INSTRUCTIONS:
-------------------

1. **Server Setup** (on Ubuntu VM or host machine):
   - Place `BastionServer.py` in your working directory.
   - Run the server: `python3 BastionServerStart.py`
   - You will be prompted to register or start server
   - Register users as needed.
   - Run it again and write server to start it.
   - The server listens on port 4443 by default.

2. **Client Setup** (on any machine including Kali):
   - Place `BastionClient.py` in your working directory.
   - Run the client: `python3 BastionClient.py`
   - Enter the server's IP address (leave blank for localhost).
   - Enter your username and password to authenticate.
   - Choose from options to send or receive encrypted messages.

3. **Certificates:**
   - Ensure both `bastion_cert.pem` and `bastion_key.pem` are in the same folder as the server script.
   - These certificates are used for TLS encryption.

4. **Security Features:**
   - TLS (SSL) for encrypted transport layer.
   - Diffie-Hellman for secure session key exchange.
   - Fernet + HMAC for message confidentiality and integrity.
   - Bcrypt password hashing and brute force protection.
   - Account lockout for 30 seconds after 3 failed login attempts.

TROUBLESHOOTING:
----------------
- Make sure your firewall allows communication over port 4443.
- Double-check IP address inputs on client side.
- If using self-signed certificates, clients must have `bastion_cert.pem` to verify the server.

Enjoy Bastion — a lightweight but powerful secure communication protocol.
