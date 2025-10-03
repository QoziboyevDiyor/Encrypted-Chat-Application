import socket
import threading
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoUtil:
    def __init__(self):
        # Kalit yaratish (soddalik uchun statik kalit)
        password = b"my_secure_password"
        salt = b"my_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher = Fernet(key)

    def encrypt(self, message):
        try:
            return self.cipher.encrypt(message.encode()).decode()
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt(self, encrypted_message):
        try:
            return self.cipher.decrypt(encrypted_message.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5000):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen()
        self.crypto = CryptoUtil()

    def handle_client(self, client_socket):
        while True:
            try:
                encrypted_message = client_socket.recv(1024).decode()
                if not encrypted_message:
                    break
                decrypted_message = self.crypto.decrypt(encrypted_message)
                if decrypted_message:
                    print(f"Client: {decrypted_message}")
                else:
                    print("Failed to decrypt message")
            except Exception as e:
                print(f"Server receive error: {e}")
                break
        client_socket.close()

    def send_messages(self, client_socket):
        while True:
            try:
                message = input("")
                if message.lower() == 'exit':
                    break
                encrypted_message = self.crypto.encrypt(message)
                if encrypted_message:
                    client_socket.send(encrypted_message.encode())
                else:
                    print("Failed to encrypt message")
            except Exception as e:
                print(f"Server send error: {e}")
                break

    def run(self):
        print("Server started on 127.0.0.1:5000...")
        try:
            client_socket, addr = self.server.accept()
            print(f"Client connected: {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
            self.send_messages(client_socket)
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.server.close()

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5000):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.crypto = CryptoUtil()

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client.recv(1024).decode()
                if not encrypted_message:
                    break
                decrypted_message = self.crypto.decrypt(encrypted_message)
                if decrypted_message:
                    print(f"Server: {decrypted_message}")
                else:
                    print("Failed to decrypt message")
            except Exception as e:
                print(f"Client receive error: {e}")
                break
        self.client.close()

    def send_messages(self):
        while True:
            try:
                message = input("")
                if message.lower() == 'exit':
                    break
                encrypted_message = self.crypto.encrypt(message)
                if encrypted_message:
                    self.client.send(encrypted_message.encode())
                else:
                    print("Failed to encrypt message")
            except Exception as e:
                print(f"Client send error: {e}")
                break

    def run(self):
        print("Connected to server!")
        try:
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.send_messages()
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            self.client.close()

if __name__ == "__main__":
    while True:
        choice = input("Run as (server/client/exit): ").lower()
        if choice == "server":
            server = ChatServer()
            server.run()
        elif choice == "client":
            client = ChatClient()
            client.run()
        elif choice == "exit":
            break
        else:
            print("Invalid choice. Please choose 'server', 'client', or 'exit'.")
