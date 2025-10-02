import os
import socket
import threading
import json
import time
import base64
import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad

class FileServerSecure:
    def __init__(self, folder_path, host="127.0.0.1", port=5000):
        self.folder_path = os.path.abspath(folder_path)
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.file_resources = [f for f in os.listdir(self.folder_path) if os.path.isfile(os.path.join(self.folder_path, f))]
        self.clientes = {}
        self.ejecutando = True

    def start(self):
        threading.Thread(target=self.escuchar_handshake, daemon=True).start()
        print(f"[Server] Servidor escuchando en {self.host}:{self.port}")
        while True:
            time.sleep(1)

    def escuchar_handshake(self):
        while self.ejecutando:
            try:
                data, addr = self.sock.recvfrom(4096)
                mensaje = json.loads(data.decode())
                if mensaje.get('type') == 'SYN':
                    respuesta = {'type': 'SYN-ACK', 'public_key': self.public_key.export_key().decode()}
                    self.sock.sendto(json.dumps(respuesta).encode(), addr)
                elif mensaje.get('type') == 'ACK':
                    aes_key_cifrada = base64.b64decode(mensaje['aes_key'])
                    cipher_rsa = PKCS1_OAEP.new(self.key)
                    aes_key = cipher_rsa.decrypt(aes_key_cifrada)
                    self.clientes[addr] = {'aes_key': aes_key, 'nonce_counter': 0}
            except Exception:
                continue

    def cifrar_mensaje(self, plaintext, addr):
        if addr not in self.clientes:
            return plaintext.encode()
        aes_key = self.clientes[addr]['aes_key']
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        hmac = HMAC.new(aes_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        mensaje_cifrado = iv + ciphertext + hmac.digest()
        return base64.b64encode(mensaje_cifrado)

    def enviar_archivo(self, archivo, cliente_addr):
        path = os.path.join(self.folder_path, archivo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024), b""):
                mensaje_cifrado = self.cifrar_mensaje(chunk.decode('latin1'), cliente_addr)
                paquete = json.dumps({'type': 'FILE_DATA', 'data': mensaje_cifrado.decode(), 'file': archivo})
                self.sock.sendto(paquete.encode(), cliente_addr)
                time.sleep(0.01)
        eof_cifrado = self.cifrar_mensaje(f"EOF:{archivo}", cliente_addr)
        paquete = json.dumps({'type': 'FILE_EOF', 'data': eof_cifrado.decode(), 'file': archivo})
        self.sock.sendto(paquete.encode(), cliente_addr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor de archivos seguro")
    parser.add_argument("--folder", required=True, help="Carpeta de archivos")
    parser.add_argument("--host", default="127.0.0.1", help="IP del servidor")
    parser.add_argument("--port", type=int, default=5000, help="Puerto del servidor")
    args = parser.parse_args()

    server = FileServerSecure(args.folder, host=args.host, port=args.port)
    server.start()
