import socket
import json
import base64
import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

class FileClient:
    def __init__(self, dns_host="127.0.0.1", dns_port=None):
        self.dns_host = dns_host
        self.dns_port = dns_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.aes_key = get_random_bytes(32)
        self.server_addr = None

    def detectar_dns(self):
        """Consulta al DNS cuál puerto está activo si no se proporcionó"""
        if self.dns_port is not None:
            return self.dns_port

        # Intenta puertos comunes altos
        for puerto in range(15050, 15060):
            try:
                self.sock.sendto(b'PING', (self.dns_host, puerto))
                self.sock.settimeout(0.2)
                data, _ = self.sock.recvfrom(1024)
                if data:
                    self.dns_port = puerto
                    print(f"[CLIENTE] DNS detectado en puerto {self.dns_port}")
                    return puerto
            except Exception:
                continue
        raise RuntimeError("No se pudo detectar un DNS activo en los puertos probados.")

    def handshake(self):
        syn_msg = json.dumps({'type': 'SYN'})
        self.sock.sendto(syn_msg.encode(), self.server_addr)
        data, _ = self.sock.recvfrom(4096)
        syn_ack = json.loads(data.decode())
        server_pub = RSA.import_key(syn_ack['public_key'])
        cipher_rsa = PKCS1_OAEP.new(server_pub)
        aes_encrypted = cipher_rsa.encrypt(self.aes_key)
        ack = json.dumps({'type': 'ACK', 'aes_key': base64.b64encode(aes_encrypted).decode()})
        self.sock.sendto(ack.encode(), self.server_addr)

    def descifrar_bytes(self, mensaje_cifrado_b64):
        mensaje = base64.b64decode(mensaje_cifrado_b64)
        iv = mensaje[:16]
        ciphertext = mensaje[16:-32]
        hmac_recibido = mensaje[-32:]
        hmac = HMAC.new(self.aes_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        hmac.verify(hmac_recibido)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    def consultar_dns(self, filename):
        self.detectar_dns()
        query = json.dumps({"type": "QUERY_FILE", "file": filename})
        self.sock.sendto(query.encode(), (self.dns_host, self.dns_port))
        data, _ = self.sock.recvfrom(4096)
        return json.loads(data.decode())

    def pedir_archivo(self, filename):
        req = json.dumps({'type': 'REQ_FILE', 'file': filename})
        self.sock.sendto(req.encode(), self.server_addr)
        buffer_archivo = b""
        archivo_actual = None
        while True:
            data, _ = self.sock.recvfrom(8192)
            paquete = json.loads(data.decode())
            if paquete.get('type') == 'FILE_DATA':
                chunk = self.descifrar_bytes(paquete['data'])
                buffer_archivo += chunk
                archivo_actual = paquete['file']
            elif paquete.get('type') == 'FILE_EOF':
                ruta = archivo_actual
                with open(ruta, "wb") as f:
                    f.write(buffer_archivo)
                print(f"[CLIENTE] Archivo {archivo_actual} recibido y guardado.")
                break
            elif paquete.get('type') == 'ERROR':
                print("[CLIENTE]", paquete.get('message'))
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cliente para sistema de archivos distribuido")
    parser.add_argument("--file", required=True, help="Archivo a solicitar")
    parser.add_argument("--dns_host", default="127.0.0.1", help="Host del DNS")
    parser.add_argument("--dns_port", type=int, default=None, help="Puerto del DNS (si no se pasa, se detecta automáticamente)")
    args = parser.parse_args()

    client = FileClient(dns_host=args.dns_host, dns_port=args.dns_port)
    response = client.consultar_dns(args.file)

    if response.get("type") == "RESPONSE_FILE":
        client.server_addr = tuple(response["servers"][0])
        client.handshake()
        client.pedir_archivo(args.file)
    else:
        print(f"[DNS] {response.get('message')}")
