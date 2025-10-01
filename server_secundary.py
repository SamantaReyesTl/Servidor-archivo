import os
import socket
import threading
import json
import time
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad

class ServidorNodo:
    def __init__(self, folder_path, host="127.0.0.1", port=5001, maestro_addr=("127.0.0.1", 5000)):
        self.folder_path = os.path.abspath(folder_path)
        self.host = host
        self.port = port
        self.maestro_addr = maestro_addr
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        
        # Generar claves RSA
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        
        self.clientes = {}  # addr -> {'aes_key': ..., 'nonce_counter': ...}
        self.archivos_locales = [f for f in os.listdir(self.folder_path) if f.endswith(".txt")]
        self.ejecutando = True
        
        # Clave AES para comunicación con maestro
        self.aes_key_maestro = None

    def registrar_con_maestro(self):
        """Registrar este nodo con el servidor maestro correctamente"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # 1. SYN
            syn = json.dumps({'type': 'SYN'}).encode()
            sock.sendto(syn, self.maestro_addr)

            data, _ = sock.recvfrom(4096)
            resp = json.loads(data.decode())

            if resp.get('type') == 'SYN-ACK':
                # Importar clave pública del maestro
                server_pub = RSA.import_key(resp['public_key'])

                # Generar clave AES para comunicación
                self.aes_key_maestro = get_random_bytes(32)
                cipher_rsa = PKCS1_OAEP.new(server_pub)
                aes_key_enc = cipher_rsa.encrypt(self.aes_key_maestro)

                # 2. Enviar ACK solo con la clave AES cifrada
                ack = json.dumps({
                    'type': 'ACK',
                    'aes_key': base64.b64encode(aes_key_enc).decode()
                }).encode()
                sock.sendto(ack, self.maestro_addr)

                # 3. Enviar registro de archivos como mensaje separado cifrado
                registro = json.dumps({
                    'type': 'registro_nodo',
                    'archivos': self.archivos_locales
                }).encode()

                # Cifrar con AES
                iv = get_random_bytes(16)
                cipher = AES.new(self.aes_key_maestro, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(registro, AES.block_size))
                hmac = HMAC.new(self.aes_key_maestro, digestmod=SHA256)
                hmac.update(iv + ciphertext)
                mensaje_cifrado = base64.b64encode(iv + ciphertext + hmac.digest())

                sock.sendto(mensaje_cifrado, self.maestro_addr)

                print(f"[NODO] Registrado con maestro {self.maestro_addr}")

            sock.close()

        except Exception as e:
            print(f"[ERROR] Registro con maestro fallido: {e}")


    def escuchar(self):
        """Escuchar conexiones entrantes"""
        print(f"[NODO] Escuchando en {self.host}:{self.port}")
        
        while self.ejecutando:
            try:
                data, addr = self.sock.recvfrom(4096)
                threading.Thread(target=self.procesar_mensaje, args=(data, addr), daemon=True).start()
            except OSError:
                break

    def procesar_mensaje(self, data, addr):
        """Procesar mensajes entrantes"""
        try:
            mensaje = json.loads(data.decode())
            tipo = mensaje.get('type')
            
            if tipo == 'SYN':
                self.procesar_syn(addr)
            elif tipo == 'ACK':
                self.procesar_ack(mensaje, addr)
            elif tipo == 'solicitud_archivo':
                self.procesar_solicitud_archivo(addr, mensaje.get('archivo'))
            elif tipo == 'solicitud_replicacion':
                self.procesar_solicitud_replicacion(mensaje)
                
        except Exception as e:
            print(f"[ERROR] Procesando mensaje de {addr}: {e}")

    def procesar_syn(self, addr):
        """Procesar handshake SYN"""
        respuesta = json.dumps({
            'type': 'SYN-ACK',
            'public_key': self.public_key.export_key().decode()
        }).encode()
        self.sock.sendto(respuesta, addr)

    def procesar_ack(self, mensaje, addr):
        """Procesar handshake ACK"""
        aes_key_cifrada = base64.b64decode(mensaje['aes_key'])
        cipher_rsa = PKCS1_OAEP.new(self.key)
        aes_key = cipher_rsa.decrypt(aes_key_cifrada)
        self.clientes[addr] = {'aes_key': aes_key, 'nonce_counter': 0}
        print(f"[NODO] Handshake completo con {addr}")

    def procesar_solicitud_archivo(self, addr, nombre_archivo):
        """Procesar solicitud de archivo desde un cliente"""
        if nombre_archivo not in self.archivos_locales:
            print(f"[NODO] Archivo {nombre_archivo} no encontrado localmente")
            return
        
        path = os.path.join(self.folder_path, nombre_archivo)
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                for linea_num, linea in enumerate(f):
                    linea = linea.strip()
                    if not linea:
                        continue
                    
                    paquete = json.dumps({
                        'type': 'data',
                        'seq': linea_num,
                        'archivo': nombre_archivo,
                        'data': self.cifrar_mensaje(linea, addr).decode()
                    })
                    
                    self.sock.sendto(paquete.encode(), addr)
                    time.sleep(0.01)  # Pequeña pausa para evitar congestión
            
            # Enviar EOF
            eof_paquete = json.dumps({
                'type': 'eof',
                'archivo': nombre_archivo,
                'data': self.cifrar_mensaje(f"EOF:{nombre_archivo}", addr).decode()
            })
            
            self.sock.sendto(eof_paquete.encode(), addr)
            print(f"[NODO] Archivo {nombre_archivo} enviado a {addr}")
            
        except Exception as e:
            print(f"[ERROR] Enviando archivo {nombre_archivo}: {e}")

    def procesar_solicitud_replicacion(self, mensaje):
        """Procesar solicitud de replicación desde el maestro"""
        archivo = mensaje.get('archivo')
        destino = tuple(mensaje.get('destino'))
        
        if archivo not in self.archivos_locales:
            print(f"[NODO] No se puede replicar {archivo} - no encontrado localmente")
            return
        
        print(f"[NODO] Replicando {archivo} a {destino}")
        self.replicar_archivo(archivo, destino)

    def replicar_archivo(self, archivo, destino_addr):
        """Replicar archivo a otro nodo"""
        try:
            # Handshake con nodo destino
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            syn = json.dumps({'type': 'SYN'}).encode()
            sock.sendto(syn, destino_addr)
            
            data, _ = sock.recvfrom(4096)
            resp = json.loads(data.decode())
            
            if resp.get('type') == 'SYN-ACK':
                server_pub = RSA.import_key(resp['public_key'])
                aes_key = AES.get_random_bytes(32)
                cipher_rsa = PKCS1_OAEP.new(server_pub)
                aes_key_enc = cipher_rsa.encrypt(aes_key)
                
                ack = json.dumps({
                    'type': 'ACK',
                    'aes_key': base64.b64encode(aes_key_enc).decode()
                })
                
                sock.sendto(ack.encode(), destino_addr)
                
                # Enviar archivo
                path = os.path.join(self.folder_path, archivo)
                with open(path, "r", encoding="utf-8") as f:
                    for i, linea in enumerate(f):
                        linea = linea.strip()
                        if not linea:
                            continue
                        
                        mensaje_cifrado = self.cifrar_mensaje_replicacion(linea, aes_key)
                        paquete = json.dumps({
                            'type': 'data',
                            'seq': i,
                            'archivo': archivo,
                            'data': mensaje_cifrado.decode()
                        })
                        
                        sock.sendto(paquete.encode(), destino_addr)
                        time.sleep(0.01)
                
                # EOF
                eof_msg = self.cifrar_mensaje_replicacion(f"EOF:{archivo}", aes_key)
                paquete = json.dumps({
                    'type': 'eof',
                    'archivo': archivo,
                    'data': eof_msg.decode()
                })
                
                sock.sendto(paquete.encode(), destino_addr)
                sock.close()
                
                print(f"[NODO] Réplica de {archivo} a {destino_addr} completada")
                
                # Notificar al maestro sobre el nuevo archivo
                self.notificar_nuevo_archivo(destino_addr, archivo)
                
        except Exception as e:
            print(f"[ERROR] Réplica fallida: {e}")

    def notificar_nuevo_archivo(self, archivo):
        """Notificar al maestro sobre un nuevo archivo replicado"""
        if not self.aes_key_maestro:
            return

        try:
            mensaje_json = json.dumps({
                'type': 'actualizacion_archivos',
                'archivos': [archivo]  # lista de archivos a agregar
            }).encode()

            # Cifrar mensaje con AES
            iv = get_random_bytes(16)
            cipher = AES.new(self.aes_key_maestro, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(mensaje_json, AES.block_size))
            hmac = HMAC.new(self.aes_key_maestro, digestmod=SHA256)
            hmac.update(iv + ciphertext)
            mensaje_cifrado = base64.b64encode(iv + ciphertext + hmac.digest())

            # Enviar al maestro
            self.sock.sendto(mensaje_cifrado, self.maestro_addr)

            print(f"[NODO] Notificado al maestro sobre el archivo {archivo}")

        except Exception as e:
            print(f"[ERROR] Notificando al maestro: {e}")

    def cifrar_mensaje(self, plaintext, addr):
        """Cifrar mensaje para un cliente específico"""
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

    def cifrar_mensaje_replicacion(self, plaintext, aes_key):
        """Cifrar mensaje para replicación"""
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        hmac = HMAC.new(aes_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        return base64.b64encode(iv + ciphertext + hmac.digest())

    def start(self):
        """Iniciar servidor nodo"""
        print(f"[NODO] Iniciando en {self.host}:{self.port}")
        
        # Registrar con maestro
        self.registrar_con_maestro()
        
        # Hilo para escuchar mensajes
        threading.Thread(target=self.escuchar, daemon=True).start()
        
        # Bucle principal
        while self.ejecutando:
            cmd = input("Comando (status, exit): ").strip()
            
            if cmd == "status":
                print(f"Archivos locales: {len(self.archivos_locales)}")
                print(f"Clientes conectados: {len(self.clientes)}")
                
            elif cmd == "exit":
                self.ejecutando = False
                self.sock.close()
                break

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Uso: python nodo.py <carpeta_archivos> <puerto> [ip_maestro] [puerto_maestro]")
        sys.exit(1)
        
    folder = sys.argv[1]
    port = int(sys.argv[2])
    maestro_ip = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    maestro_port = int(sys.argv[4]) if len(sys.argv) > 4 else 5000
    
    nodo = ServidorNodo(folder, host="127.0.0.1", port=port, maestro_addr=(maestro_ip, maestro_port))
    nodo.start()