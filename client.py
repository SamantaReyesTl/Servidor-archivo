import socket
import json
import os
import base64
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

class ClienteInteligente:
    def __init__(self, maestro_addr):
        self.maestro_addr = maestro_addr
        self.aes_keys = {}  # servidor -> clave AES
        self.cache_archivos = {}  # nombre_archivo -> contenido

    # Consulta al maestro por la ubicación del archivo
    def consultar_maestro(self, nombre_archivo):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            consulta = json.dumps({
                'type': 'consulta',
                'archivo': nombre_archivo
            }).encode()
            
            sock.sendto(consulta, self.maestro_addr)
            sock.settimeout(3)
            
            data, _ = sock.recvfrom(4096)
            respuesta = json.loads(data.decode())
            
            if respuesta.get('type') == 'respuesta_consulta' and respuesta.get('encontrado'):
                # Adaptado a maestro que devuelve un solo nodo
                return respuesta.get('nodo', [])
            else:
                return []
                
        except Exception as e:
            print(f"[ERROR] Consulta al maestro fallida: {e}")
            return []
        finally:
            sock.close()

    # Descarga archivo directamente desde un nodo
    def descargar_desde_nodo(self, nombre_archivo, nodo_addr):  
        if nombre_archivo in self.cache_archivos:
            print(f"[CACHE] Archivo {nombre_archivo} encontrado en caché local")
            return self.cache_archivos[nombre_archivo]
        
        sock = self.handshake(nodo_addr)
        if not sock:
            return None
        
        try:
            solicitud = json.dumps({
                'type': 'solicitud_archivo',
                'archivo': nombre_archivo
            }).encode()
            sock.sendto(solicitud, nodo_addr)
            
            buffer = []
            
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                    paquete = json.loads(data.decode())
                    
                    if paquete.get('archivo') != nombre_archivo:
                        continue
                    
                    aes_key = self.aes_keys[nodo_addr]
                    contenido = self.descifrar_mensaje(paquete['data'], aes_key)
                    
                    if contenido is None:
                        continue
                    
                    if paquete.get('type') == 'data':
                        buffer.append(contenido)
                    elif paquete.get('type') == 'eof':
                        contenido_completo = "\n".join(buffer)
                        self.cache_archivos[nombre_archivo] = contenido_completo
                        return contenido_completo
                        
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[ERROR] Descarga fallida: {e}")
                    break
                    
        finally:
            sock.close()
        
        return None

    # Handshake seguro con un servidor
    def handshake(self, server_addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            syn = json.dumps({'type':'SYN'}).encode()
            sock.sendto(syn, server_addr)

            data, _ = sock.recvfrom(4096)
            resp = json.loads(data.decode())
            if resp.get('type') != 'SYN-ACK':
                sock.close()
                return None

            server_pub = RSA.import_key(resp['public_key'])
            aes_key = AES.get_random_bytes(32)
            cipher_rsa = PKCS1_OAEP.new(server_pub)
            aes_key_enc = cipher_rsa.encrypt(aes_key)

            ack = json.dumps({'type':'ACK','aes_key':base64.b64encode(aes_key_enc).decode()})
            sock.sendto(ack.encode(), server_addr)
            self.aes_keys[server_addr] = aes_key
            return sock
        except Exception as e:
            print(f"[ERROR] Handshake fallido con {server_addr}: {e}")
            return None

    # Descifrar mensaje
    def descifrar_mensaje(self, mensaje_b64, aes_key):
        try:
            mensaje = base64.b64decode(mensaje_b64)
            iv = mensaje[:16]
            ciphertext = mensaje[16:-32]
            hmac_recibido = mensaje[-32:]
            h = HMAC.new(aes_key, digestmod=SHA256)
            h.update(iv + ciphertext)
            h.verify(hmac_recibido)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        except Exception:
            return None

    # Método principal para descargar archivos
    def descargar_archivo(self, nombre_archivo):
        nodo = self.consultar_maestro(nombre_archivo)
        
        if not nodo:
            print(f"[ERROR] Archivo {nombre_archivo} no encontrado en el sistema")
            return False
        
        nodo_addr = tuple(nodo)  # ahora maestro devuelve solo un nodo
        print(f"[INFO] Descargando {nombre_archivo} desde {nodo_addr}")
        contenido = self.descargar_desde_nodo(nombre_archivo, nodo_addr)
        
        if contenido:
            ruta_salida = os.path.join("archivos_descargados", nombre_archivo)
            os.makedirs("archivos_descargados", exist_ok=True)
            with open(ruta_salida, "w", encoding="utf-8") as f:
                f.write(contenido)
            print(f"[EXITO] Archivo {nombre_archivo} guardado en {ruta_salida}")
            return True
        else:
            print(f"[ERROR] Fallo al descargar {nombre_archivo} desde {nodo_addr}")
            return False

# Ejemplo de uso
if __name__ == "__main__":
    maestro_addr = ("127.0.0.1", 5000)  # Dirección del servidor maestro
    cliente = ClienteInteligente(maestro_addr)

    archivo = input("Nombre del archivo a descargar: ").strip()
    cliente.descargar_archivo(archivo)
