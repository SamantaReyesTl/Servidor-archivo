import os, socket, threading, json, time, random, base64
from collections import defaultdict
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad

class ServidorMaestro:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        
        # Generar claves RSA
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        
        # Estructuras de datos para gestión distribuida
        self.nodos_registrados = {}  # addr -> {'last_seen': timestamp, 'archivos': []}
        self.indice_archivos = defaultdict(list)  # nombre_archivo -> [nodo1, nodo2, ...]
        self.estadisticas_acceso = defaultdict(int)  # nombre_archivo -> contador_accesos
        self.ejecutando = True
        
        # Claves AES para comunicación con nodos
        self.aes_keys = {}

    # Escuchar consultas de clientes y registros de nodos
    def escuchar(self):
        print(f"[MAESTRO] Escuchando en {self.host}:{self.port}")
        
        while self.ejecutando:
            try:
                data, addr = self.sock.recvfrom(4096)
                threading.Thread(target=self.procesar_mensaje, args=(data, addr), daemon=True).start()
            except OSError:
                break

    # Procesar mensajes entrantes
    def procesar_mensaje(self, data, addr):
        try:
            mensaje = json.loads(data.decode())
            tipo = mensaje.get('type')
            
            if tipo == 'SYN':
                self.procesar_syn(addr)
            elif tipo == 'ACK':
                self.procesar_ack(mensaje, addr)
            elif tipo == 'registro_nodo':
                self.registrar_nodo(addr, mensaje.get('archivos', []))
            elif tipo == 'consulta':
                self.procesar_consulta(addr, mensaje.get('archivo'))
            elif tipo == 'actualizacion_archivos':
                self.actualizar_archivos_nodo(addr, mensaje.get('archivos', []))
                
        except Exception as e:
            print(f"[ERROR] Procesando mensaje de {addr}: {e}")

    # Procesar handshake SYN
    def procesar_syn(self, addr):
        respuesta = json.dumps({
            'type': 'SYN-ACK',
            'public_key': self.public_key.export_key().decode()
        }).encode()
        self.sock.sendto(respuesta, addr)

    # Procesar handshake ACK y establecer clave AES
    def procesar_ack(self, mensaje, addr):
        aes_key_cifrada = base64.b64decode(mensaje['aes_key'])
        cipher_rsa = PKCS1_OAEP.new(self.key)
        aes_key = cipher_rsa.decrypt(aes_key_cifrada)
        self.aes_keys[addr] = aes_key
        print(f"[MAESTRO] Handshake completo con {addr}")

    # Registrar un nuevo nodo en el sistema
    def registrar_nodo(self, addr, archivos):
        self.nodos_registrados[addr] = {
            'last_seen': time.time(),
            'archivos': archivos
        }
        
        # Actualizar índice de archivos
        for archivo in archivos:
            if addr not in self.indice_archivos[archivo]:
                self.indice_archivos[archivo].append(addr)
        
        print(f"[MAESTRO] Nodo {addr} registrado con {len(archivos)} archivos")

    # Actualizar lista de archivos de un nodo
    def actualizar_archivos_nodo(self, addr, archivos):
        if addr in self.nodos_registrados:
            # Remover archivos antiguos del índice
            archivos_antiguos = self.nodos_registrados[addr]['archivos']
            for archivo in archivos_antiguos:
                if archivo in self.indice_archivos and addr in self.indice_archivos[archivo]:
                    self.indice_archivos[archivo].remove(addr)
            
            # Actualizar con nuevos archivos
            self.nodos_registrados[addr]['archivos'] = archivos
            self.nodos_registrados[addr]['last_seen'] = time.time()
            
            for archivo in archivos:
                if addr not in self.indice_archivos[archivo]:
                    self.indice_archivos[archivo].append(addr)
            
            print(f"[MAESTRO] Nodo {addr} actualizado con {len(archivos)} archivos")

    # Procesar consulta de cliente y devolver todos los nodos con el archivo
    import random

    # Procesar consulta de cliente y devolver un solo nodo con el archivo
    def procesar_consulta(self, addr, nombre_archivo):
        if nombre_archivo not in self.indice_archivos or not self.indice_archivos[nombre_archivo]:
            respuesta = json.dumps({
                'type': 'respuesta_consulta',
                'encontrado': False
            }).encode()
        else:
            # Incrementar estadísticas de acceso
            self.estadisticas_acceso[nombre_archivo] += 1
            
            # 🔹 Seleccionar un nodo aleatorio que tenga el archivo
            nodo = random.choice(self.indice_archivos[nombre_archivo])
            
            respuesta = json.dumps({
                'type': 'respuesta_consulta',
                'encontrado': True,
                'nodo': list(nodo)  # Retorna solo un nodo
            }).encode()
        
        self.sock.sendto(respuesta, addr)


    # Iniciar replicación automática de archivos populares
    def iniciar_replicacion_automatica(self):
        while self.ejecutando:
            time.sleep(30)  # Replicar cada 30 segundos
            
            # Encontrar archivos populares que necesitan replicación
            archivos_populares = sorted(
                self.estadisticas_acceso.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]  # Top 5 archivos populares
            
            for archivo, _ in archivos_populares:
                if archivo in self.indice_archivos:
                    nodos_con_archivo = self.indice_archivos[archivo]
                    nodos_sin_archivo = [
                        nodo for nodo in self.nodos_registrados 
                        if nodo not in nodos_con_archivo
                    ]
                    
                    if nodos_sin_archivo:
                        # Replicar a un nodo que no tenga el archivo
                        nodo_destino = nodos_sin_archivo[0]
                        self.solicitar_replicacion(archivo, nodo_destino)

    # Solicitar a un nodo origen que replique un archivo a nodo destino
    def solicitar_replicacion(self, archivo, nodo_destino):
        if archivo not in self.indice_archivos or not self.indice_archivos[archivo]:
            return
        
        nodo_origen = self.indice_archivos[archivo][0]
        
        if nodo_origen in self.aes_keys:
            mensaje = json.dumps({
                'type': 'solicitud_replicacion',
                'archivo': archivo,
                'destino': list(nodo_destino)
            }).encode()
            
            # Cifrar mensaje si tenemos clave AES
            try:
                mensaje_cifrado = self.cifrar_mensaje(mensaje, nodo_origen)
                self.sock.sendto(mensaje_cifrado, nodo_origen)
                print(f"[REPLICA] Solicitando replicación de {archivo} desde {nodo_origen} a {nodo_destino}")
            except Exception as e:
                print(f"[ERROR] Error solicitando replicación: {e}")

    # Cifrar mensaje para un nodo específico
    def cifrar_mensaje(self, plaintext, addr):
        if addr not in self.aes_keys:
            return plaintext
            
        aes_key = self.aes_keys[addr]
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        hmac = HMAC.new(aes_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        return iv + ciphertext + hmac.digest()

    def start(self):
        """Iniciar servidor maestro"""
        print(f"[MAESTRO] Iniciando en {self.host}:{self.port}")
        
        # Hilo para escuchar mensajes
        threading.Thread(target=self.escuchar, daemon=True).start()
        
        # Hilo para replicación automática
        threading.Thread(target=self.iniciar_replicacion_automatica, daemon=True).start()
        
        # Bucle principal
        while self.ejecutando:
            cmd = input("Comando (status, exit): ").strip()
            
            if cmd == "status":
                print(f"Nodos registrados: {len(self.nodos_registrados)}")
                print(f"Archivos indexados: {len(self.indice_archivos)}")
                print(f"Archivos populares: {sorted(self.estadisticas_acceso.items(), key=lambda x: x[1], reverse=True)[:5]}")
                
            elif cmd == "exit":
                self.ejecutando = False
                self.sock.close()
                break

if __name__ == "__main__":
    maestro = ServidorMaestro(host="127.0.0.1", port=5000)
    maestro.start()