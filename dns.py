import os
import socket
import json
import argparse

class FileDNSServer:
    def __init__(self, folder_paths, servers, host="127.0.0.1", port=None):
        self.host = host
        self.port = port or 0  # 0 hace que el SO elija un puerto libre
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._bind_socket()
        self.index = self.generar_indice_archivos(folder_paths, servers)

    def _bind_socket(self):
        """Intenta bind en el puerto deseado o busca uno libre si falla"""
        try:
            self.sock.bind((self.host, self.port))
        except OSError:
            print(f"[DNS] Puerto {self.port} ocupado, buscando puerto libre...")
            self.sock.bind((self.host, 0))  # 0 = puerto libre
        self.port = self.sock.getsockname()[1]
        print(f"[DNS] Usando puerto {self.port}")

    def generar_indice_archivos(self, folder_paths, servers):
        index = {}
        for i, folder in enumerate(folder_paths):
            folder = os.path.abspath(folder)
            server_addr = servers[i]
            for f in os.listdir(folder):
                path = os.path.join(folder, f)
                if os.path.isfile(path):
                    if f not in index:
                        index[f] = {"size": os.path.getsize(path),
                                    "type": os.path.splitext(f)[1],
                                    "servers": []}
                    index[f]["servers"].append(server_addr)
        return index

    def start(self):
        print(f"[FileDNS] Escuchando en {self.host}:{self.port}")
        while True:
            data, addr = self.sock.recvfrom(4096)
            try:
                query = json.loads(data.decode())
                if query.get("type") == "QUERY_FILE":
                    filename = query.get("file")
                    if filename in self.index:
                        response = {
                            "type": "RESPONSE_FILE",
                            "file": filename,
                            "size": self.index[filename]["size"],
                            "file_type": self.index[filename]["type"],
                            "servers": self.index[filename]["servers"],
                            "authoritative": True
                        }
                    else:
                        response = {"type": "ERROR", "message": f"Archivo {filename} no encontrado"}
                    self.sock.sendto(json.dumps(response).encode(), addr)
            except Exception as e:
                print(f"[ERROR] Consulta inválida de {addr}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor DNS de archivos distribuidos")
    parser.add_argument("--folders", nargs='+', required=True, help="Lista de carpetas locales de servidores")
    parser.add_argument("--servers", nargs='+', required=True, help="Lista de servidores host:port separados por espacio")
    parser.add_argument("--host", default="127.0.0.1", help="IP del DNS")
    parser.add_argument("--port", type=int, default=None, help="Puerto del DNS (si está ocupado se elige otro)")
    args = parser.parse_args()

    # Parse servers
    servers = []
    for s in args.servers:
        host, port = s.split(":")
        servers.append((host, int(port)))

    dns_server = FileDNSServer(args.folders, servers, host=args.host, port=args.port)
    dns_server.start()
