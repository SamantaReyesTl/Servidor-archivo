# Servidor-archivo

# Estructura del Proyecto

dns.py                # Servidor DNS de archivos distribuido
server.py             # Servidor de archivos seguro (cifrado TLS)
client.py             # Cliente que consulta DNS y descarga archivos
server1_files/        # Carpeta con archivos del primer servidor
server2_files/        # Carpeta con archivos del segundo servidor


# Requuisitos
Para instalar con el comando:

    pip install pycryptodome

Si no llegara funcionar tamnbn:

    python -m pip install pycryptodome

# Uso

1. Crear carpetas de servidores y colocar archivos

2. Ejecutar cada servidor con su carpeta y puerto distinto:

   # Servidor 1
   python server.py --folder server1_files --port 5000

   # Servidor 2
   python server.py --folder server2_files --port 5001

3. Ejecutar DNS indicando carpetas y puertos de los servidores:

   python dns.py --folders server1_files server2_files --servers 127.0.0.1:5000 127.0.0.1:5001

   Nota: Si el puerto DNS por defecto está ocupado, se elegirá automáticamente otro puerto libre.

4. Ejecutar cliente indicando el archivo a solicitar:

   python client.py --file archivo1.txt

   Opcional (agregarlo despues):
   --dns_host 127.0.0.1 --dns_port 15050


# Flujo

1. El cliente consulta al DNS si el archivo existe.
2. El DNS devuelve los servidores que tienen el archivo.
3. El cliente hace handshake seguro con un servidor y descarga el archivo.
