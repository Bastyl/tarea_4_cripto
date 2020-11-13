import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sqlite3

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Informacion del socket
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)
sock.listen(1)


while True:
    print('Esperando una coneccion')
    connection, client_address = sock.accept()  #espera coneccion del cliente
    try:
        print('coneccion de', client_address)

        while True:
            data = connection.recv(16)
            print('recibido {!r}'.format(data))   #recibe una solicitud de llave publica, por ende procede a crearla
            if data:
                print('generando y enviando clave publica')   

                key = RSA.generate(2048)     #crea su llave publica y privada, la llave privada la guarda en un archivo propio
                public_key = key.publickey()
                f = open('private.pem','wb')
                f.write(key.export_key('PEM'))
                f.close()
                
                connection.sendall(public_key.export_key('PEM'))  #envia la llave publica
                break   

       
        count = 0    #aqui basicamente se crea la base de datos por mientras que el cliente cifra los hashes
        conn = sqlite3.connect('tabla_hashes.sqlite')
        cur = conn.cursor()
        cur.execute('DROP TABLE IF EXISTS Hashes')
        cur.execute('CREATE TABLE Hashes (title TEXT, id INTEGER)')


        while True:    #ciclo mientras el cliente envia los cifrados 1 por 1, cada uno pesa 256 bytes
            data = connection.recv(256)

            if len(data) == 256:  #recibe el paquete de 256 bytes
                private_key = RSA.importKey(open('private.pem').read()) # lo descifra con su llave privada
                cipher = PKCS1_OAEP.new(private_key)
                message_2 = cipher.decrypt(data)
                cur.execute('INSERT INTO Hashes (title, id) VALUES (?, ?)',(message_2.decode("utf-8") , count))
                conn.commit()  #ingresa a la tabla slqli el hash descifrado

                count += 1


            if data == b'end':  #ya no hay mas hashes recibidos y se termina el proceso
                cur.execute('SELECT title, id FROM Hashes')
                for row in cur:
                    #print("chau")
                    print(row)
                cur.close()
                break

            


    finally:
        connection.close()

