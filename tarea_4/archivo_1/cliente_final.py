import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os
import bcrypt

os.system('time hashcat -m 0 -a 0 --potfile-path=/Users/Bastian/desktop/tarea_4/archivo_1/my.pot.txt /Users/Bastian/desktop/tarea_4/archivo_1/archivo_1 /Users/Bastian/desktop/tarea_4/diccionario_2.dict')

f = open("my.pot.txt", "r")   #abre potfile, lee las contrasenas y las hashea 1 x 1.
f2 = open("salida_hasheada.txt", "a+")

a = f.read().split('\n')

for i in range(0, len(a)-1):
    b = a[i].split(':')
    print(b[1])
    
    c = bytes(b[1], 'utf-8')
    
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(c, salt)  #encripta con bcrypt las pass

    f2.write(hashed.decode("utf-8") + '\n' ) #las guarda en "salida_hasheada.txt"
    print(hashed)

f.close()
f2.close()




sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)

public_key = b''

try:
    message = b'Dame una llave publica.'
    print('sending {!r}'.format(message))
    sock.sendall(message)   #solicita la llave publica
    amount_received = 0

    while True:  #recibe la llave
        data = sock.recv(16)
        print('received {!r}'.format(data))
        public_key += data
        
        if(data == b'--'): #esto es por el formato de la llave, indica cuando ya se envio toda la llave
            break

    f = open('public.pem','wb') #guarda la llave publica en un archivo
    f.write(public_key)
    f.close()

    f = open('salida_hasheada.txt','r') #lee el archivo con el hash SEGURO

    a = f.read().split('\n')

    key = RSA.importKey(open('public.pem').read())
    cipher = PKCS1_OAEP.new(key)

    for i in a:    #cominza a cifrar cada hash y lo va enviando instantaneamente
    	c = bytes(i, 'utf-8')
    	ciphertext = cipher.encrypt(c)#el cifrado es de 256 bytes.
    	m = ciphertext
    	#print(len(ciphertext))
    	sock.sendall(ciphertext)

finally:
    sock.sendall(b'end')
    print('closing socket')
    sock.close()

