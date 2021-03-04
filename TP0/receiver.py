import socket
import os 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


######## Estabelecer conexão 
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host=socket.gethostname()
port=7635
s.connect((host, port))
########################


########## Recebe do sender 
salt = s.recv(1024)
s.send(b'ok')

iv = s.recv(1024)
s.send(b'ok')

ciphertext = s.recv(1024)
s.send(b'ok')

tag = s.recv(1024)
s.send(b'ok')

associated_data = s.recv(1024)
s.send(b'ok')

sign = s.recv(1024)
s.send(b'ok')
####################################


########## KDF
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(b"my great password")
##################################


##### Verificação da assinatura da chave 
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(key)
h.verify(sign)
##########################


##### Função de decifragem 
def decrypt(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()
#####################


print(decrypt(key, associated_data, iv, ciphertext, tag))