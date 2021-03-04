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
s.bind((host, port))
s.listen(1)
con, addr = s.accept()
print('connected with ', addr)
########################


########## KDF
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(b"my great password")
##############

#### Assinatura da chave 
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(key)
sign = h.finalize()
##########################

# associated data
associated_data = b'random data'

#### Função de cifragem
def encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)
##########################


(iv, ciphertext, tag) = encrypt(key, b'mensagem secreta', associated_data)


########## Envia ao receiver 
con.send(salt)
con.recv(1024)

con.send(iv)
con.recv(1024)

con.send(ciphertext)
con.recv(1024)

con.send(tag)
con.recv(1024)

con.send(associated_data)
con.recv(1024)

con.send(sign)
con.recv(1024)