import socket
import os 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host=socket.gethostname()
port=7635

s.bind((host, port))
s.listen(1)

con, addr = s.accept()
print('connected with ', addr)



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


(iv, ciphertext, tag) = encrypt(key, b'boas malta', b'yo')


print(salt)
con.send(salt)
con.recv(1024)

print(iv)
con.send(iv)
con.recv(1024)

print(ciphertext)
con.send(ciphertext)
con.recv(1024)

print(tag)
con.send(tag)
con.recv(1024)