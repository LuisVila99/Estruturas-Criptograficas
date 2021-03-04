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

s.connect((host, port))


salt = s.recv(1024)
s.send(b'ok')
print(salt)


iv = s.recv(1024)
s.send(b'ok')
print(iv)


ciphertext = s.recv(1024)
s.send(b'ok')
print(ciphertext)


tag = s.recv(1024)
s.send(b'ok')
print(tag)





########## KDF
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(b"my great password")
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
kdf.verify(b"my great password", key)
##############




def decrypt(key, associated_data, iv, ciphertext, tag):

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    return decryptor.update(ciphertext) + decryptor.finalize()

print(decrypt(key, b'yo', iv, ciphertext, tag))