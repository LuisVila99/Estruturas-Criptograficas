from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys


def generator(N):
    i=0
    palavras = list()
    while i < pow(2, N):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(b"seed") # password
        x = digest.finalize()
        value = int.from_bytes(x[:8], 'little')
        print(value.bit_length())
        palavras.append(value)
        i+=1
    print(palavras)
    return palavras 

generator(8)