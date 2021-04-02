import multiprocessing
import sys
import os
import pickle
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec

def nounceGenerator(tam):
    return os.urandom(tam)


def cifragem(plaintext):
    iv = nounceGenerator(12)
    password = b'chave secreta'
    nounce = nounceGenerator(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nounce,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    private_key = dsa.generate_private_key(key_size=1024, )

    sign = private_key.sign(ciphertext, hashes.SHA256())

    dsa_key = load_der_public_key(private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

    pp = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)

    return ciphertext, iv, encryptor.tag, nounce, sign, pp


def emitter(conn, m):
    (ct, iv, tag, n, sig, pp) = cifragem(m)
    print('ciphertext: ', ct)
    conn.send(ct)
    conn.send(iv)
    conn.send(tag)
    conn.send(n)
    conn.send(sig)
    conn.send(pp)
    conn.close()


def decifragem(ciphertext, iv, tag, nounce, sign, public_key):
    password = b'chave secreta'

    dsa_key = load_der_public_key(public_key, backend=default_backend())

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nounce,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    dsa_key.verify(
        sign,
        ciphertext,
        hashes.SHA256()
    )

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def receiver(conn):
    while 1:
        ct = conn.recv()
        iv = conn.recv()
        tag = conn.recv()
        n = conn.recv()
        sig = conn.recv()
        pp = conn.recv()
        m = decifragem(ct, iv, tag, n, sig, pp)
        print(b"Mensagem decifrada: " + m)
        break


if __name__ == '__main__':
    parent_conn, child_conn = multiprocessing.Pipe()

    while True:

        print("Write a message!!!")

        msg = msg = bytes(input(), 'utf-8')

        p1 = multiprocessing.Process(target=emitter, args=(parent_conn, msg))
        p2 = multiprocessing.Process(target=receiver, args=(child_conn,))

        p1.start()
        p2.start()

        p1.join()
        p2.join()
