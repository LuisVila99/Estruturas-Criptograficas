import multiprocessing
import sys
import os
import pickle
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_parameters
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dh
#from cryptography.hazmat.primitives.asymmetric.dh.DHParameters import parameter_bytes
import cryptography.hazmat.primitives.asymmetric.dh.DHParameters as x




def is_in(val, lst):
    for a in lst:
        if a==val: return True
    return False

def nounceGenerator(tam):

    with open('./used.log', 'r') as fr:
        nounces_usados = fr.readlines()
        fr.close()
    

    r = os.urandom(tam)
    while(is_in(str(r), nounces_usados)):
        r = os.urandom(tam)

    with open('./used.log', 'a') as fw:
        fw.write(str(r))
        fw.write('\n')
        fw.close()

    return r


def cifragem(conn, plaintext):
    iv = nounceGenerator(12)
    password = b'chave secreta'
    nounce = nounceGenerator(16)

    params = (2, 2048)
    parameters = dh.generate_parameters(generator=params[0], key_size=params[1])
    private_key = parameters.generate_private_key()
    conn.send(x.parameter_bytes(parameters))
    conn.send(private_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    pk = conn.recv()
    p=load_der_public_key(pk)
    shared_key = private_key.exchange(p)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    print(derived_key)

        

    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    private_key = dsa.generate_private_key(key_size=1024, )

    sign = private_key.sign(derived_key, hashes.SHA256())

    pp = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)

    conn.send(nounce)
    conn.send(ciphertext)
    conn.send(iv)
    conn.send(encryptor.tag)
    conn.send(sign)
    conn.send(pp)

    #return ciphertext, iv, encryptor.tag, nounce, sign, pp, params, pk.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)





def decifragem(conn, useless):

    parameters = conn.recv()
    pk = conn.recv()
    #parameters = dh.generate_parameters(generator=params[0], key_size=params[1])
    private_key = load_der_parameters(parameters).generate_private_key()
    conn.send(private_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))

    p=load_der_public_key(pk)
    shared_key = private_key.exchange(p)

    nounce = conn.recv()

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    )
    key = kdf.derive(shared_key)



    
    ciphertext = conn.recv()
    iv = conn.recv()
    tag = conn.recv()
    sign = conn.recv()
    pp = conn.recv()

    

    load_der_public_key(pp).verify(
        sign,
        key,
        hashes.SHA256()
    )

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()



if __name__ == '__main__':
    parent_conn, child_conn = multiprocessing.Pipe()
    
    while True:
        
        print("Write a message!!!")

        msg = msg = bytes(input(), 'utf-8')

        p1 = multiprocessing.Process(target=cifragem, args=(parent_conn, msg))
        p2 = multiprocessing.Process(target=decifragem, args=(child_conn, ''))

        p1.start()
        p2.start()

        p1.join()
        p2.join()