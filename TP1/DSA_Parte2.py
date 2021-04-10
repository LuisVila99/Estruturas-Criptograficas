from random import randrange
from hashlib import sha1
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

# Esta fase têm como objectivo a criação de uma classe que implemente o algoritmo DSA. Uma instância desta classe
# irá receber como parâmetros os tamanhos dos primos p e q. Com uma instância desta classe irá ser possível assinar
# e verificar uma assinatura digital.
## As 3 funções apresentadas neste esquema são as seguintes:

# A função *__init(self)__* tem como objetivo inicializar os parâmetros necessários para que seja, posteriormente,
# possível assinar e verificar mensagens.

# A função *sign(self,message)* tem como objetivo assinar digitalmente a mensagem message.

# A função verify(self,message,signature) tem como objetivo verificar a assinatura signature tendo em conta a mensagem

# A função gen_p_q(self) que gera os valores de p e q consoante o valor dos parâmetros da instância

# A função gen_g(self) que gera os valores de g consoante o valor de p e q

# A função gen_key(self) que gera as chaves pública e privada.

class myDSA():

    def __init__(self, N, L):
        self.n = N
        self.l = L
        self.p = None
        self.q = None
        self.g = None
        self.priv_key = None
        self.pub_key = None

    def gen_p_q(self):

        g = self.n
        n = (self.l - 1) // g
        b = (self.l - 1) % g
        while True:
            # gerar q
            while True:
                s = xmpz(randrange(1, 2 ** (g)))
                a = sha1(to_binary(s)).hexdigest()
                zz = xmpz((s + 1) % (2 ** g))
                z = sha1(to_binary(zz)).hexdigest()
                U = int(a, 16) ^ int(z, 16)
                mask = 2 ** (N - 1) + 1
                q = U | mask
                print(is_prime(q,20))
                if is_prime(q, 20):
                    break
            # gerar p
            i = 0  # contador
            j = 2  # offset
            while i < 4096:
                V = []
                for k in range(n + 1):
                    arg = xmpz((s + j + k) % (2 ** g))
                    zzv = sha1(to_binary(arg)).hexdigest()
                    V.append(int(zzv, 16))
                W = 0
                for qq in range(0, n):
                    W += V[qq] * 2 ** (160 * qq)
                W += (V[n] % 2 ** b) * 2 ** (160 * n)
                X = W + 2 ** (self.l - 1)
                c = X % (2 * q)
                p = X - c + 1  # p = X - (c - 1)
                if p >= 2 ** (self.l - 1):
                    if is_prime(p, 10):
                        print("gg")
                        self.p = p
                        self.q = q
                        return
                i += 1
                j += n + 1


    def gen_g(self):
        p = self.p
        q = self.q
        while True:
            h = randrange(2, p - 1)
            exp = xmpz((p - 1) // q)
            g = powmod(h, exp, p)
            if g > 1:
                break
        print(g)
        self.g = g



    def gen_keys(self):
        p = self.p
        q = self.q
        g = self.g
        self.priv_key = randrange(1, q - 1)
        self.pub_key = powmod(g, self.priv_key, p)


    def sign(self, message):

        p = self.p
        q = self.q
        g = self.g
        print(g)
        print(p)
        priv_key = self.priv_key

        while True:
            k = randrange(2, q)
            r = powmod(g, k, p) % q
            m = int(sha1(message).hexdigest(), 16)
            try:

                s = (invert(k, q) * (m + priv_key * r)) % q
                return r, s
            except ZeroDivisionError:
                pass

    def verify(self, message, r, s):

        p = self.p
        q = self.q
        g = self.g
        pub_key = self.pub_key

        if r < 0 and r > q:
            raise Exception("Invalid r")

        if s < 0 and s > q:
            raise Exception("Invalid s")
        try:
            w = invert(s, q)
        except ZeroDivisionError:
            return False
        u1 = (int(sha1(message).hexdigest(), 16) * w) % q
        u2 = (r * w) % q
        v = (powmod(g, u1, p) * powmod(pub_key, u2, p)) % p % q
        print(v)
        print(r)
        if v == r:
            return True
        return False


if __name__ == "__main__":

    text = "Mensagem super secreta!!!!"
    message = str.encode(text, "ascii")

    N = 160
    L = 1024
    dsa = myDSA(N, L)
    dsa.gen_p_q()
    dsa.gen_g()
    dsa.gen_keys()

    r, s = dsa.sign(message)
    if dsa.verify(message, r, s):
        print('Correu tudo bem')
    print(message, r, s, sep='\n')
