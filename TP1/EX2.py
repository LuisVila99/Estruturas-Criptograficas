from random import randrange
from hashlib import sha1
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

def gen_p_q(L, N):
    g = N
    n = (L - 1) // g
    b = (L - 1) % g
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
            if is_prime(q, 20):
                break
        # gerar p
        i = 0  # contador
        j = 2  # offset
        while i < g:
            V = []
            for k in range(n + 1):
                arg = xmpz((s + j + k) % (2 ** g))
                zzv = sha1(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = 0
            for qq in range(0, n):
                W += V[qq] * 2 ** (160 * qq)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1  # p = X - (c - 1)
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1


# Gerar G
def gen_g(p, q):
    # g = h^exp mod p
    while True:
        h = randrange(2, p - 1)
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g


def gen_keys(p, q, g):
    priv_key = randrange(1, q - 1)
    pub_key = powmod(g, priv_key, p)

    return priv_key, pub_key


def sign(message, p, q, g, priv_key):
    if not validate_params(p, q, g):
        raise Exception("Invalid params")
    while True:
        k = randrange(2, q)  # 0 < k < q
        r = powmod(g, k, p) % q  # (g^k mod p) mod q
        m = int(sha1(message).hexdigest(), 16)
        try:
            # 1/k (H + x*r) mod q
            s = (invert(k, q) * (m + priv_key * r)) % q  # invmod(k, q) * (H + x*r)
            return r, s
        except ZeroDivisionError:
            pass


def validate_params(p, q, g):
    if is_prime(p) and is_prime(q):
        return True
    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
        return True
    return False


def verify(message, r, s, p, q, g, pub_key):
    if not validate_params(p, q, g):
        raise Exception("Invalid params")

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
    text = "This is a secret message!"
    message = str.encode(text, "ascii")

    N = 160
    L = 1024
    p, q = gen_p_q(L, N)
    g = gen_g(p, q)
    priv_key, pub_key = gen_keys(p, q, g)
    r, s = sign(message, p, q, g, priv_key)
    if verify(message, r, s, p, q, g, pub_key):
        print('All went perfectly')
    # print(message, r, s, p, q, g, priv_key, pub_key, sep='\n')
