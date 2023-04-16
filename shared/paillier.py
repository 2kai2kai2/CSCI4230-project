import math
import secrets


def make_keys() -> (int, int, int):
    """
        Calculates a valid p, q, and g value to be used for a Paillier Session.

        Parameters
        ----
           None.

        Returns
        ----
        p Private Key, prime.
        q Private Key, prime.
        g Generator is Set Z_n**2.
        """
    def is_prime(n):
        for i in range(2, n):
            if (n % i) == 0:
                return False
        return True

    p = secrets.randbelow(1000)
    while not is_prime(p) or p < 200:
        p = secrets.randbelow(1000)

    q = secrets.randbelow(1000)
    while 1 != math.gcd(p * q, (p - 1) * (q - 1)) or p < 200 or not is_prime(q):
        q = secrets.randbelow(1000)

    n = p*q
    g = secrets.randbelow(n*n)
    while 1 != math.gcd(g, n*n):
        g = secrets.randbelow(n*n)

    return p, q, g


# Paillier encryption using PyCrypto's PRNG
def encrypt(m: int, n: int, g: int) -> int:
    """
        Encrypts Message 'm' with public keys 'n' and 'g'.

        Parameters
        ----
           m Message PlainText
           n p*q
           g Public Key in set Z*_n^2

        Returns
        ----
        c Message CphierText
        """
    # Random number from PRNG
    r = secrets.randbelow(n)
    while 1 != math.gcd(r, n):
        r = secrets.randbelow(n)
    print("Random Number: " + str(r))
    # Begin Encryption
    print("Message: " + str(m))
    c = (pow(g, m) * pow(r, n)) % (n * n)
    return c


# Decrypts the Paillier encryption using the given u = 53022
def decrypt(c: int, p: int, q: int, g: int):
    """
        Decrypts Message 'c' with private keys 'p', 'q' and public key 'g'.

        Parameters
        ----
        m Message CphierText
        p Private Key
        q Private Key
        g Public Key in set Z*_n^2

        Returns
        ----
        m Message Plaintext
        """
    n = p * q

    # L function defined by Paillier PKC
    def L(um):
        return (um - 1) // n

    u = pow(L(pow(g, math.lcm(p - 1, q - 1), n * n)), -1, n)
    print("u:", u)
    m = ((L(pow(c, math.lcm(p - 1, q - 1), n * n))) * u) % n
    return m


# Sum of the messages by adding up the ciphertexts in a list or tuple
def summation(ctxt: tuple[int], n: int) -> int:
    """
        Does a summation of a list/tuple of Encrypted Messages.

        Parameters
        ----
        ctext CphierText List
        n: Public Key

        Returns
        ----
        sum
        """
    tally = 1
    for i in range(0, len(ctxt)):
        tally = tally * ctxt[i] % (n * n)
    return tally


