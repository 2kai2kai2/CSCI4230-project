import random


# Paillier encryption using PyCrypto's PRNG
def encrypt(m, n, g):
    # Random number from PRNG
    r = random.randrange(n)
    print("Random Number: " + str(r))
    # Begin Encryption
    print("Message: " + str(m))
    c = (pow(g, m) * pow(r, n)) % (n * n)
    return c


# Decrypts the Paillier encryption using the given u = 53022
def decrypt(c, p, q, g):
    n = p * q

    # Used for the Carmicheal Function
    def lcm(x, y):
        """This function takes two
        integers and returns the L.C.M."""

        # choose the greater number
        greater = max(x, y)

        while True:
            if (greater % x == 0) and (greater % y == 0):
                return greater
                break
            greater += 1

    # L function defined by Paillier PKC
    def L(um):
        return (um - 1) / n

    u = pow(L(pow(g, lcm(p - 1, q - 1)) % (n * n)), -1) % n
    print("u:", u)
    m = ((L(pow(c, lcm(p - 1, q - 1), n * n))) * u) % n
    return m


# Sum of the messages by adding up the ciphertexts in a list or tuple
def summation(ctxt):
    tally = 1
    for i in range(0, len(ctxt)):
        tally = tally * ctxt[i] % (n * n)
    return tally


if __name__ == '__main__':

    # Private key information (carmicheal function(n))
    p = 293
    q = 433
    # Public key pair
    n = p * q  # 126869
    g = 6497955158

    ctxts = []
    # Begin Random Sums
    for i in range(0, 1):
        print("Iteration: m = " + str(i))
        c = encrypt(random.choice((5, 5)), n, g)
        print("Ciphertext: " + str(c))
        print("")
        ctxts.append(c)
    # Tally Votes without decrypting them
    print("The Cryptographic Tally of Votes: " + str(summation(ctxts)))
    print("The Decryption of the Tally: " + str(decrypt(summation(ctxts), p, q, g) % n))
