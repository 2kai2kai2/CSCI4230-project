import math
import secrets
from typing import Optional

_DEFAULT_N = 606637
_DEFAULT_G = 55491315847
_DEFAULT_SERVER_SECRET_P = 653
_DEFAULT_SERVER_SECRET_Q = 929
assert (_DEFAULT_N == _DEFAULT_SERVER_SECRET_Q * _DEFAULT_SERVER_SECRET_P)
DEFAULT_SERVER_PUBKEY = (_DEFAULT_G, _DEFAULT_N)
DEFAULT_SERVER_PRIVKEY = math.lcm(
    _DEFAULT_SERVER_SECRET_P - 1, _DEFAULT_SERVER_SECRET_Q - 1)


def extended_euclidian_algorithm(a: int, b: int) -> tuple[int, int, int]:
    """
    Returns (`gcd(a,b)`, `s`, `t`) such that `gcd(a,b)=as+bt`
    """
    r = [a, b]
    s = [1, 0]
    t = [0, 1]
    q = [-1, a // b]
    while r[-1] != 0:
        q.append(r[-2] // r[-1])
        s.append(s[-2] - q[-1] * s[-1])
        t.append(t[-2] - q[-1] * t[-1])
        r.append(r[-2] % r[-1])
    return (r[-2], s[-2], t[-2])


def primality_test(num: int, k=None) -> bool:
    """
    Tests the primality of `num`. This tests trivial cases, then uses the Miller-Rabin primality test with `k` iterations.

    Parameters
    ----
       - `num` - the number to check the primality of.
       - `k` - the number of iterations of Miller-Rabin primality test to use. If `None` (default), k=8log_2(num)

    Returns
    ----
    `False` if the `num` is found to be composite, or `True` if it was not.
    The probability of a composite number being found to be prime is, worst case, (1/4)^k
    """
    # Invalid integers
    if not isinstance(num, int) or num <= 1:
        return False
    # Divide by low factors
    LOWEST_200_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 292, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
                         127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                         257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
                         401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
                         563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                         709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
                         877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031,
                         1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171,
                         1181, 1187, 1193, 1201, 1213, 1217, 1223]
    if num in LOWEST_200_PRIMES:
        return True
    if any([num % x == 0 for x in LOWEST_200_PRIMES]):
        return False
    # Then do Miller-Rabin if we don't have an easy answer
    if k is None:
        k = int(math.log2(num)) * 8
    d = num - 1
    s = 0

    while d & 1 == 0 and d != 0:
        assert (d // 2) * 2 == d
        d = d // 2
        s += 1
    assert d * (2 ** s) == num - 1
    for _ in range(k):
        a = secrets.randbelow(num - 4) + 2
        x = pow(a, d, num)
        for _ in range(s):
            y = pow(x, 2, num)
            if y == 1 and x != 1 and x != num - 1:
                return False
            x = y
        if x != 1:
            return False
    return True


def keygen(bits=1024) -> tuple[tuple[int, int], int]:
    """
    Generates a key set for Paillier cryptosystem
    Using recommended simplified version from https://en.wikipedia.org/wiki/Paillier_cryptosystem#Key_generation

    Returns
    ----
    A tuple containing:
       - Public key `(g,n)`
       - Private key `\\lambda`
    """
    p = 1
    while not primality_test(p):
        p = secrets.randbelow(2 ** bits)
    q = 1
    while not primality_test(q):
        q = secrets.randbelow(2 ** bits)
    n = p * q
    lam = (p - 1) * (q - 1)
    assert math.gcd(p, q) == 1 and math.gcd(n, lam) == 1
    g = n + 1
    return ((g, n), lam)


def funcL(x: int, n: int) -> int:
    return int(((x-1) % (n * n)) // n)


def encrypt(msg: int, pubkey: tuple[int, int], r: Optional[int] = None) -> int:
    """Public key (g,n)"""
    g, n = pubkey
    if r is None:
        while r is None or math.gcd(r, n) != 1:
            r = secrets.randbelow(n - 1) + 1
    assert 0 < r and r < n and math.gcd(r, n) == 1
    return (pow(g, msg, n*n) * pow(r, n, n*n)) % (n * n)


def decrypt(msg: int, pubkey: tuple[int, int], privkey: int) -> int:
    """Public key (g,n)"""
    g, n = pubkey
    inv = extended_euclidian_algorithm(funcL(pow(g, privkey, n*n), n), n)[1]
    return int(funcL(pow(msg, privkey, n*n), n) * inv) % n


def homomorphic_add(a: int, b: int, n: int) -> int:
    """D(result) = D(a) + D(b) (mod n)"""
    return (a * b) % (n * n)


def homomorphic_summation(items: list[int], n: int) -> int:
    """D(result) = sum(D(item[i])) (mod n)"""
    p = 1
    for i in items:
        p *= i
    return p % (n * n)


def homomorphic_mult(a: int, b_plain: int, n: int) -> int:
    """D(result) = D(a) * b_plain (mod n)"""
    return pow(a, b_plain, n*n)
