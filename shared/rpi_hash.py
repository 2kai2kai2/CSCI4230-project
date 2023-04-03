from typing import Callable


def SHA1(data: bytes) -> bytes:
    """
    Calculates a SHA-1 hash for provided data.

    Parameters
    ----
       - `data` - the data to hash. May be any length.

    Returns
    ----
    A 20-byte (160-bit) hash.
    """

    # Byte Xor Operation
    def byte_xor(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    # Byte And Operation
    def byte_and(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a & _b for _a, _b in zip(ba1, ba2)])

    # Byte Add (mod 256) Operation
    def byte_add(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([(_a + _b) % 256 for _a, _b in zip(ba1, ba2)])

    # Pre - processing:
    data += bytes.fromhex('80')
    if len(data) % 64 > 56:
        data += bytes.fromhex('00') * (56 + 64 - len(data) % 64)
    else:
        data += bytes.fromhex('00') * (56 - len(data) % 64)
    data += len(data).to_bytes(8, 'big')

    # Initialize variables:
    h0 = bytes.fromhex('67452301')
    h1 = bytes.fromhex('efcdab89')
    h2 = bytes.fromhex('98badcfe')
    h3 = bytes.fromhex('10325476')
    h4 = bytes.fromhex('c3d2e1f0')

    # Process the message in successive 512-bit chunks:
    for j in range(0, len(data), 64):
        chunk = data[j:j + 64]

        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [bytes()] * 80
        for i in range(16):
            w[i] = chunk[i:i + 4]

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16, 80):
            w[i] = byte_xor(byte_xor(w[i - 3], w[i - 8]), byte_xor(w[i - 14], w[i - 16]))
            # Left Rotate 1
            w[i] = w[i][1:] + w[i][0:1]

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop:
        for i in range(80):
            if 0 <= i <= 19:
                f = byte_xor(byte_and(b, c), byte_and(b, d))
                k = bytes.fromhex('5A827999')
            elif 20 <= i <= 39:
                f = byte_xor(byte_xor(b, c), d)
                k = bytes.fromhex('6ED9EBA1')
            elif 40 <= i <= 59:
                f = byte_xor(byte_xor(byte_and(b, c), byte_and(b, d)), byte_and(c, d))
                k = bytes.fromhex('8F1BBCDC')
            else:
                f = byte_xor(byte_xor(b, c), d)
                k = bytes.fromhex('CA62C1D6')

            temp = byte_add((a[5:] + a[0:5]), byte_add(byte_add(f, e), byte_add(k, w[i])))
            e = d
            d = c
            c = (a[6:] + a[0:6])
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        h0 = byte_add(h0, a)
        h1 = byte_add(h1, b)
        h2 = byte_add(h2, c)
        h3 = byte_add(h3, d)
        h4 = byte_add(h4, e)

    # Produce the final hash value (big-endian) as a 160-bit number:
    return h0 + h1 + h2 + h3 + h4


def SHA256(data: bytes) -> bytes:
    """
    Calculates a SHA-256 hash for provided data.

    Parameters
    ----
       - `data` - the data to hash. May be any length.

    Returns
    ----
    A 32-byte (256-bit) hash.
    """

    # Byte Xor Operation
    def byte_xor(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    # Byte And Operation
    def byte_and(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a & _b for _a, _b in zip(ba1, ba2)])

    # Byte Add (mod 256) Operation
    def byte_add(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([(_a + _b) % 256 for _a, _b in zip(ba1, ba2)])

    # Pre - processing:
    data += bytes.fromhex('80')
    if len(data) % 64 > 56:
        data += bytes.fromhex('00') * (56 + 64 - len(data) % 64)
    else:
        data += bytes.fromhex('00') * (56 - len(data) % 64)
    data += len(data).to_bytes(8, 'big')

    # Initialize variables:
    # (first 32 bits of the fractional parts
    # of the square roots of the first 8 primes 2..19):
    h0 = bytes.fromhex('6a09e667')
    h1 = bytes.fromhex('bb67ae85')
    h2 = bytes.fromhex('3c6ef372')
    h3 = bytes.fromhex('a54ff53a')
    h4 = bytes.fromhex('510e527f')
    h5 = bytes.fromhex('9b05688c')
    h6 = bytes.fromhex('1f83d9ab')
    h7 = bytes.fromhex('5be0cd19')

    k = [
        '428a2f98', '71374491', 'b5c0fbcf', 'e9b5dba5', '3956c25b', '59f111f1', '923f82a4', 'ab1c5ed5',
        'd807aa98', '12835b01', '243185be', '550c7dc3', '72be5d74', '80deb1fe', '9bdc06a7', 'c19bf174',
        'e49b69c1', 'efbe4786', '0fc19dc6', '240ca1cc', '2de92c6f', '4a7484aa', '5cb0a9dc', '76f988da',
        '983e5152', 'a831c66d', 'b00327c8', 'bf597fc7', 'c6e00bf3', 'd5a79147', '06ca6351', '14292967',
        '27b70a85', '2e1b2138', '4d2c6dfc', '53380d13', '650a7354', '766a0abb', '81c2c92e', '92722c85',
        'a2bfe8a1', 'a81a664b', 'c24b8b70', 'c76c51a3', 'd192e819', 'd6990624', 'f40e3585', '106aa070',
        '19a4c116', '1e376c08', '2748774c', '34b0bcb5', '391c0cb3', '4ed8aa4a', '5b9cca4f', '682e6ff3',
        '748f82ee', '78a5636f', '84c87814', '8cc70208', '90befffa', 'a4506ceb', 'bef9a3f7', 'c67178f2'
    ]
    for i in range(64):
        k[i] = bytes.fromhex(k[i])

    # Process the message in successive 512-bit chunks:
    for j in range(0, len(data), 64):
        chunk = data[j:j + 64]

        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [bytes()] * 64
        for i in range(16):
            w[i] = chunk[i:i + 4]

        # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in range(16, 64):
            s0 = byte_xor(byte_xor(w[i - 15][-2:] + w[i - 15][0:-2], w[i - 15][-4:] + w[i - 15][0:-4]),
                          w[i - 15])
            s1 = byte_xor(byte_xor(w[i - 2][-4:] + w[i - 2][0:-4], w[i - 2][-5:] + w[i - 2][0:-5]),
                          w[i - 2])
            w[i] = byte_add(byte_add(w[i - 16], s0), byte_add(w[i - 7], s1))

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Main loop:
        for i in range(64):
            S1 = byte_xor(byte_xor(e[-2:] + e[0:-2], e[-3:] + e[0:-3]), e[-6:] + e[0:-6])
            ch = byte_xor(byte_and(e, f), byte_add(e, g))
            temp1 = byte_add(byte_add(byte_add(h, S1), byte_add(ch, k[i])), w[i])
            S0 = byte_xor(byte_xor(a[-2:] + a[0:-2], a[-3:] + a[0:-3]), a[-6:] + a[0:-6])
            maj = byte_xor(byte_xor(byte_and(a, b), byte_add(a, c)), byte_add(b, c))
            temp2 = byte_add(S0, maj)

            h = g
            g = f
            f = e
            e = byte_add(d, temp1)
            d = c
            c = b
            b = a
            a = byte_add(temp1, temp2)

            # Add the compressed chunk to the current hash value:
            h0 = byte_add(h0, a)
            h1 = byte_add(h1, b)
            h2 = byte_add(h2, c)
            h3 = byte_add(h3, d)
            h4 = byte_add(h4, e)
            h5 = byte_add(h5, f)
            h6 = byte_add(h6, g)
            h7 = byte_add(h7, h)

    return h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7


def SHA384(data: bytes) -> bytes:
    """
    Calculates a SHA-384 hash for provided data.

    Parameters
    ----
       - `data` - the data to hash. May be any length.

    Returns
    ----
    A 48-byte (384-bit) hash.
    """

    # Byte Xor Operation
    def byte_xor(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    # Byte And Operation
    def byte_and(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a & _b for _a, _b in zip(ba1, ba2)])

    # Byte Add (mod 256) Operation
    def byte_add(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([(_a + _b) % 256 for _a, _b in zip(ba1, ba2)])

    # Pre - processing:
    data += bytes.fromhex('80')
    if len(data) % 128 > 112:
        data += bytes.fromhex('00') * (112 + 128 - len(data) % 128)
    else:
        data += bytes.fromhex('00') * (112 - len(data) % 128)
    data += len(data).to_bytes(16, 'big')

    # Initialize variables:
    # (first 32 bits of the fractional parts
    # of the square roots of the first 8 primes 2..19):
    h0 = bytes.fromhex('cbbb9d5dc1059ed8')
    h1 = bytes.fromhex('629a292a367cd507')
    h2 = bytes.fromhex('9159015a3070dd17')
    h3 = bytes.fromhex('152fecd8f70e5939')
    h4 = bytes.fromhex('67332667ffc00b31')
    h5 = bytes.fromhex('8eb44a8768581511')
    h6 = bytes.fromhex('db0c2e0d64f98fa7')
    h7 = bytes.fromhex('47b5481dbefa4fa4')

    k = [
        '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538',
        '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118', 'd807aa98a3030242', '12835b0145706fbe',
        '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235',
        'c19bf174cf692694', 'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
        '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5', '983e5152ee66dfab',
        'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725',
        '06ca6351e003826f', '142929670a0e6e70', '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed',
        '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
        'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218',
        'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8', '19a4c116b8d2d0c8', '1e376c085141ab53',
        '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373',
        '682e6ff3d6b2b8a3', '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
        '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b', 'ca273eceea26619c',
        'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6',
        '113f9804bef90dae', '1b710b35131c471b', '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc',
        '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
    ]
    for i in range(80):
        k[i] = bytes.fromhex(k[i])

    # Process the message in successive 1024-bit chunks:
    for j in range(0, len(data), 128):
        chunk = data[j:j + 128]

        # break chunk into sixteen 64-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [bytes()] * 80
        for i in range(16):
            w[i] = chunk[i:i + 8]

        # Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array:
        for i in range(16, 80):
            s0 = byte_xor(byte_xor(w[i - 15][-1:] + w[i - 15][0:-1],
                                   w[i - 15][-2:] + w[i - 15][0:-2]),
                          w[i - 15])
            s1 = byte_xor(byte_xor(w[i - 2][-5:] + w[i - 2][0:-5],
                                   w[i - 2][-10:] + w[i - 2][0:-10]),
                          w[i - 2])
            w[i] = byte_add(byte_add(w[i - 16], s0), byte_add(w[i - 7], s1))

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Main loop:
        for i in range(80):
            S1 = byte_xor(byte_xor(a[-7:] + a[0:-7],
                                   a[-9:] + a[0:-9]),
                          a[-10:] + a[0:-10])
            ch = byte_xor(byte_and(e, f), byte_add(e, g))
            temp1 = byte_add(byte_add(byte_add(h, S1), byte_add(ch, k[i])), w[i])
            S0 = byte_xor(byte_xor(e[-7:] + a[0:-7],
                                   e[-4:] + a[0:-4]),
                          e[-10:] + e[0:-10])
            maj = byte_xor(byte_xor(byte_and(a, b), byte_add(a, c)), byte_add(b, c))
            temp2 = byte_add(S0, maj)

            h = g
            g = f
            f = e
            e = byte_add(d, temp1)
            d = c
            c = b
            b = a
            a = byte_add(temp1, temp2)

            # Add the compressed chunk to the current hash value:
            h0 = byte_add(h0, a)
            h1 = byte_add(h1, b)
            h2 = byte_add(h2, c)
            h3 = byte_add(h3, d)
            h4 = byte_add(h4, e)
            h5 = byte_add(h5, f)
            h6 = byte_add(h6, g)
            h7 = byte_add(h7, h)

    return h0 + h1 + h2 + h3 + h4 + h5


def HMAC(data: bytes, key: bytes,
         algo: tuple[Callable[[bytes], bytes], int] = (SHA1, 64)) -> bytes:
    """
    Calculates the HMAC for the provided data.

    Parameters
    ----
       - `data` - the data to generate an HMAC for. May be any length.
       - `key` - the shared key to use for the HMAC.
       - `algo` - a tuple containing (in order), a hash function f(bytes)->bytes and int hash block size.
                  By default, SHA-1, 64 bytes
    
    Returns
    ----
    A corresponding HMAC, with the length determined by (the same as) the specified hash function.
    """

    # Byte Xor Operation
    def byte_xor(ba1: bytes, ba2: bytes) -> bytes:
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    # Var definitions
    hasher = algo[0]
    blockSize = algo[1]

    # Compute the block sized key
    block_sized_key = key
    # Keys longer than blockSize are shortened by hashing them
    if len(block_sized_key) > blockSize:
        block_sized_key = hasher(block_sized_key)

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if len(block_sized_key) < blockSize:
        block_sized_key += bytes.fromhex('00') * (blockSize - len(block_sized_key))

    # Pad key with zeros to make it blockSize bytes long
    o_key_pad = byte_xor(block_sized_key, bytes.fromhex('5c') * blockSize)  # Outer padded key
    i_key_pad = byte_xor(block_sized_key, bytes.fromhex('36') * blockSize)  # Inner padded key

    return hasher(o_key_pad + hasher(i_key_pad + data))
