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


def HMAC(data: bytes, key: bytes,
         algo: tuple[Callable[[bytes], bytes], bytes, bytes] = (SHA1, b'\x36' * 40, b'\x5C' * 40)) -> bytes:
    """
    Calculates the HMAC for the provided data.

    Parameters
    ----
       - `data` - the data to generate an HMAC for. May be any length.
       - `key` - the shared key to use for the HMAC.
       - `algo` - a tuple containing (in order), a hash function f(bytes)->bytes, HMAC pad_1, and HMAC pad_2. By default, SHA-1.
    
    Returns
    ----
    A corresponding HMAC, with the length determined by (the same as) the specified hash function.
    """
    raise NotImplementedError("Oopsies!")
