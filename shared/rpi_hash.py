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
    raise NotImplementedError("Oopsies!")


def HMAC(data: bytes, key: bytes, algo: tuple[Callable[[bytes], bytes], bytes, bytes] = (SHA1, b'\x36'*40, b'\x5C'*40)) -> bytes:
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
