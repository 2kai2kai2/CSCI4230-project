"""
Based on RFC 8017

https://datatracker.ietf.org/doc/html/rfc8017
"""

from typing import Callable, Optional, TypeAlias
import secrets
import math

HashFuncType: TypeAlias = Callable[[bytes], bytes]


def MGF1(seed: bytes, mask_len: int, hash_func: HashFuncType) -> bytes:
    """
    Runs the MGF1 mask generation function.

    https://en.wikipedia.org/wiki/Mask_generation_function#MGF1

    Parameters
    ----
       - `seed` the seed from which the mask is generated
       - `mask_len` the length in bytes of the output.
       - `hash_func` the hash function to use

    Returns
    ----
    The generated mask of length `mask_len`
    """
    T = b''
    ctr = 0
    while len(T) < mask_len:
        C = ctr.to_bytes(4, 'big')
        T += hash_func(seed + C)
    return T[:mask_len]


def EMSA_PSS_ENCODE(msg: bytes, emLen: int, hash_func: HashFuncType,
                    MGF: Callable[[bytes, int, HashFuncType], bytes] = MGF1, sLen: Optional[int] = None) -> bytes:
    """
    Encodes a message using EMSA-PSS as specified in RFC 8017 section 9.1.1

    Parameters
    ----
       - `msg` the message to encode (`M`)
       - `emLen` the length of the output in bytes (`emBits` / 8)
       - `hash_func` the hash function to use
       - `MGF` the mask generation function to use. Defaults to `MGF1`
       - `sLen` the salt length to generate in bytes. If `None`, then hash length is used. This is the default.

    Returns
    ----
    `EM`, the EMSA-PSS encoded message of length `emLen`
    """
    mHash = hash_func(msg)
    sLen = sLen or len(mHash)
    if emLen < len(mHash) + sLen + 2:
        raise RuntimeError("Encoding Error")
    salt = secrets.token_bytes(sLen)
    msg_modified = (b'\x00' * 8) + mHash + salt
    H = hash_func(msg_modified)
    PS = b'\x00' * (emLen - sLen - len(mHash) - 2)
    DB = PS + b'\x01' + salt
    dbMask = MGF(H, emLen - len(mHash) - 1, hash_func)
    maskedDB = bytes([x ^ y for x, y in zip(DB, dbMask)])
    # (step 11 excluded; does nothing since we return in full bytes)
    return maskedDB + H + b'\xbc'


def EMSA_PSS_VERIFY(msg: bytes, EM: bytes, hash_func: HashFuncType,
                    MGF: Callable[[bytes, int, HashFuncType], bytes] = MGF1, sLen: Optional[int] = None) -> bool:
    """
    Verifies a message using EMSA-PSS as specified in RFC 8017 section 9.1.2

    Parameters
    ----
       - `msg` the message to encode (`M`)
       - `EM` the encoded message used to verify the message (note the lack of `emLen`/`emBits` as this is just the length of `EM`)
       - `hash_func` the hash function to use
       - `MGF` the mask generation function to use. Defaults to `MGF1`
       - `sLen` the salt length to generate in bytes. If `None`, then hash length is used. This is the default.

    Returns
    ----
    `True` if successfully verified, otherwise `False`
    """
    mHash = hash_func(msg)
    sLen = sLen or len(mHash)
    if len(EM) < len(mHash) + sLen + 2:
        return False
    if EM[-1] != 0xbc:
        return False
    maskedDB = EM[:len(EM) - len(mHash) - 1]
    H = EM[len(EM) - len(mHash) - 1:-1]
    # (step 6 excluded; does nothing since we deal with full bytes)
    dbMask = MGF(H, len(EM) - len(mHash) - 1, hash_func)
    DB = bytes([x ^ y for x, y in zip(maskedDB, dbMask)])
    # (step 9 excluded; does nothing since we deal with full bytes)
    if any([x != 0x00 for x in DB[:len(EM) - len(mHash) - sLen - 2]]) or DB[len(EM) - len(mHash) - sLen - 2] != 0x01:
        return False
    salt = DB[-sLen:]
    msg_modified = (b'\x00' * 8) + mHash + salt
    H_found = hash_func(msg_modified)
    return H_found == H


def RSASSA_PSS_SIGN(msg: bytes, key: int, n: int, hash_func: HashFuncType) -> bytes:
    """
    Signs a message using RSASSA-PSS as specified in RFC 8017 section 8.1.1

    Parameters
    ----
       - `msg` the message to sign
       - `key` the private key `d` of the signer
       - `n` the modulus
       - `hash_func` the hash function to use

    Returns
    ----
    The signature
    """
    emLen = math.floor((math.log2(n) - 1)/8)
    EM = EMSA_PSS_ENCODE(msg, emLen, hash_func)
    m = int.from_bytes(EM, 'big')
    s = pow(m, key, n)
    return s.to_bytes(math.ceil(math.log2(n) / 8), 'big')


def RSASSA_PSS_VERIFY(msg: bytes, s: int, key: int, n: int, hash_func: HashFuncType) -> bool:
    """
    Verifies a message using RSASSA-PSS as specified in RFC 8017 section 8.1.2

    Parameters
    ----
       - `msg` the message to sign
       - `S` the signature of the message
       - `key` the public key `e` of the signer
       - `n` the modulus
       - `hash_func` the hash function to use

    Returns
    ----
    `True` if successfully verified, otherwise `False`
    """
    m = int(pow(s, key, n))
    try:
        EM = m.to_bytes(math.floor((math.log2(n) - 1)/8), 'big')
    except OverflowError:
        return False
    return EMSA_PSS_VERIFY(msg, EM, hash_func)
