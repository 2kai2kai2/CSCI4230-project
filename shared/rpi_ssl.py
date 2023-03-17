from enum import IntEnum
from typing import Callable


class ContentType(IntEnum):
    ChangeCipherSpec = 0x14
    Alert = 0x15
    Handshake = 0x16
    Application = 0x17
    Heartbeat = 0x18


def build_record(content_type: ContentType, body: bytes) -> bytes:
    """
    Builds a TLS/SSL record. Does not alter the body (see specialized functions), instead 
    only adding the header containing Content Type, Legacy Version, and Length, with `body` starting on byte 5.

    https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record
    """
    return bytes([content_type.value, 0x03, 0x03]) + len(body).to_bytes(2, 'big') + body


def build_handshake_record():
    """
    Builds a TLS/SSL record for the handshake.

    https://en.wikipedia.org/wiki/Transport_Layer_Security#Handshake_protocol
    """
    # This should probably call build_record
    raise NotImplementedError("oopsie!")


def build_app_record(body: bytes, seq: int, MAC: Callable[[bytes], bytes],
                     encryptor: Callable[[bytes], bytes], block_size: int) -> bytes:
    """
    Builds a TLS/SSL record for the main part of communication, after handshake.

    https://en.wikipedia.org/wiki/Transport_Layer_Security#Application_protocol

    Parameters
    ----
       - `body` - the application data to be sent.
       - `seq` - the sequence number of this record.
       - `MAC` - a MAC function to be run on the body. Lambdas may be used to provide parameters other than the data, for example `lambda x: HMAC(x, <KEY>)`
       - `encryptor` - an encryption function to be run on the body, MAC, and padding. Lambdas may be used to provide parameters other than the plaintext, for example `lambda x: encrypt(x, <KEY>, 'CBC')`
       - `block_size` - the block size of the encryption function. Used to pad before encrypting.

    Throws
    ----
       - `ValueError` if `seq < 0`  or `block_size <= 0`
    """
    if seq < 0:
        raise ValueError("Sequence number cannot be negative.")
    elif block_size <= 0:
        raise ValueError("Block size must be a positive integer.")

    mac_value = MAC(seq.to_bytes(8, 'big') + body)
    plaintext = body + mac_value
    pad_len = block_size - (len(plaintext) % block_size)
    plaintext += b'a' * (pad_len - 1) + pad_len.to_bytes(1, 'big')

    ciphertext = encryptor(plaintext)
    return build_record(ContentType.Application, ciphertext) 
