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


class Session:
    """
    For use after handshake completion.
    """

    def __init__(self, encryptor: Callable[[bytes], bytes], decryptor: Callable[[bytes], bytes], block_size: int,
                 MAC: Callable[[bytes], bytes], mac_length: int):
        """
        Parameters
        ----
           - `encryptor` - an encryption function to be used. Lambdas may be used to provide parameters other than the plaintext, for example `lambda x: encrypt(x, <KEY>, 'CBC')`
           - `decryptor` - an decryption function to be used. Lambdas may be used to provide parameters other than the ciphertext, for example `lambda x: decrypt(x, <KEY>, 'CBC')`
           - `block_size` - the block size of the encryption function. Used to pad before encrypting.
           - `MAC` - a MAC function to be run on the body. Lambdas may be used to provide parameters other than the data, for example `lambda x: HMAC(x, <KEY>)`
           - `mac_length` - the length of the output of the MAC function.
        """
        if block_size <= 0:
            raise ValueError("Block size must be a positive integer.")
        elif mac_length <= 0:
            raise ValueError("MAC size must be a positive integer.")

        self.encryptor = encryptor
        self.decryptor = decryptor
        self.block_size = block_size
        self.MAC = MAC
        self.mac_length = mac_length

    def build_app_record(self, body: bytes, seq: int) -> bytes:
        """
        Builds a TLS/SSL record for the main part of communication, after handshake.

        https://en.wikipedia.org/wiki/Transport_Layer_Security#Application_protocol

        Parameters
        ----
        - `body` - the application data to be sent.
        - `seq` - the sequence number of this record.

        Throws
        ----
        - `ValueError` if `seq < 0`
        - Potentially some other error if block size is incorrect.
        """
        if seq < 0:
            raise ValueError("Sequence number cannot be negative.")

        mac_value = self.MAC(seq.to_bytes(8, 'big') + body)
        plaintext = body + mac_value
        pad_len = self.block_size - \
            ((len(plaintext) + 1) % self.block_size) + 1
        plaintext += b'a' * (pad_len - 1) + pad_len.to_bytes(1, 'big')
        # Note that there will always be at least one byte of 'pad' since we will always have the pad length byte.

        ciphertext = self.encryptor(plaintext)
        return build_record(ContentType.Application, ciphertext)

    def open_app_record(self, content: bytes, seq: int) -> bytes:
        """
        Decrypts and verifies the body of a TLS/SSL application record.

        Parameters
        ----
        - `content` - the encrypted body of a TLS/SSL application record, **excluding** the header.
        - `seq` - the sequence number of this record. Used for verification.

        Throws
        ----
        - `ValueError` if `seq < 0`
        - `RuntimeError` if verification fails.
        - `ValueError` if `len(content)` is not a multiple of block length.
        - Potentially some other error if block length is incorrect.

        Returns
        ----
        The application message. Does **not** include MAC, padding, or anything else.
        """
        if seq < 0:
            raise ValueError("Sequence number cannot be negative.")
        if len(content) % self.block_size != 0:
            raise ValueError(
                "TLS/SSL application record content length must be a multiple of the block length.")

        plaintext = self.decryptor(content)
        pad_len = int.from_bytes(plaintext[-1], 'big')
        # Note that there will always be at least one byte of 'pad' since we will always have the pad length byte.
        plaintext = plaintext[:-pad_len]
        message = plaintext[:-self.mac_length]
        mac_value = plaintext[-self.mac_length:]
        if mac_value != self.MAC(seq.to_bytes(8, 'big') + message):
            raise RuntimeError(f"MAC verification failed on message seq{seq}.")
        return message
