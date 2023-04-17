from enum import IntEnum
from typing import Callable


class ContentType(IntEnum):
    ChangeCipherSpec = 0x14
    Alert = 0x15
    Handshake = 0x16
    Application = 0x17
    Heartbeat = 0x18


class AlertLevel(IntEnum):
    """
    Note that in TLS 1.3, all error-type alerts should be FATAL.
    """
    WARNING = 1
    FATAL = 2


class AlertType(IntEnum):
    # Excludes some types not applicable to this implementation
    CloseNotify = 0
    UnexpectedMsg = 10
    BadMAC = 20
    DecryptionFailed = 21
    RecordOverflow = 22
    HandshakeFailure = 40
    NoCertificate = 41
    BadCertificate = 42
    UnsupportedCertificate = 43
    CertificateRevoked = 44
    CertificateExpired = 45
    CertificateUnknown = 46
    IllegalParameter = 47
    AccessDenied = 49
    DecodeError = 50
    DecryptError = 51
    InternalError = 80
    UserCanceled = 90


class SSLError(Exception):
    def __init__(self, atype: AlertType, msg=None):
        self.atype = atype
        super().__init__(f"FATAL TLS/SSL error: {atype.name}", msg)


def build_record(content_type: ContentType, body: bytes) -> bytes:
    """
    Builds a TLS/SSL record. Does not alter the body (see specialized functions), instead 
    only adding the header containing Content Type, Legacy Version, and Length, with `body` starting on byte 5.

    https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record
    """
    return bytes([content_type, 0x03, 0x03]) + len(body).to_bytes(2, 'big') + body


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

    Each record should only be processed **once** by each party to maintain sequence number.
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

        self.seq = 0

    def build_encrypted_record(self, content_type: ContentType, body: bytes) -> bytes:
        """
        Builds a TLS/SSL record for the main part of communication, after handshake.

        Parameters
        ----
        - `content_type` - the content type (Should be `Application` or `Alert`)
        - `body` - the data to be sent.

        Throws
        ----
        - Potentially some error if block size is incorrect.
        """
        mac_value = self.MAC(self.seq.to_bytes(8, 'big') + body)
        plaintext = body + mac_value
        pad_len = self.block_size - \
            ((len(plaintext) + 1) % self.block_size) + 1
        plaintext += b'a' * (pad_len - 1) + pad_len.to_bytes(1, 'big')
        # print(f"s{self.seq}: {plaintext.hex(';')}", flush=True)
        # Note that there will always be at least one byte of 'pad' since we will always have the pad length byte.

        self.seq += 1
        ciphertext = self.encryptor(plaintext)
        return build_record(content_type, ciphertext)

    def build_app_record(self, body: bytes) -> bytes:
        """
        Builds a TLS/SSL application record for the main part of communication, after handshake.

        https://en.wikipedia.org/wiki/Transport_Layer_Security#Application_protocol

        Parameters
        ----
        - `body` - the data to be sent.

        Throws
        ----
        - Potentially some error if block size is incorrect.
        """
        return self.build_encrypted_record(ContentType.Application, body)

    def build_alert_record(self, level: AlertLevel, alert_type: AlertType) -> bytes:
        """
        Builds a TLS/SSL alert record for after the handshake.

        https://en.wikipedia.org/wiki/Transport_Layer_Security#Alert_protocol

        Parameters
        ----
        - `level` - the alert level (WARNING or FATAL)
        - `alert_type` - the alert type description.

        Throws
        ----
        - Potentially some error if block size is incorrect.
        """
        return self.build_encrypted_record(ContentType.Alert, bytes([level, alert_type]))

    def open_encrypted_record(self, content: bytes) -> bytes:
        """
        Decrypts and verifies the body of an encrypted TLS/SSL record (should be application or alert).

        Parameters
        ----
        - `content` - the encrypted body of a TLS/SSL record, **excluding** the header.

        Throws
        ----
        - `SSLError: (FATAL, BadMAC)` if verification fails.
        - `ValueError` if `len(content)` is not a multiple of block length.
        - Potentially some other error if block length is incorrect.

        Returns
        ----
        The message. Does **not** include MAC, padding, or anything else.
        """
        if len(content) % self.block_size != 0:
            raise ValueError(
                "TLS/SSL record content length must be a multiple of the block length.")

        plaintext = self.decryptor(content)
        # print(f"r{self.seq}: {plaintext.hex(';')}", flush=True)
        pad_len: int = plaintext[-1]
        if pad_len <= 0 or 16 <= pad_len:
            raise SSLError(AlertType.DecodeError,
                           "Invalid padding length in decrypted message.")
        # Note that there will always be at least one byte of 'pad' since we will always have the pad length byte.
        plaintext = plaintext[:-pad_len]
        message = plaintext[:-self.mac_length]
        mac_calculated = self.MAC(self.seq.to_bytes(8, 'big') + message)
        mac_value = plaintext[-self.mac_length:]
        if mac_value != mac_calculated:
            self.seq += 1
            raise SSLError(AlertType.BadMAC, f"seq{self.seq}")
        self.seq += 1

        return message

    def open_alert_record(self, content: bytes) -> tuple[AlertLevel, AlertType]:
        """
        Decrypts and verifies the body of an encrypted TLS/SSL alert record.

        Parameters
        ----
        - `content` - the encrypted body of a TLS/SSL alert record, **excluding** the header.

        Throws
        ----
        - `SSLError: (FATAL, BadMAC)` if verification fails.
        - `ValueError` if `len(content)` is not a multiple of block length.
        - Potentially some other error if block length is incorrect.

        Returns
        ----
        A tuple with the contained alert level and alert type description.
        """
        alert = self.open_encrypted_record(content)
        if len(alert) != 2:
            raise RuntimeError("Alert record has invalid length.")
        return (AlertLevel(alert[0]), AlertType(alert[1]))
