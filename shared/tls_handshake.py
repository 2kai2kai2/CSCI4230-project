# urandom generates cryptographically-secure random numbers as per
# https://docs.python.org/3/library/os.html 
# "This function returns random bytes from an OS-specific randomness source. 
# The returned data should be unpredictable enough for cryptographic applications, 
# though its exact quality depends on the OS implementation."
from os import urandom
from enum import IntEnum
from typing import Union, Callable
import shared.rpi_ssl as ssl

# import rpi_ssl as ssl

# We define our own cipher with a unique custom value
TLS_AES_128_SHA1 = 0x13A1


def marshal_list_of_bytes(arr: list[bytes], elementLength: int = 1, maxLengthInBytes: int = 2) -> bytes:
    # Encode the length of objects
    ret = (len(arr) * elementLength).to_bytes(maxLengthInBytes, 'big')
    # Encode every object sequenially
    for el in arr:
        if len(el) != elementLength:
            raise ssl.SSLError(ssl.AlertType.InternalError, "Invalid item size while marshalling bytes.")
        ret += el
    return ret


def marshal_list_of_ints(arr: list[int], elementLength: int = 1, maxLengthInBytes: int = 2) -> bytes:
    # Encode the length of objects
    ret = (len(arr) * elementLength).to_bytes(maxLengthInBytes, 'big')
    # Encode every object sequenially
    for el in arr:
        ret += el.to_bytes(elementLength, "big")
    return ret


def marshal_list_of_objects(arr: list[int], elementLength: int = 1, maxLengthInBytes: int = 2) -> bytes:
    # Encode the length of objects
    ret = (len(arr)).to_bytes(maxLengthInBytes, 'big')
    # Encode every object sequenially
    for el in arr:
        ret += el.to_bytes(elementLength, "big")
    return ret


def unmarshal_list(msg: bytes, elementLength: int = 1, lengthFieldSize: int = 2, start: int = 0) -> Union[list, int]:
    count = int.from_bytes(msg[start:start + lengthFieldSize], 'big')
    ret = []
    for i in range(count // elementLength):
        s = start + lengthFieldSize + i * elementLength
        ret.append(msg[s:s + elementLength])
    return ret, lengthFieldSize + count


class HandshakeType(IntEnum):
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4
    NONE = -1
    client_hello = 1
    server_hello = 2
    encrypted_extensions = 8
    certificate = 11
    certificate_verify = 15
    finished = 20


class Handshake:
    def __init__(self, msg_type: int = -1, msg_length: int = 0):
        # Must be a supported handshake type
        if msg_type not in HandshakeType._value2member_map_:
            raise ssl.SSLError(ssl.AlertType.InternalError, "Unsupported handshake type.")
        self.msg_type = msg_type
        self.msg_length = msg_length

    def __str__(self):
        if self.msg_type == HandshakeType.client_hello: return "ClientHello"
        if self.msg_type == HandshakeType.server_hello: return "ServerHello"
        if self.msg_type == HandshakeType.encrypted_extensions: return "EncryptedExtensions"
        if self.msg_type == HandshakeType.certificate: return "Certificate"
        if self.msg_type == HandshakeType.certificate_verify: return "CertificateVerify"
        if self.msg_type == HandshakeType.finished: return "Finished"

    def marshal(self) -> bytes:
        """
        Generic marshalling function for all handshake messages.

        Throws
        ----
           - `SSLError (FATAL, RecordOverflow)` if message cannot fit in a uint-24.
        """
        # Message needs to fit in a uint-24
        if self.msg_length <= 0 or self.msg_length >= 2 ** 24:
            raise ssl.SSLError(ssl.AlertType.RecordOverflow, "Handshake message must fit in a uint-24.")
        ret = self.msg_type.to_bytes(1, 'big')
        ret += self.msg_length.to_bytes(3, 'big')
        return ret

    def unmarshal(self, data: bytes):
        """
        Generic unmarshalling function for all handshake messages.
        Saves information to `self`.

        Throws
        ----
           - `SSLError (FATAL, DecodeError)` if packet has insufficient length.
        """
        if len(data) < 4:
            raise ssl.SSLError(ssl.AlertType.DecodeError, "Failed to unmarshal packet" + data.hex())
        # First byte should be the message type
        self.msg_type = data[0]
        # Then we have the length in the next three
        self.msg_length = int.from_bytes(data[1:4], 'big')


class Alert:
    def populate(self, alert_level: ssl.AlertLevel, alert_description: ssl.AlertType):
        self.alert_level = alert_level
        self.alert_description = alert_description


class ExtensionType(IntEnum):
    # A full list of extensions can be found in RFC 8446, Section 4.2:
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
    supported_groups = 10
    signature_algorithms = 13
    supported_versions = 43
    key_share = 51
    server_name = 0
    server_certificate_type = 20


class SignatureScheme(IntEnum):
    # This replaces SignatureAlgorithms, which is the TLS 1.2 standard.
    # That being said, SignatureAlgorithms has the same information
    rsa_pkcs1_sha384 = 0x0501


class SignatureAlgorithms(IntEnum):
    # A full list of signature algorithms is in RFC 8446, Section 4.2.3:
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha1 = 0x0201


class SupportedGroups(IntEnum):
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
    ffdhe2048 = 0x0100
    ffdhe8192 = 0x0104
    NONE = -1


class KeyShareEntry:
    def __init__(self, group: int = SupportedGroups.NONE, key_exchange: bytes = bytes(0)):
        # Make sure we were given a valid group
        if group not in SupportedGroups._value2member_map_:
            raise ssl.SSLError(ssl.AlertType.InternalError, "Invalid group type.")
        self.group = group
        self.key_exchange = key_exchange

    def toData(self) -> bytes:
        if self.group == SupportedGroups.NONE:
            raise ssl.SSLError(ssl.AlertType.InternalError, "Group type cannot be NONE.")
        if len(self.key_exchange) == 0:
            raise ssl.SSLError(ssl.AlertType.InternalError, "key_exchange cannot be empty.")
        return self.group.to_bytes(2, 'big') + len(self.key_exchange).to_bytes(2, 'big') + self.key_exchange

    def fromData(self, data) -> int:
        self.group = int.from_bytes(data[:2], 'big')
        key_exchange_len = int.from_bytes(data[2:4], 'big')
        self.key_exchange = data[4:4 + key_exchange_len]
        return 4 + key_exchange_len


class KeyShare_ClientShares:
    def __init__(self, entries: list[KeyShareEntry]):
        self.entries = entries


class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1


class Extension:
    def populate(self, extension_type: int, extension_data: bytes):
        self.extension_type = extension_type
        self.extension_data = extension_data

    def marshal(self) -> bytes:
        ret = self.extension_type.to_bytes(2, 'big')
        # include the length of the data
        ret += len(self.extension_data).to_bytes(2, 'big')
        ret += self.extension_data
        return ret

    def unmarshal(self, data: bytes, start: int) -> int:
        self.extension_type = int.from_bytes(data[start:start + 2], 'big')
        # include the length of the data
        length = int.from_bytes(data[start + 2:start + 4], 'big')
        self.extension_data = data[start + 4:start + length + 4]
        return length + 4


def MakeExtension(et, ed) -> Extension:
    ex = Extension()
    ex.populate(et, ed)
    return ex


def FindExtension(extensions: list[Extension], desired: ExtensionType) -> Union[Extension, None]:
    for e in extensions:
        if e.extension_type == desired: return e
    return None


class ClientHello:
    """
    See here: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
    Note that we use no PSK systems
    """
    legacy_version = 0x0303
    # We will not support resuming cached sessions. 
    # Additionally, this implementation is not 'compatability mode' compliant.
    legacy_session_id = [bytes([0])]
    # We will used this fixed suite of ciphers. Note that the cipher
    # listed is not a valid SSL 1.3 cipher and is custom to this implementation
    cipher_suites = [TLS_AES_128_SHA1]
    # As per the spec, this must be a vector containing a single zero byte
    legacy_compression_methods = [bytes([0])]
    extensions = [
        MakeExtension(ExtensionType.supported_versions, 0x0304.to_bytes(2, 'big')),
        MakeExtension(ExtensionType.signature_algorithms, marshal_list_of_ints([
            SignatureAlgorithms.rsa_pkcs1_sha384
        ], 2, 2)),
        # Certificate Authorities is not required
        # Our client will send it's own key_share material to save on an extra round trip with 
        # the server. The server will inspect this value and ensure it is satisfied with the choice.
        # todo:: add server-side checking on key_share information
        MakeExtension(ExtensionType.supported_groups, marshal_list_of_ints([
            SupportedGroups.ffdhe2048
        ], 2, 2)),  # p = 2048
        # Our client only enables authenticating a server with raw public keys
        # MakeExtension(ExtensionType.server_certificate_type, )
    ]
    handshake = Handshake(HandshakeType.client_hello, -1)

    def populate(self, DHKeyShare: KeyShareEntry, randomFunc: Callable[[int], bytes] = urandom):
        # Create 32 random bytes for the 'random' field (used as a Nonce)
        self.random = randomFunc(32)
        # Set the client shares information
        self.extensions.append(MakeExtension(ExtensionType.key_share, DHKeyShare.toData()))

    def marshal(self) -> bytes:
        # Here is the structure of this object:
        """
        uint16 ProtocolVersion;
        opaque Random[32];
        uint8 CipherSuite[2];
        {
            ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
            Random random;
            opaque legacy_session_id<0..32>;
            CipherSuite cipher_suites<2..2^16-2>;
            opaque legacy_compression_methods<1..2^8-1>;
            Extension extensions<8..2^16-1>;
        }
        """
        ret = self.legacy_version.to_bytes(2, "big")
        ret += self.random
        ret += marshal_list_of_bytes(self.legacy_session_id, elementLength=1, maxLengthInBytes=1)
        ret += marshal_list_of_ints(self.cipher_suites, elementLength=2, maxLengthInBytes=2)
        ret += marshal_list_of_bytes(self.legacy_compression_methods, elementLength=1, maxLengthInBytes=1)
        # The extensions are more complicated because they all want to be special, special snowflakes
        encoded_extensions = bytes(0)
        for ex in self.extensions:
            encoded_extensions += ex.marshal()
        # Add the extensions to the message
        last = len(encoded_extensions).to_bytes(2, 'big')
        last += encoded_extensions
        # Finally we can push the handshake header info as 
        # we know the length of the rest of the message
        ret += last
        self.handshake.msg_length = len(ret)
        prefix = self.handshake.marshal()
        ret = prefix + ret
        return ret

    def unmarshal(self, msg: bytes):
        """
        Throws
        ----
           - `SSLError (FATAL, UnexpectedMsg)` if message type is not `client_hello`
           - Other stuff, maybe
        """
        # First we have the prefix that we can strip away
        self.handshake.unmarshal(msg)
        if self.handshake.msg_type != HandshakeType.client_hello:
            raise ssl.SSLError(ssl.AlertType.UnexpectedMsg,
                               "Recieved unexpected message type (should have been client_hello)")

        tracker = 4
        # Next 2 bytes should be legacy version information 
        self.legacy_version = int.from_bytes(msg[tracker:tracker + 2], 'big')
        tracker += 2

        # Next 32 have the random
        self.random = msg[tracker:tracker + 32]
        tracker += 32

        self.legacy_session_id, advance = unmarshal_list(msg, elementLength=1, lengthFieldSize=1, start=tracker)
        tracker += advance
        cs, advance = unmarshal_list(msg, elementLength=2, lengthFieldSize=2, start=tracker)
        self.cipher_suites = [int.from_bytes(x, 'big') for x in cs]
        tracker += advance
        self.legacy_compression_methods, advance = unmarshal_list(msg, elementLength=1, lengthFieldSize=1,
                                                                  start=tracker)
        tracker += advance

        extensionFieldLength = int.from_bytes(msg[tracker:tracker + 2], 'big')
        tracker += 2
        subtracker = 0
        self.extensions = []
        while subtracker < extensionFieldLength:
            ex = Extension()
            consumed = ex.unmarshal(msg, start=tracker + subtracker)
            subtracker += consumed
            self.extensions.append(ex)
        return True


class ServerHello:
    legacy_version = 0x0303
    random = 0

    cipher_suite = None

    extensions = [
        MakeExtension(ExtensionType.supported_versions, 0x0304.to_bytes(2, 'big')),
    ]

    handshake = Handshake(HandshakeType.server_hello, -1)

    RETRY_REQUEST = 0xCF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C.to_bytes(32, 'big')

    def __init__(self):
        self.legacy_session_id = None

    def populate(self, correspondingHello: ClientHello, selectedCipherSuite, DHKeyShare: KeyShareEntry,
                 randomFunc: Callable[[int], bytes] = urandom):
        # Create 32 random bytes for the 'random' field (used as a Nonce)
        self.random = randomFunc(32)
        self.legacy_session_id = correspondingHello.legacy_session_id
        if not selectedCipherSuite in correspondingHello.cipher_suites:
            print("[WARN] Selected Cipher Suite {}, but the corresponding ClientHello message do not offer it")
            return False
        self.cipher_suite = selectedCipherSuite
        self.extensions.append(MakeExtension(ExtensionType.key_share, DHKeyShare.toData()))
        return True

    def setRetryRequest(self):
        self.random = self.RETRY_REQUEST

    def isRetryRequest(self):
        return self.random == self.RETRY_REQUEST

    def marshal(self):
        """
        struct {
            ProtocolVersion legacy_version = 0x0303;
            Random random;
            opaque legacy_session_id_echo<0..32>;
            CipherSuite cipher_suite;
            uint8 legacy_compression_method = 0;
            Extension extensions<6..2^16-1>;
        } ServerHello;
        """
        ret = self.legacy_version.to_bytes(2, "big")
        ret += self.random
        ret += marshal_list_of_bytes(self.legacy_session_id, elementLength=1, maxLengthInBytes=1)
        ret += self.cipher_suite.to_bytes(2, "big")
        # Legacy compression method
        ret += (0).to_bytes(1, "big")
        # Encode the extensions
        encoded_extensions = bytes(0)
        for ex in self.extensions:
            encoded_extensions += ex.marshal()
        # Add the extensions to the message
        ret += len(encoded_extensions).to_bytes(2, 'big')
        ret += encoded_extensions
        # Finally we can push the handshake header info as 
        # we know the length of the rest of the message
        self.handshake.msg_length = len(ret)
        prefix = self.handshake.marshal()
        ret = prefix + ret
        return ret

    def unmarshal(self, msg: bytes) -> bool:
        """
        Throws
        ----
           - `SSLError (FATAL, UnexpectedMsg)` if message type is not `server_hello`
           - Other stuff, maybe
        """
        # First we have the prefix that we can strip away
        self.handshake.unmarshal(msg)
        if self.handshake.msg_type != HandshakeType.server_hello:
            raise ssl.SSLError(ssl.AlertType.UnexpectedMsg,
                               "Recieved unexpected message type (should have been server_hello)")

        tracker = 4
        # Next 2 bytes should be legacy version information 
        self.legacy_version = int.from_bytes(msg[tracker:tracker + 2], 'big')
        tracker += 2

        # Next 32 have the random
        self.random = msg[tracker:tracker + 32]
        tracker += 32

        self.legacy_session_id, advance = unmarshal_list(msg, elementLength=1, lengthFieldSize=1, start=tracker)
        tracker += advance
        self.cipher_suite = int.from_bytes(msg[tracker:tracker + 2], 'big')
        tracker += 2
        legacy_compression_method = int.from_bytes(msg[tracker:tracker + 1], 'big')
        tracker += 1
        if legacy_compression_method != 0:
            raise ssl.SSLError(ssl.AlertType.DecodeError, "We do not support compression.")

        extensionFieldLength = int.from_bytes(msg[tracker:tracker + 2], 'big')
        tracker += 2
        subtracker = 0
        self.extensions = []
        while subtracker < extensionFieldLength:
            ex = Extension()
            consumed = ex.unmarshal(msg, start=tracker + subtracker)
            subtracker += consumed
            self.extensions.append(ex)
        return True


class EncryptedExtensions:
    def __init__(self):
        self.handshake = Handshake(HandshakeType.encrypted_extensions, -1)
        self.extensions = []

    def populate(self, extensions: list[Extension]):
        self.extensions = extensions

    def marshal(self) -> bytes:
        # Encode the extensions
        encoded_extensions = bytes(0)
        for ex in self.extensions:
            encoded_extensions += ex.marshal()
        ret = len(encoded_extensions).to_bytes(2, 'big') + encoded_extensions
        self.handshake.msg_length = len(ret)
        prefix = self.handshake.marshal()
        return prefix + ret

    def unmarshal(self, msg: bytes):
        self.handshake.unmarshal(msg)
        if self.handshake.msg_type != HandshakeType.encrypted_extensions:
            raise ssl.SSLError(ssl.AlertType.UnexpectedMsg,
                               "Recieved unexpected message type (should have been encrypted_extensions)")
        extensionFieldLength = int.from_bytes(msg[4:6], 'big')
        subtracker = 0
        self.extensions = []
        while subtracker < extensionFieldLength:
            ex = Extension()
            consumed = ex.unmarshal(msg, start=6 + subtracker)
            subtracker += consumed
            self.extensions.append(ex)


class Certificate:
    handshake = Handshake(HandshakeType.certificate, -1)

    def __init__(self):
        self.modulus = None
        self.public_key = None

    def populate(self, public_key: int, mod: int):
        self.modulus = mod
        self.public_key = public_key

    def validate(self, private_key: int, p: int, q: int):
        lambdaN = (p - 1) * (q - 1)
        return 1 == (self.public_key * private_key) % lambdaN

    def marshal(self) -> bytes:
        ret = b"0000" + \
              (self.modulus.bit_length() // 8).to_bytes(3, "big") + \
              b"0000" + \
              self.modulus.to_bytes(self.public_key.bit_length() // 8, 'big') + \
              b"0000" + \
              (self.public_key.bit_length() // 8).to_bytes(3, "big") + \
              b"0000" + \
              self.public_key.to_bytes(self.public_key.bit_length() // 8, 'big')
        return ret

    def unmarshal(self, msg: bytes):
        modsize = int.from_bytes(msg[:3], "big")
        msg = msg[5:]
        self.modulus = int.from_bytes(msg[:modsize], "big")

        msg = msg[2:]

        keysize = int.from_bytes(msg[:3], "big")
        msg = msg[5:]
        self.public_key = int.from_bytes(msg[:keysize], "big")
