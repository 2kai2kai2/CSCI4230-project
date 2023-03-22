
# urandom generates cryptographically-secure random numbers as per
# https://docs.python.org/3/library/os.html 
# "This function returns random bytes from an OS-specific randomness source. 
# The returned data should be unpredictable enough for cryptographic applications, 
# though its exact quality depends on the OS implementation."
from os import urandom
from enum import IntEnum
from typing import Union

# We define our own cipher with a unique custom value
TLS_AES_128_SHA1 = 0x13A1

def marshal_list_of_bytes(arr: list[bytes], elementLength: int = 1, maxLengthInBytes: int = 2) -> bytes:
    # Encode the length of objects
    ret = (len(arr) * elementLength).to_bytes(maxLengthInBytes, 'big')
    # Encode every object sequenially
    for el in arr:
        assert(len(el) == elementLength)
        ret += el
    return ret

def marshal_list_of_ints(arr: list[int], elementLength: int = 1, maxLengthInBytes: int = 2) -> bytes:
    # Encode the length of objects
    ret = (len(arr) * elementLength).to_bytes(maxLengthInBytes, 'big')
    # Encode every object sequenially
    for el in arr:
        ret += el.to_bytes(elementLength, "big")
    return ret

class HandshakeType(IntEnum):
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4
    client_hello = 1
    server_hello = 2

class Handshake:
    def __init__(self, msg_type: int):
        # Must be a supported handshake type
        assert(msg_type in HandshakeType._value2member_map_) 
        self.msg_type = msg_type

    def __str__(self):
        if self.msg_type == HandshakeType.client_hello: return "Client Hello"
        if self.msg_type == HandshakeType.server_hello: return "Server Hello"

    def marshal(self, messageLength) -> bytes:
        # Message needs to fit in a uint-24
        assert(messageLength > 0 and messageLength < 2**24)
        ret = bytes([self.msg_type])
        ret += messageLength.to_bytes(3, 'big')
        return ret

class ExtensionType(IntEnum):
    # A full list of extensions can be found in RFC 8446, Section 4.2:
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
    supported_groups = 10
    signature_algorithms = 13
    supported_versions = 43
    key_share = 51

class SignatureAlgorithms(IntEnum):
    # A full list of signature algorithms is in RFC 8446, Section 4.2.3:
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
    rsa_pkcs1_sha1 = 0x0201

class SupportedGroups(IntEnum):
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
    ffdhe2048 = 0x0100

class KeyShareEntry:
    def __init__(self, group: int, key_exchange):
        # Make sure we were given a valid group
        assert(group in SupportedGroups._value2member_map_)
        self.group = group
        self.key_exchange = key_exchange

class KeyShare_ClientShares:
    def __init__(self, entries: list[KeyShareEntry]):
        self.entries=entries

class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1

class Extension:
    def __init__(self, extension_type: int, extension_data: bytes):
        self.extension_type = extension_type
        self.extension_data = extension_data

    def marshal(self) -> bytes:
        ret = self.extension_type.to_bytes(2, 'big')
        # include the length of the data
        ret += len(self.extension_data).to_bytes(2, 'big')
        ret += self.extension_data
        return ret

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
    extensions = {
        # ExtensionType.key_share: KeyShare_ClientShares()
    }
    extensions = [
        Extension(ExtensionType.supported_versions, 0x0304.to_bytes(2, 'big')),
        Extension(ExtensionType.signature_algorithms, marshal_list_of_ints([
            SignatureAlgorithms.rsa_pkcs1_sha1
        ], 2, 2)),
        #Certificate Authorities is not required
        # Our client will send it's own key_share material to save on an extra round trip with 
        # the server. The server will inspect this value and ensure it is satisfied with the choice.
        # todo:: add server-side checking on key_share information
        Extension(ExtensionType.supported_groups, marshal_list_of_ints([
            SupportedGroups.ffdhe2048
        ], 2, 2)), # p = 2048
    ]
    handshake = Handshake(HandshakeType.client_hello)

    def __init__(self, DHKeyShare: KeyShareEntry):
        # Create 32 random bytes for the 'random' field (used as a Nonce)
        self.random = urandom(32)
        # Make sure the keyshare we have works with the hard-coded hello parameters
        # todo:: change this when more algorithms are implemented
        assert(DHKeyShare.group == SupportedGroups.ffdhe2048)
        # Set the client shares information
        # self.extensions[ExtensionType.key_share] = KeyShare_ClientShares([DHKeyShare])

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
        ret += len(encoded_extensions).to_bytes(2, 'big')
        ret += encoded_extensions
        # Finally we can push the handshake header info as 
        # we know the length of the rest of the message
        prefix = self.handshake.marshal(len(ret))
        ret = prefix + ret
        return ret

if __name__ == "__main__":
    computedKey = KeyShareEntry(SupportedGroups.ffdhe2048, 57)
    hello = ClientHello(computedKey)
    print(hello.marshal().hex())
