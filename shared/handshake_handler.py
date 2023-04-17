import shared.rpi_ssl as ssl
import shared.tls_handshake as handshake
import shared.keygen as keygen
from io import BytesIO
from os import urandom

import shared.rpi_hash as rpi_hash
import cpp

def gen_hash_input(to_sign: bytes, is_server: bool = True):
    # The digital signature is then computed over the concatenation of:
    #    -  A string that consists of octet 32 (0x20) repeated 64 times
    full = bytes([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20])
    #    -  The context string
    if is_server:
        full = full + bytes("TLS 1.3, server CertificateVerify")
    else:
        full = full + bytes("TLS 1.3, client CertificateVerify")
    #    -  A single 0 byte which serves as the separator
    full = full + bytes([0])
    #    -  The content to be signed
    full = full + to_sign
    return full

def server_handle_handshake(rfile: BytesIO, wfile: BytesIO, info) -> ssl.Session:
    local_private = info["server_private"]
    local_public = info["server_public"]
    remote_public = info["client_public"]
    """
    Handles the handshake from the server side, temporarily taking control of the buffers.

    Returns
    ----
    A valid SSL session with the client

    Throws
    ----
       - `SSLError` if anything went wrong.
    """
    # We first wait for the ClientHello message
    hs = handshake.Handshake()
    header = rfile.read(4)
    hs.unmarshal(header)
    if hs.msg_type != handshake.HandshakeType.client_hello:
        raise ssl.SSLError(ssl.AlertType.UnexpectedMsg, "Recieved unexpected message type (should have been client_hello)")
    client_hello = handshake.ClientHello()
    rest = rfile.read(hs.msg_length)
    data = header + rest
    client_hello.unmarshal(data)

    # Get the key_share extension from the client
    key_share = handshake.FindExtension(client_hello.extensions, handshake.ExtensionType.key_share)
    if key_share == None:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Failed to find key_share extension.")
    key_share_dh_y_value = handshake.KeyShareEntry()
    key_share_dh_y_value.fromData(key_share.extension_data)

    if key_share_dh_y_value.group == handshake.SupportedGroups.ffdhe8192:
        generator = keygen.ffdhe8192
    else:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Unsupported supported group sent by client.")

    # Need to decide on a secret
    secret_value = int.from_bytes(urandom(generator.len_bytes), 'big')
    share = generator.compute_dh_Y(secret_value)
    computedKeyPart = handshake.KeyShareEntry(
        handshake.SupportedGroups.ffdhe8192,
        share.to_bytes(generator.len_bytes, 'big')
    )

    exchanged = int.from_bytes(key_share_dh_y_value.key_exchange, 'big')
    secret = generator.compute_secret(exchanged, secret_value)
    key = (secret & 0xffffffff).to_bytes(32, 'big')
    IV = ((secret & ((0xffff) << (generator.len_bytes - 12) * 8))
          >> ((generator.len_bytes - 8)*8)).to_bytes(16, 'big')

    # Respond with a corresponding ServerHello message
    response = handshake.ServerHello()
    response.populate(
        client_hello, client_hello.cipher_suites[0], computedKeyPart)
    wfile.write(response.marshal())

    return ssl.Session(
        lambda x: cpp.encrypt_cbc(x, key, IV),
        lambda x: cpp.decrypt_cbc(x, key, IV),
        16,
        lambda x: rpi_hash.HMAC(x, key, (rpi_hash.SHA384, 48)),
        48
    )


def client_handle_handshake(rfile: BytesIO, wfile: BytesIO, info) -> ssl.Session:
    local_private = info["client_private"]
    local_public = info["client_public"]
    remote_public = info["server_public"]
    """
    Handles the handshake from the server side, temporarily taking control of the buffers.
    
    Returns
    ----
    A valid SSL session with the server

    Throws
    ----
       - `SSLError` if anything went wrong.
    """
    # We need to setup some crypto information before we send the Hello.
    # We will attempt ffdhe8192 first.
    generator = keygen.ffdhe8192
    secret_value = int.from_bytes(urandom(generator.len_bytes), 'big')
    share = generator.compute_dh_Y(secret_value)
    computedKeyPart = handshake.KeyShareEntry(
        handshake.SupportedGroups.ffdhe8192,
        share.to_bytes(generator.len_bytes, 'big')
    )

    # First, send a ClientHello message.
    hello = handshake.ClientHello()
    hello.populate(computedKeyPart)
    sent = wfile.write(hello.marshal())

    # Now we receive either a 'HelloRetryRequest' or a 'ServerHello'
    # Note that both of these messages will present as a 'ServerHello'
    hs = handshake.Handshake()
    header = rfile.read(4)
    hs.unmarshal(header)
    # Figure out what kind of packet we've received
    if hs.msg_type != handshake.HandshakeType.server_hello:
        raise ssl.SSLError(ssl.AlertType.UnexpectedMsg, "Recieved unexpected message type (should have been server_hello)")
    # We got back a server hello
    rest = rfile.read(hs.msg_length)
    packet = header + rest
    server_hello = handshake.ServerHello()
    server_hello.unmarshal(packet)
    # Now we need to inspect the packet to discover what keygen algorithm
    # we are using.
    # Find the key_share extension
    key_share = handshake.FindExtension(server_hello.extensions, handshake.ExtensionType.key_share)
    if key_share == None:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Failed to find key_share extension that was returned.")
    key_share_dh_y_value = handshake.KeyShareEntry()
    key_share_dh_y_value.fromData(key_share.extension_data)
    exchanged = int.from_bytes(key_share_dh_y_value.key_exchange, 'big')
    secret = generator.compute_secret(exchanged, secret_value)
    key = (secret & 0xffffffff).to_bytes(32, 'big')
    IV = ((secret & ((0xffff) << (generator.len_bytes - 12) * 8))
          >> ((generator.len_bytes - 8)*8)).to_bytes(16, 'big')

    session = ssl.Session(
        lambda x: cpp.encrypt_cbc(x, key, IV),
        lambda x: cpp.decrypt_cbc(x, key, IV),
        16,
        lambda x: rpi_hash.HMAC(x, key, (rpi_hash.SHA384, 48)),
        48
    )
    return session
