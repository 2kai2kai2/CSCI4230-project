import shared.rpi_ssl as ssl
import shared.tls_handshake as handshake
import shared.keygen as keygen
from io import BytesIO
from os import urandom

import shared.rpi_hash as rpi_hash
import cpp

def server_handle_handshake(rfile: BytesIO, wfile: BytesIO) -> ssl.Session:
    # We first wait for the ClientHello message
    hs = handshake.Handshake()
    header = rfile.read(4)
    ok = hs.unmarshal(header)
    if not ok:
        return None
    if hs.msg_type == handshake.HandshakeType.client_hello:
        client_hello = handshake.ClientHello()
        rest = rfile.read(hs.msg_length)
        data = header + rest
        client_hello.unmarshal(data)

        # Get the key_share extension from the client
        key_share = None
        for e in client_hello.extensions:
            if e.extension_type == handshake.ExtensionType.key_share:
                key_share = e
                break
        if key_share == None:
            print("[FATAL] failed to find key_share extension.")
            return None
        key_share_dh_y_value = handshake.KeyShareEntry()
        key_share_dh_y_value.fromData(key_share.extension_data)

        if key_share_dh_y_value.group == handshake.SupportedGroups.ffdhe8192:
            generator = keygen.ffdhe8192
        else:
            print("[FATAL] unsupported supported group sent by client")
            return None

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
        IV = ((secret & ((0xffff) << (generator.len_bytes - 12) * 8)) >> ((generator.len_bytes - 8)*8)).to_bytes(16, 'big')

        # Response with a corresponding ServerHello message
        response = handshake.ServerHello()
        response.populate(client_hello, client_hello.cipher_suites[0], computedKeyPart)
        wfile.write(response.marshal())
    else:
        # If we didn't get a ClientHello message, abort.
        # todo:: wtf is error handling.
        return None

    return ssl.Session(
        lambda x: cpp.encrypt_cbc(x, key, IV),
        lambda x: cpp.decrypt_cbc(x, key, IV),
        16,
        lambda x: rpi_hash.HMAC(x, key, (rpi_hash.SHA384, 48)),
        48
    )

def client_handle_handshake(rfile: BytesIO, wfile: BytesIO) -> ssl.Session:
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
    ok = hs.unmarshal(header)
    if not ok: 
        print("[FATAL] failed to unmarshal received packet!", header.hex())
        return None
    # Figure out what kind of packet we've received
    if hs.msg_type != handshake.HandshakeType.server_hello:
        print("[FATAL] Received unexpected packet:", str(hs), header) 
        return None
    # We got back a server hello
    rest = rfile.read(hs.msg_length)
    packet = header + rest
    server_hello = handshake.ServerHello()
    server_hello.unmarshal(packet)
    # Now we need to inspect the packet to discover what keygen algorithm
    # we are using.
    # Find the key_share extension 
    ex = server_hello.extensions
    key_share = None
    for e in ex:
        if e.extension_type == handshake.ExtensionType.key_share:
            key_share = e
            break
    if key_share == None:
        print("[FATAL] failed to find key_share extension returned.")
        return None
    key_share_dh_y_value = handshake.KeyShareEntry()
    key_share_dh_y_value.fromData(key_share.extension_data)
    exchanged = int.from_bytes(key_share_dh_y_value.key_exchange, 'big')
    secret = generator.compute_secret(exchanged, secret_value)
    key = (secret & 0xffffffff).to_bytes(32, 'big')
    IV = ((secret & ((0xffff) << (generator.len_bytes - 12) * 8)) >> ((generator.len_bytes - 8)*8)).to_bytes(16, 'big')

    # session: ssl.Session = ...  # placeholder
    session = ssl.Session(
        lambda x: cpp.encrypt_cbc(x, key, IV),
        lambda x: cpp.decrypt_cbc(x, key, IV),
        16,
        lambda x: rpi_hash.HMAC(x, key, (rpi_hash.SHA384, 48)),
        48
    )
    return session