import shared.rpi_ssl as ssl
import shared.tls_handshake as handshake
import shared.keygen as keygen
from io import BytesIO
from os import urandom
from typing import Tuple

import shared.rpi_hash as rpi_hash
import cpp

sig_alg = rpi_hash.SHA256

def gen_hash_input(to_sign: bytes, is_server: bool = True) -> bytes:
    # The digital signature is then computed over the concatenation of:
    #    -  A string that consists of octet 32 (0x20) repeated 64 times
    full = bytes([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20])
    #    -  The context string
    if is_server:
        full = full + bytes("TLS 1.3, server CertificateVerify", "utf-8")
    else:
        full = full + bytes("TLS 1.3, client CertificateVerify", "utf-8")
    #    -  A single 0 byte which serves as the separator
    full = full + bytes([0])
    #    -  The content to be signed
    full = full + to_sign
    return full

def from_shared_secret(secret : int) -> Tuple[bytes, bytes]:
    lb = secret.bit_length()
    key = (secret & 2**32).to_bytes(32, 'big')
    mask = (2 ** lb) - (2 ** (lb - 16)) - 1
    IV = (secret & mask) >> (lb - 16)
    return key, IV.to_bytes(16, 'big')

def server_handle_handshake(rfile: BytesIO, wfile: BytesIO, info) -> ssl.Session:
    private = info["server_private"]
    public = info["server_public"]
    modulus = info["server_modulus"]
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

    transcript = data

    # Get the key_share extension from the client
    key_share = handshake.FindExtension(client_hello.extensions, handshake.ExtensionType.key_share)
    if key_share == None:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Failed to find key_share extension.")
    key_share_dh_y_value = handshake.KeyShareEntry()
    key_share_dh_y_value.fromData(key_share.extension_data)

    if key_share_dh_y_value.group == handshake.SupportedGroups.ffdhe8192:
        generator = keygen.ffdhe2048
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
    key, IV = from_shared_secret(secret)

    # Respond with a corresponding ServerHello message
    response = handshake.ServerHello()
    response.populate(
        client_hello, client_hello.cipher_suites[0], computedKeyPart)

    to_send = response.marshal()
    wfile.write(to_send)
    transcript += to_send

    # Send a Certificate message to communicate the public key
    cert = handshake.Certificate()
    cert.populate(public, modulus)

    to_send = cert.marshal()
    wfile.write(to_send)
    transcript += to_send

    # Send the Certificate Verify on the running transcript
    # Make sure the client supports the hash we want to use
    signature_algorithms = handshake.FindExtension(client_hello.extensions, handshake.ExtensionType.signature_algorithms)
    if signature_algorithms == None:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Failed to find signature_algorithms extension.")
    signature_algorithm_list, _ = handshake.unmarshal_list(signature_algorithms.extension_data, 2, 2)
    signature_algorithm_list = [int.from_bytes(x) for x in signature_algorithm_list]
    if not handshake.SignatureAlgorithms.rsa_pkcs1_sha256 in signature_algorithm_list:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Client does not support desired signature algorithm.")

    transcript_hash = sig_alg(transcript)
    to_hash = gen_hash_input(transcript_hash)
    found_signature = int.from_bytes(sig_alg(to_hash))
    encrypted_signature = pow(found_signature, private, modulus)
    cert_verify = handshake.CertificateVerify()
    cert_verify.populate(handshake.SignatureScheme.rsa_pkcs1_sha256, encrypted_signature)

    to_send = cert_verify.marshal()
    wfile.write(to_send)
    transcript += to_send

    # Process client certificate
    header = rfile.read(4)
    hs.unmarshal(header)
    if hs.msg_type != handshake.HandshakeType.certificate:
        raise ssl.SSLError(ssl.AlertType.UnexpectedMsg, "Recieved unexpected message type (should have been certificate)")
    rest = rfile.read(hs.msg_length)
    packet = header + rest
    client_cert = handshake.Certificate()
    client_cert.unmarshal(packet)
    transcript += packet
    
    client_public_key = client_cert.public_key
    client_modulus = client_cert.modulus

    # Now, process the client verify
    header = rfile.read(4)
    hs.unmarshal(header)
    if hs.msg_type != handshake.HandshakeType.certificate_verify:
        raise ssl.SSLError(ssl.AlertType.UnexpectedMsg, "Recieved unexpected message type (should have been certificate_verify)")
    rest = rfile.read(hs.msg_length)
    packet = header + rest
    cert_verify = handshake.CertificateVerify()
    cert_verify.unmarshal(packet)
    # Let's decrypt the signature 
    encrypted_signature = pow(cert_verify.signature, client_public_key, client_modulus)
    decrypted_signature = encrypted_signature
    # Now let's find the signature of the transcript independently
    if cert_verify.signatureScheme != handshake.SignatureScheme.rsa_pkcs1_sha256:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Client does not use a supported signature algorithm.")
    transcript_hash = sig_alg(transcript)
    to_hash = gen_hash_input(transcript_hash)
    found_signature = int.from_bytes(sig_alg(to_hash))
    if found_signature != decrypted_signature:
        raise ssl.SSLError(ssl.AlertType.BadCertificate, "Decrypted signature did not match expectation")

    return ssl.Session(
        lambda x: cpp.encrypt_cbc(x, key, IV),
        lambda x: cpp.decrypt_cbc(x, key, IV),
        16,
        lambda x: rpi_hash.HMAC(x, key, (rpi_hash.SHA384, 48)),
        48
    )


def client_handle_handshake(rfile: BytesIO, wfile: BytesIO, info) -> ssl.Session:
    private = info["client_private"]
    public = info["client_public"]
    modulus = info["client_modulus"]
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
    generator = keygen.ffdhe2048
    secret_value = int.from_bytes(urandom(generator.len_bytes), 'big')
    share = generator.compute_dh_Y(secret_value)
    computedKeyPart = handshake.KeyShareEntry(
        handshake.SupportedGroups.ffdhe8192,
        share.to_bytes(generator.len_bytes, 'big')
    )

    # First, send a ClientHello message.
    hello = handshake.ClientHello()
    hello.populate(computedKeyPart)

    to_send = hello.marshal()
    wfile.write(to_send)
    transcript = to_send

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

    transcript += packet

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
    key, IV = from_shared_secret(secret)

    # Process certificate
    header = rfile.read(4)
    hs.unmarshal(header)
    if hs.msg_type != handshake.HandshakeType.certificate:
        raise ssl.SSLError(ssl.AlertType.UnexpectedMsg, "Recieved unexpected message type (should have been certificate)")
    rest = rfile.read(hs.msg_length)
    packet = header + rest
    cert = handshake.Certificate()
    cert.unmarshal(packet)

    transcript += packet

    server_public_key = cert.public_key
    server_modulus = cert.modulus

    # Wait for the server to send their CertificateVerify message!
    header = rfile.read(4)
    hs.unmarshal(header)
    if hs.msg_type != handshake.HandshakeType.certificate_verify:
        raise ssl.SSLError(ssl.AlertType.UnexpectedMsg, "Recieved unexpected message type (should have been certificate_verify)")
    rest = rfile.read(hs.msg_length)
    packet = header + rest
    cert_verify = handshake.CertificateVerify()
    cert_verify.unmarshal(packet)
    # Let's decrypt the signature 
    encrypted_signature = pow(cert_verify.signature, server_public_key, server_modulus)
    decrypted_signature = encrypted_signature
    # Now let's find the signature of the transcript independently
    if cert_verify.signatureScheme != handshake.SignatureScheme.rsa_pkcs1_sha256:
        raise ssl.SSLError(ssl.AlertType.HandshakeFailure, "Server does not use a supported signature algorithm.")
    transcript_hash = sig_alg(transcript)
    to_hash = gen_hash_input(transcript_hash)
    found_signature = int.from_bytes(sig_alg(to_hash))
    if found_signature != decrypted_signature:
        raise ssl.SSLError(ssl.AlertType.BadCertificate, "Decrypted signature did not match expectation")

    transcript += packet

    # Send our own certificate!
    my_cert = handshake.Certificate()
    my_cert.populate(public, modulus)

    to_send = my_cert.marshal()
    wfile.write(to_send)
    transcript += to_send

    # Send our certificate verification
    my_transcript_hash = sig_alg(transcript)
    my_to_hash = gen_hash_input(my_transcript_hash)
    my_found_signature = int.from_bytes(sig_alg(my_to_hash))
    my_encrypted_signature = pow(my_found_signature, private, modulus)
    cert_verify = handshake.CertificateVerify()
    cert_verify.populate(handshake.SignatureScheme.rsa_pkcs1_sha256, my_encrypted_signature)

    to_send = cert_verify.marshal()
    wfile.write(to_send)

    session = ssl.Session(
        lambda x: cpp.encrypt_cbc(x, key, IV),
        lambda x: cpp.decrypt_cbc(x, key, IV),
        16,
        lambda x: rpi_hash.HMAC(x, key, (rpi_hash.SHA384, 48)),
        48
    )
    return session
