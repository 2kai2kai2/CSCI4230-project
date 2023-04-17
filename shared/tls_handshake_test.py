
from tls_handshake import *

def fixedRandom(bits):
    b = bytes(17)
    for i in range(0x1, 0xf + 1):
        b += (0x11 * i).to_bytes()
    return b

if __name__ == "__main__":
    computedKey = KeyShareEntry(SupportedGroups.ffdhe2048, (57).to_bytes(1, 'big'))
    hello = ClientHello()
    hello.populate(computedKey, fixedRandom)
    
    # print(hello.marshal().hex())

    # ------------------------------
    
    testIn = ClientHello()
    testOut = ClientHello()

    testIn.populate(computedKey, fixedRandom)
    data = testIn.marshal()
    assert(testOut.unmarshal(data))
    assert(testOut.marshal() == testIn.marshal())

    # ------------------------------

    # Set up a ClientHello message for the ServerHello
    example = 0x01000042030300000000000000000000000000000000000000000000000000000000000000aa0100000213a101000016002b00020304000d000400020201000a000400020100.to_bytes(70, 'big')
    client = ClientHello()
    client.unmarshal(example)

    server = ServerHello()
    server.populate(client, client.cipher_suites[0], computedKey, fixedRandom)

    server_example = 0x0200002f030300000000000000000000000000000000000000000000000000000000000000aa010013a1000006002b00020304.to_bytes(51, 'big')
    server2 = ServerHello()
    assert(server2.unmarshal(server_example))
    assert(server2.unmarshal(server.marshal()))
    assert(server2.marshal() == server.marshal())

    # ------------------------------

    ee = EncryptedExtensions()
    ee2 = EncryptedExtensions()

    example = [
        MakeExtension(ExtensionType.server_name, bytes("Hello, world!", 'utf-8'))
    ]

    ee.populate(example)
    # print(ee.marshal().hex())
    ee2.unmarshal(ee.marshal())
    assert(ee2.marshal() == ee.marshal())

    example = [
        MakeExtension(ExtensionType.server_name, bytes("Hello, world!", 'utf-8')),
        MakeExtension(ExtensionType.supported_groups, marshal_list_of_ints([
            SupportedGroups.ffdhe2048
        ], 2, 2))
    ]

    ee.populate(example)
    ee2.unmarshal(ee.marshal())
    assert(ee2.marshal() == ee.marshal())

    # ------------------------------
    # Small example key
    c_pub = 65537
    c_pr = 0x6a94682a9c16679fdaf04fdf6d9a618d86fea7328c11210b727514dfcc577251
    c_p = 0x00d573da589539e04ca947cffbccd89be5
    c_q = 0x00d3ba475c16b994601bed32d8bdd61b17

    cert = Certificate()
    cert.populate(c_pub)
    assert(cert.validate(c_pr, c_p, c_q))

    # ------------------------------
    cert_verify = CertificateVerify()
    cert_verify.populate(SignatureScheme.rsa_pkcs1_sha384, 37)
    cert_verify2 = CertificateVerify()
    cert_verify2.unmarshal(cert_verify.marshal())
    assert(cert_verify.marshal() == cert_verify2.marshal())


