
from ssl_handshake import *

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
