
from ssl_handshake import *

def fixedRandom(bits):
    b = bytes(31)
    b += (0xaa).to_bytes()
    return b

if __name__ == "__main__":
    computedKey = KeyShareEntry(SupportedGroups.ffdhe2048, 57)
    hello = ClientHello()
    hello.populate(computedKey, fixedRandom)

    example = 0x01000042030300000000000000000000000000000000000000000000000000000000000000aa0100000213a101000016002b00020304000d000400020201000a000400020100.to_bytes(70, 'big')
    hello2 = ClientHello()
    hello2.unmarshal(example)
    
    testIn = ClientHello()
    testOut = ClientHello()

    testIn.populate(computedKey, fixedRandom)
    testOut.unmarshal(testIn.marshal())

    assert(testOut.marshal() == testIn.marshal())
