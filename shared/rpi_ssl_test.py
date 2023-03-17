import rpi_ssl as ssl
import random


def bad_encrypt(data: bytes) -> bytes:
    return bytes([x ^ 0x56 for x in data])


def bad_hash(data: bytes) -> bytes:
    out = 0
    for i in range(0, len(data), 8):
        out ^= int.from_bytes(data[i:min(i+8, len(data))], 'big')
    return out.to_bytes(8, 'big')


basic_session = ssl.Session(bad_encrypt, bad_encrypt, 16, bad_hash, 8)

print("Testing with basic but very bad crypto primitives:")
for i in range(1000):
    data = random.randbytes(random.randrange(0, 500))
    record = basic_session.build_app_record(data, i)
    assert record[0] == ssl.ContentType.Application
    assert record[1] == 0x03 and record[2] == 0x03
    assert int.from_bytes(record[3:5], 'big') % basic_session.block_size == 0
    retrieved_data = basic_session.open_app_record(record[5:], i)
    assert data == retrieved_data
    print("+", end="")
print()
