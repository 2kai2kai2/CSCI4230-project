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
print("-> Basic encrypted records:")
for i in range(1000):
    data = random.randbytes(random.randrange(0, 500))
    record = basic_session.build_encrypted_record(
        ssl.ContentType.Application, data, i)
    assert record[0] == ssl.ContentType.Application
    assert record[1] == 0x03 and record[2] == 0x03
    assert int.from_bytes(record[3:5], 'big') % basic_session.block_size == 0
    retrieved_data = basic_session.open_encrypted_record(record[5:], i)
    assert data == retrieved_data
    print("+", end="")
print("\n-> Encrypted alert records:")
for i in range(1000):
    level = random.choice(list(ssl.AlertLevel))
    atype = random.choice(list(ssl.AlertType))
    record = basic_session.build_alert_record(level, atype, i)
    assert record[0] == ssl.ContentType.Alert
    assert record[1] == 0x03 and record[2] == 0x03
    assert int.from_bytes(record[3:5], 'big') == basic_session.block_size
    retrieved_level, retrieved_type = basic_session.open_alert_record(
        record[5:], i)
    assert retrieved_level == level
    assert retrieved_type == atype
    print("+", end="")
