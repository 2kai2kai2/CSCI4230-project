from card import Card

if __name__ != "__main__":
    quit()

a = Card("0000000000000000", 999, 12, 2999, 1234)
print(a)
a_bytes = a.to_bytes()
print(a_bytes.hex())
a_retrieved = Card.from_bytes(a_bytes)

b = Card("0505050505050505", 999, 12, 2998, 1111)
print(b)
b_bytes = b.to_bytes()
print(b_bytes.hex())

assert a == a_retrieved
assert b != a
assert a_bytes != b_bytes

for i in range(1000):
    tmp = Card.generate_random(10, 2025)
    tmp_bytes = tmp.to_bytes()
    assert tmp == Card.from_bytes(tmp_bytes)