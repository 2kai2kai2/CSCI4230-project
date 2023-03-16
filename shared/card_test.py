import card

if __name__ != "__main__":
    quit()

a = card.Card("0000000000000000", 999, 12, 2999)
print(a)
a_bytes = a.to_bytes()
print(a_bytes.hex())
a_retrieved = card.Card.from_bytes(a_bytes)

b = card.Card("0505050505050505", 999, 12, 2998)
print(b)
b_bytes = b.to_bytes()
print(b_bytes.hex())

assert a == a_retrieved
assert b != a
assert a_bytes != b_bytes
