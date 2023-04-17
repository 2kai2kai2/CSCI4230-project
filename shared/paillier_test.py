import paillier
import random

for i in range(100):
    pubkey, privkey = paillier.keygen(1024)

    item_sum = 0
    item_prod = 1
    enc_sum = paillier.encrypt(0, pubkey)
    enc_prod = paillier.encrypt(1, pubkey)
    for j in range(100):
        item = random.randrange(2, pubkey[1])
        enc_item = paillier.encrypt(item, pubkey)
        assert item == paillier.decrypt(enc_item, pubkey, privkey)

        item_sum = (item_sum + item) % pubkey[1]
        enc_sum = paillier.homomorphic_add(enc_sum, enc_item, pubkey[1])
        p_sum = paillier.decrypt(enc_sum, pubkey, privkey)
        assert p_sum == item_sum

        item_prod = (item_prod * item) % pubkey[1]
        enc_prod = paillier.homomorphic_mult(enc_prod, item, pubkey[1])
        p_prod = paillier.decrypt(enc_prod, pubkey, privkey)
        assert p_prod == item_prod
        print(
            f"\r\x1b[2KTested: random key {i + 1}/100 iteration {j + 1}/100", end="", flush=True)
print()
