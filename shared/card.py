"""
This file contains shared implementation for the communication and verification of cards.
"""
import random
from typing import Optional
import shared.paillier as paillier

def valid_card_num(number: str) -> bool:
    if not isinstance(number, str) or not number.isdecimal() or len(number) != 16:
        return False
    sum: int = 0
    for i in range(16):
        tmp = int(number[i]) * (2 if i % 2 == 0 else 1)
        sum += int(tmp / 10) + tmp % 10
    return sum % 10 == 0


class Card:
    """
    Storage in bits: \\
    `[0,54)` - Card Number (unsigned) \\
    `[54,64)` - CVC (unsigned) \\
    `[64,68)` - Month (unsigned) \\
    `[68,78)` - Year (unsigned, starting with 0 as year 2000) \\
    `[78, 92)` - PIN (unsigned)
    """
    BYTE_LEN = 12
    BIT_LEN = BYTE_LEN * 8

    def __init__(self, number: str, cvc: int, month: int, year: int, pin: int):
        if not valid_card_num(number):
            raise ValueError("Invalid card number.")
        if cvc < 0 or 1000 <= cvc:
            raise OverflowError("Invalid CVC.")
        if month < 1 or 12 < month:
            raise OverflowError("Invalid expiration month.")
        if year < 2000 or 2000+2**10 <= year:
            raise OverflowError("Invalid expiration year.")
        if pin < 0 or 10000 <= pin:
            raise OverflowError("Invalid pin number provided.")
        self.number = number
        self.cvc = cvc
        self.month = month
        self.year = year
        self.pin = pin

    def to_bytes(self) -> bytes:
        as_int: int = 0

        as_int |= int(self.number) << (Card.BIT_LEN-54)
        as_int |= self.cvc << (Card.BIT_LEN-64)
        as_int |= self.month << (Card.BIT_LEN-68)
        as_int |= (self.year - 2000) << (Card.BIT_LEN-78)
        as_int |= self.pin << (Card.BIT_LEN-92)

        return as_int.to_bytes(Card.BYTE_LEN, 'big')

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != Card.BYTE_LEN:
            raise ValueError(
                f"UserAuth->from_bytes must be bytes object of length {Card.BYTE_LEN} ({Card.BIT_LEN} bits)")
        as_int = int.from_bytes(data, 'big')

        card_num = str(as_int >> (Card.BIT_LEN-54)).zfill(16)
        cvc = (as_int >> (Card.BIT_LEN-64)) & 0x3ff
        month = (as_int >> (Card.BIT_LEN-68)) & 0xf
        year = ((as_int >> (Card.BIT_LEN-78)) & 0x3ff) + 2000
        pin = ((as_int >> (Card.BIT_LEN-92)) & 0x3fff)

        return Card(card_num, cvc, month, year, pin)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Card):
            return False
        return self.number == other.number and self.cvc == other.cvc and self.month == other.month and self.year == other.year and self.pin == other.pin

    def __repr__(self) -> str:
        return f"<Card: number:{self.number} CVC:{str(self.cvc).zfill(3)} expires:{str(self.month).zfill(2)}/{self.year} pin:{str(self.pin).zfill(4)}>"

    @classmethod
    def generate_random(cls, month: int, year: int, card_num: Optional[str] = None, cvc: Optional[int] = None, pin: Optional[int] = None):
        if month < 1 or 12 < month:
            raise OverflowError("Invalid expiration month on card.")
        if year < 2000 or 2000+2**10 <= year:
            raise OverflowError("Invalid expiration year on card.")

        if card_num is None:
            while not valid_card_num(card_num):
                card_num = str(random.randrange(0, 10**16))
        elif not valid_card_num(card_num):
            raise ValueError("Invalid card number on card.")

        if cvc is None:
            cvc = random.randrange(0, 1000)
        elif cvc < 0 or 1000 <= cvc:
            raise OverflowError("Invalid CVC on card.")

        if pin is None:
            pin = random.randrange(0, 10000)
        elif pin < 0 or 10000 < pin:
            raise OverflowError("Invalid PIN on card.")

        return Card(card_num, cvc, month, year, pin)


def validate_encrypted_check(card: Card, C: int, paillier_pubkey: tuple[int, int], paillier_privkey: int) -> bool:
    """
    Parameters
    ----
       - `card`: Card to check
       - `C`: cryptographic checksum produced by `gen_encrypted_check`
       - `paillier_pubkey`: `(g, n)`
       - `paillier_privkey`: `\lambda`
    """
    expected = int(card.number) + card.cvc + card.pin + card.month + card.year
    M = paillier.decrypt(C, paillier_pubkey, paillier_privkey)
    return M == expected

def gen_encrypted_check(card: Card, paillier_pubkey: tuple[int, int]) -> int:
    """
    Parameters
    ----
       - `card`: Card to check
       - `paillier_pubkey`: `(g, n)`
    """
    # Encrypt the number, cvc, pin, month, and year
    _num = paillier.encrypt(int(card.number), paillier_pubkey)
    _cvc = paillier.encrypt(card.cvc, paillier_pubkey)
    _pin = paillier.encrypt(card.pin, paillier_pubkey)
    _mth = paillier.encrypt(card.month, paillier_pubkey)
    _yar = paillier.encrypt(card.year, paillier_pubkey)
    checksum = paillier.homomorphic_summation([_num, _cvc, _pin, _mth, _yar], paillier_pubkey[1])
    return checksum
