"""
This file contains shared implementation for the communication and verification of cards.
"""


def valid_card_num(number: str) -> bool:
    if not isinstance(number, str) or not number.isdigit() or len(number) != 16:
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
    `[68,78)` - Year (unsigned, starting with 0 as year 2000)
    """
    BYTE_LEN = 10
    BIT_LEN = BYTE_LEN * 8

    def __init__(self, number: str, cvc: int, month: int, year: int):
        if not valid_card_num(number):
            raise ValueError("Invalid card number.")
        if cvc < 0 or 1000 <= cvc:
            raise ValueError("Invalid CVC on card.")
        if month < 1 or 12 < month:
            raise OverflowError("Invalid expiration month on card.")
        if year < 2000 or 2000+2**10 <= year:
            raise OverflowError("Invalid expiration year on card.")
        self.number = number
        self.cvc = cvc
        self.month = month
        self.year = year

    def to_bytes(self) -> bytes:
        as_int: int = 0

        as_int |= int(self.number) << (Card.BIT_LEN-54)
        as_int |= self.cvc << (Card.BIT_LEN-64)
        as_int |= self.month << (Card.BIT_LEN-68)
        as_int |= (self.year - 2000) << (Card.BIT_LEN-78)

        return as_int.to_bytes(Card.BYTE_LEN, 'big')

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != 10:
            raise ValueError(
                f"UserAuth->from_bytes must be bytes object of length {Card.BYTE_LEN} ({Card.BIT_LEN} bits)")
        as_int = int.from_bytes(data, 'big')

        card_num = str(as_int >> (Card.BIT_LEN-54)).zfill(16)
        cvc = (as_int >> (Card.BIT_LEN-64)) & 0x3ff
        month = (as_int >> (Card.BIT_LEN-68)) & 0xf
        year = ((as_int >> (Card.BIT_LEN-78)) & 0x3ff) + 2000

        return Card(card_num, cvc, month, year)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Card):
            return False
        return self.number == other.number and self.cvc == other.cvc and self.month == other.month and self.year == other.year

    def __repr__(self) -> str:
        return f"<Card: number:{self.number} CVC:{str(self.cvc).zfill(3)} expires:{str(self.month).zfill(2)}/{self.year}>"
