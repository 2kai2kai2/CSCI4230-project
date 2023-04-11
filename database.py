"""
This file provides a simple abstraction of a database attached to the server.
"""
from shared.card import Card


class Account:
    """
    Represents a bank account.

    `balance` is in cents.
    """

    def __init__(self, name: str, card: Card, balance: int = 0):
        self.name = name
        self.card = card
        self._balance = balance

    @property
    def balance(self) -> int:
        """
        Account balance in cents.
        """
        return self._balance

    def deposit(self, amount: int):
        """
        Adds money to the account.

        Always succeeds.

        Parameters
        ----
           - `amount` in cents to be added to the balance.

        Throws
        ----
           -`ValueError` if a negative amount is specified.
        """
        if amount < 0:
            raise ValueError("Cannot deposit a negative amount.")
        self._balance += amount

    def withdraw(self, amount: int):
        """
        Removes money from the account.

        Parameters
        ----
           - `amount` in cents to be removed from the balance.

        Throws
        ----
           - `RuntimeError` if there are insufficient funds.
           - `ValueError` if a negative amount is specified.
        """
        if amount < 0:
            raise ValueError("Cannot withdraw a negative amount.")
        elif amount > self._balance:
            raise RuntimeError("Insufficient Funds.")
        self._balance -= amount


_db: dict[str, Account] = {}


def _add_account(name: str, card: Card, balance: int):
    if card.number in _db:
        raise RuntimeError("Card number already exists.")
    _db[card.number] = Account(name, card, balance)


_add_account("Mallory Malificent", Card(
    "0000000000000000", 666, 4, 2025, 6969), 666_00)
_add_account("Cici Collaborator", Card(
    "0000000000000505", 111, 5, 2025, 1111), 100_00)
_add_account("Alice Allison", Card.generate_random(5, 2025), 1000_00)
_add_account("Bobby McBobface", Card.generate_random(
    6, 2023, card_num="0505050505050505", cvc=123), 10_00)
_add_account("Victor Evilson", Card.generate_random(
    9, 2026, card_num="4111111111111111"), 100000_00)
_add_account("Billy Bazillionaire", Card.generate_random(
    12, 2100), 1000000000000_00)


def get_account(card: Card) -> Account:
    """
    Gets an account based on the provided card's card number, additionally verifying the other card information.

    Parameters
    ----
       - `card` - The debit card of the account to be retrieved.

    Returns
    ----
       The associated `Account` if it exists and the card information is valid.

    Throws
    ----
       - `ValueError` if no account with the card number was found.
       - `PermissionError` if the card information did not match the found account.
    """
    account = _db.get(card.number)
    if account is None:
        raise ValueError(
            f"No matching account found for card number {card.number}.")
    elif card != account.card:
        raise PermissionError(
            "Provided card details do not match the associated account.")
    return account
