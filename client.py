import socket
import shared.rpi_ssl as ssl
from shared.card import *


conn = socket.create_connection(("localhost", 125))
conn.setblocking(True)
rfile = conn.makefile('rb')
wfile = conn.makefile('wb')


def fetch_record() -> tuple[ssl.ContentType, bytes]:
    tls_header = rfile.read(5)
    content_type = ssl.ContentType.from_bytes(tls_header[0], 'big')
    assert tls_header[1:3] == b'\x03\x03'
    content_length = int.from_bytes(tls_header[3:5], 'big')

    tls_content = rfile.read(content_length)
    return (content_type, tls_content)


# ==== Handshake Stage ====
# TODO: Handshake


session: ssl.Session = ...  # placeholder

# ==== Account Auth Stage ====


def input_card() -> Card:
    print("Enter card details:")
    card_num = ""
    while True:
        tmp = input("Card number: ").strip()
        if not tmp.isdigit() or len(tmp) != 16:
            print("ERROR: Invalid card number format (should be 16 digits).")
            continue
        if not valid_card_num(tmp):
            print("ERROR: Invalid card number.")
            continue
        card_num = tmp
        break

    cvc = -1
    while True:
        tmp = input("CVC: ").strip()
        if not tmp.isdigit() or len(tmp) != 3:
            print("ERROR: Invalid CVC format (should be 3 digits).")
            continue
        cvc = int(tmp)
        break

    month = -1
    year = -1
    while True:
        tmp = input("Expiration date (MM/YYYY): ").strip()
        if len(tmp) != 7 or not tmp[:2].isdigit() or tmp[2] != "/" or not tmp[3:].isdigit():
            print("ERROR: Invalid expiration date format (should be MM/YYYY).")
            continue
        month = int(tmp[:2])
        if month < 1 or 12 < month:
            print("ERROR: Expiration month must be in the range [1,12].")
            continue
        year = int(tmp[3:])
        if year < 2000 or 2**10 + 2000 <= year:
            print("ERROR: Expiration year is out of bounds.")
            continue
        break

    pin = -1
    while True:
        tmp = input("PIN: ").strip()
        if len(tmp) != 4 or not tmp.isdigit():
            print("ERROR: Invalid PIN format (should be 4 digits).")
            continue
        pin = int(tmp)
        break

    return Card(card_num, cvc, month, year, pin)


account_auth = False
while not account_auth:
    card = input_card()
    # TODO: send the card for verification and set account_auth if so

# ==== Commands Stage ====
while True:
    pass
