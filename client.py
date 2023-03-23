import socket
import shared.rpi_ssl as ssl
from shared.card import *
from shared.protocol import *
from getkey import getkey, keys


conn = socket.create_connection(("localhost", 125))
conn.setblocking(True)
rfile = conn.makefile('rb', buffering=0)
wfile = conn.makefile('wb', buffering=0)


def fetch_record() -> tuple[ssl.ContentType, bytes]:
    tls_header = rfile.read(5)
    content_type = ssl.ContentType(tls_header[0])
    assert tls_header[1:3] == b'\x03\x03'
    content_length = int.from_bytes(tls_header[3:5], 'big')

    tls_content = rfile.read(content_length)
    return (content_type, tls_content)


# ==== Handshake Stage ====
# TODO: Handshake


session: ssl.Session = ...  # placeholder

# ==== Account Auth Stage ====


def input_card_legacy() -> Card:
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


def input_card() -> Card:
    print("Enter card details:")
    card_num = ""
    while True:
        print("Card number: ", end="")
        while len(card_num) != 16:
            k = getkey()
            if str(k).isdigit():
                print(str(k), end="")
                card_num += str(k)

        if valid_card_num(card_num):
            print("\x1b[0K")
            break
        else:
            card_num = ""
            print("\x1b[1K (Invalid card number) \r", end="")
    cvc = ""
    print("CVC: ", end="")
    while len(cvc) != 3:
        k = getkey()
        if str(k).isdigit():
            print(str(k), end="")
            cvc += str(k)
    cvc = int(cvc)
    print()

    month = ""
    year = ""
    print("Expiration Date:   /    \x1b[7D", end="")
    while month == "":
        # First character of month must be 0 or 1
        k = getkey()
        if k == "0" or k == "1":
            month += str(k)
            print(k, end="")
    while len(month) != 2:
        # Second character of month must form a number in [1,12]
        k = getkey()
        if (month == "0" and k != "0") or (month == "1" and k in ["0", "1", "2"]):
            month += str(k)
            print(f"{k}/", end="")

    while len(year) == 0:
        # First character of year must be 2
        if getkey() == "2":
            year = "2"
            print("2", end="")
    while len(year) < 4:
        # Put in the other numbers
        k = getkey()
        if str(k).isdigit():
            print(str(k), end="")
            year += str(k)
    month = int(month)
    year = int(year)

    pin = ""
    print("\nPIN: ", end="")
    while len(pin) != 4:
        k = getkey()
        if str(k).isdigit():
            print("*", end="")
            pin += str(k)
    pin = int(pin)
    print()

    return Card(card_num, cvc, month, year, pin)


account_auth = False
while not account_auth:
    card = input_card()
    request = bytes([MsgType.ACCOUNT_AUTH]) + card.to_bytes()
    wfile.write(session.build_app_record(request))

    rtype, tls_content = fetch_record()
    if rtype == ssl.ContentType.Alert:
        alevel, atype = session.open_alert_record(tls_content)
        if alevel == ssl.AlertLevel.FATAL:
            print("FATAL ERROR: " + atype.name)
            quit()
        else:
            pass  # handle any warnings that need to be handled
    elif rtype == ssl.ContentType.Application:
        app_content = session.open_encrypted_record(tls_content)
        if app_content[0] != MsgType.ACCOUNT_AUTH:
            # Something went wrong. Let's just move on.
            print(
                f"WARNING (app): Recieved app message type {MsgType(app_content[0])} instead of ACCOUNT_AUTH")
            continue
        if app_content[1] == 0x01:
            account_auth = True
            print("++ Account Authorized ++\n")
        else:
            print("!! Invalid details !!\n")
    else:
        pass  # That wasn't supposed to happen.


# ==== Commands Stage ====
while True:
    pass
