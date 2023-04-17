from typing import Literal, Union
from shared.handshake_handler import client_handle_handshake
import socket
import shared.rpi_ssl as ssl
from shared.card import *
from shared.protocol import *
from getkey import getkey, keys
from sys import exit
from shared.port import PORT


conn = socket.create_connection(("localhost", PORT))
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

import my_secrets.client as secret_keys

INFO = {
    "client_public": secret_keys.PUBLIC_KEY,
    "client_private": secret_keys.PRIVATE_KEY,
    "client_modulus": secret_keys.P * secret_keys.Q
}

session: ssl.Session = client_handle_handshake(rfile, wfile, INFO)
if session == None:
    exit(1)

# ==== Account Auth Stage ====


def input_card_legacy() -> Card:
    # Still works if your computer doesn't support getkey or ANSI escape codes
    print("Enter card details:")
    card_num = ""
    while True:
        tmp = input("Card number: ").strip()
        if not tmp.isdecimal() or len(tmp) != 16:
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
        if not tmp.isdecimal() or len(tmp) != 3:
            print("ERROR: Invalid CVC format (should be 3 digits).")
            continue
        cvc = int(tmp)
        break

    month = -1
    year = -1
    while True:
        tmp = input("Expiration date (MM/YYYY): ").strip()
        if len(tmp) != 7 or not tmp[:2].isdecimal() or tmp[2] != "/" or not tmp[3:].isdecimal():
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
        if len(tmp) != 4 or not tmp.isdecimal():
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
            if str(k).isdecimal():
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
        if str(k).isdecimal():
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
        if str(k).isdecimal():
            print(str(k), end="")
            year += str(k)
    month = int(month)
    year = int(year)

    pin = ""
    print("\nPIN: ", end="")
    while len(pin) != 4:
        k = getkey()
        if str(k).isdecimal():
            print("*", end="")
            pin += str(k)
    pin = int(pin)
    print()

    return Card(card_num, cvc, month, year, pin)


account_auth = False


def select_mode_legacy() -> MsgType:
    # Still works if your computer doesn't support getkey or ANSI escape codes
    while True:
        mode = input(
            "Enter mode (BALANCE, DEPOSIT, WITHDRAW): ").strip().upper()
        if mode not in ["BALANCE", "DEPOSIT", "WITHDRAW"]:
            print("Invalid mode. Try again.")
            continue
        return MsgType[mode]


def select_mode() -> Union[MsgType, Literal['EXIT']]:
    option = MsgType.BALANCE
    while True:
        if option == MsgType.BALANCE:
            print(
                "\r\x1b[7mBALANCE\x1b[27m   DEPOSIT   WITHDRAW   EXIT\x1b[?25l", end="")
        elif option == MsgType.DEPOSIT:
            print(
                "\rBALANCE   \x1b[7mDEPOSIT\x1b[27m   WITHDRAW   EXIT\x1b[?25l", end="")
        elif option == MsgType.WITHDRAW:
            print(
                "\rBALANCE   DEPOSIT   \x1b[7mWITHDRAW\x1b[27m   EXIT\x1b[?25l", end="")
        elif option == "EXIT":
            print(
                "\rBALANCE   DEPOSIT   WITHDRAW   \x1b[7mEXIT\x1b[27m\x1b[?25l", end="")
        k = getkey()
        if k == keys.ENTER:
            print("\x1b[?25h")
            return option
        elif k == keys.LEFT:
            if option == MsgType.DEPOSIT:
                option = MsgType.BALANCE
            elif option == MsgType.WITHDRAW:
                option = MsgType.DEPOSIT
            elif option == "EXIT":
                option = MsgType.WITHDRAW
        elif k == keys.RIGHT:
            if option == MsgType.BALANCE:
                option = MsgType.DEPOSIT
            elif option == MsgType.DEPOSIT:
                option = MsgType.WITHDRAW
            elif option == MsgType.WITHDRAW:
                option = "EXIT"


def request_balance() -> int:
    msg = session.build_app_record(bytes([MsgType.BALANCE]))
    wfile.write(msg)
    rtype, response_body = fetch_record()
    assert rtype == ssl.ContentType.Application
    response = session.open_encrypted_record(response_body)
    assert len(response) == 9 and response[0] == MsgType.BALANCE
    return int.from_bytes(response[1:], 'big')


def request_deposit(amount: int) -> bool:
    msg = session.build_app_record(
        bytes([MsgType.DEPOSIT]) + amount.to_bytes(8, 'big'))
    wfile.write(msg)
    rtype, response_body = fetch_record()
    assert rtype == ssl.ContentType.Application
    response = session.open_encrypted_record(response_body)
    assert len(response) == 2 and response[0] == MsgType.DEPOSIT
    return response[1] == 0x01


def request_withdraw(amount: int) -> bool:
    msg = session.build_app_record(
        bytes([MsgType.WITHDRAW]) + amount.to_bytes(8, 'big'))
    wfile.write(msg)
    rtype, response_body = fetch_record()
    assert rtype == ssl.ContentType.Application
    response = session.open_encrypted_record(response_body)
    assert len(response) == 2 and response[0] == MsgType.WITHDRAW
    return response[1] == 0x01


try:
    while not account_auth:
        # card = input_card()
        card = Card("0000000000000000", 666, 4, 2025, 6969)
        request = bytes([MsgType.ACCOUNT_AUTH]) + card.to_bytes()
        toSend = session.build_app_record(request)
        wfile.write(toSend)

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
            if app_content[0] == MsgType.ERROR:
                print(f"ERROR (app): {AppError(app_content[1]).name}\n")
                quit()
            elif app_content[0] != MsgType.ACCOUNT_AUTH:
                # Something went wrong. Let's just move on.
                print(
                    f"WARNING (app): Recieved app message type {MsgType(app_content[0]).name} instead of ACCOUNT_AUTH")
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
        print("Select command:")
        mode = select_mode()
        if mode == MsgType.BALANCE:
            print("Fetching balance...")
            amount = request_balance()
            print(f"Account Balance: ${amount/100:.2f}")
        elif mode == MsgType.DEPOSIT:
            amount = input("Enter amount to deposit: $")
            if not amount.replace(".", "", 1).isdecimal():
                print("Invalid number format.")
                continue
            success = request_deposit(int(float(amount) * 100))
            print("Deposit " + ("successful." if success else "unsuccessful."))
        elif mode == MsgType.WITHDRAW:
            amount = input("Enter amount to withdraw: $")
            if not amount.replace(".", "", 1).isdecimal():
                print("Invalid number format.")
                continue
            success = request_withdraw(int(float(amount) * 100))
            print("Withdrawal " + ("successful." if success else "unsuccessful."))
        elif mode == "EXIT":
            raise KeyboardInterrupt()
        else:
            raise NotImplementedError("This shouldn't be able to happen.")
except KeyboardInterrupt:
    print(f"SSL session closing gracefully.")
    if not wfile.closed:
        wfile.write(session.build_alert_record(
            ssl.AlertLevel.FATAL, ssl.AlertType.CloseNotify))
    quit()
except ssl.SSLError as e:
    print(f"[FATAL] (ssl): {e.atype.name} {e.args}")
    if not wfile.closed:
        wfile.write(session.build_alert_record(ssl.AlertLevel.FATAL, e.atype))
    quit(1)
except BaseException as e:
    print(f"[FATAL] (unknown {type(e)}): {e.args}")
    if not wfile.closed:
        wfile.write(session.build_alert_record(
            ssl.AlertLevel.FATAL, ssl.AlertType.InternalError))
    quit(1)
