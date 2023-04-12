import socketserver as ssv
from typing import Optional
from database import Account, get_account, AttemptsExceededError
import shared.rpi_ssl as ssl
from shared.protocol import MsgType, AppError
from shared.card import Card
from shared.handshake_handler import server_handle_handshake
from shared.port import PORT


class Handler(ssv.StreamRequestHandler):
    """
    Parent reference: https://docs.python.org/3/library/socketserver.html#socketserver.StreamRequestHandler
    """

    def fetch_record(self) -> tuple[ssl.ContentType, bytes]:
        tls_header = self.rfile.read(5)
        content_type = ssl.ContentType(tls_header[0])
        assert tls_header[1:3] == b'\x03\x03'
        content_length = int.from_bytes(tls_header[3:5], 'big')

        tls_content = self.rfile.read(content_length)
        return (content_type, tls_content)

    def handle_handshake(self, tls_content: bytes):
        # SSL handshake
        raise NotImplementedError("oopsie!")

    def handle_account_auth(self, app_content: bytes) -> bytes:
        """
        Purely application-level

        Returns
        ----
        `bytes` object with response message. Application message type should be the same as `app_content` or be `ERROR`
        """
        if app_content[0] != MsgType.ACCOUNT_AUTH:  # Must be account auth message
            return bytes([MsgType.ERROR, AppError.INVALID_STAGE])
        # Check the card
        try:
            card = Card.from_bytes(app_content[1:])
            self.account = get_account(card)
        except AttemptsExceededError:
            self.close = True
            return bytes([MsgType.ERROR, AppError.ATTEMPTS_EXCEEDED])
        except:
            return bytes([MsgType.ACCOUNT_AUTH, 0x00])
        else:
            return bytes([MsgType.ACCOUNT_AUTH, 0x01])

    def handle_routine(self, app_content: bytes) -> bytes:
        """
        Purely application-level

        Returns
        ----
        `bytes` object with response message. Application message type should be the same as `app_content` or be `ERROR`
        """
        # Accept commands
        if app_content[0] == MsgType.BALANCE:
            if len(app_content) != 1:
                return bytes([MsgType.ERROR, AppError.BAD_MESSAGE])
            return bytes([MsgType.BALANCE]) + self.account.balance.to_bytes(8, 'big')
        elif app_content[0] == MsgType.DEPOSIT:
            if len(app_content) != 9:
                return bytes([MsgType.ERROR, AppError.BAD_MESSAGE])
            amount = int.from_bytes(app_content[1:], 'big')
            self.account.deposit(amount)
            return bytes([MsgType.DEPOSIT, 0x01])
        elif app_content[0] == MsgType.WITHDRAW:
            if len(app_content) != 9:
                return bytes([MsgType.ERROR, AppError.BAD_MESSAGE])
            amount = int.from_bytes(app_content[1:], 'big')
            try:
                self.account.withdraw(amount)
            except:
                return bytes([MsgType.WITHDRAW, 0x00])
            else:
                return bytes([MsgType.WITHDRAW, 0x01])
        else:
            return bytes([MsgType.ERROR, AppError.INVALID_STAGE])

    def setup(self):
        super().setup()
        # If this is not None, handshake is done
        self.session: Optional[ssl.Session] = None
        # If this is not None, account is authenticated
        self.account: Optional[Account] = None

        self.user_attempts = 0
        # If self.close is True after a response is sent, then the connection is terminated.
        self.close = False
        print(f"[LOG] {self.client_address}: Session started.")

    def message_handler(self):
        """
        Waits for a new SSL/TLS record, then calls the appropriate handler.
        - During handshake: TODO
        - During user authentication: uses application-level `handle_account_auth`
        - Otherwise: uses application-level `handle_routine`

        Throws
        ----
           - `SSLError` - will include error details; should be caught and have alert message sent.
           - `NotImplementedError` where not implemented.
        """
        content_type, tls_content = self.fetch_record()

        if self.session is None:
            # First stage: Handshake
            if content_type is ssl.ContentType.Handshake:
                self.handle_handshake(tls_content)
                return
            raise NotImplementedError(
                "We don't know what to do with non-handshake messages at this stage.")
        elif self.account is None:
            # Second stage: user authentication
            if content_type is ssl.ContentType.Application:
                app_content = self.session.open_encrypted_record(tls_content)
                print(
                    f"[LOG] {self.client_address}: Auth Recieved: {app_content.hex(';')}")
                response = self.handle_account_auth(app_content)
                self.user_attempts += 1
                if self.user_attempts >= 8 and self.account is None:
                    print("      Session attempts exceeded")
                    response = bytes(
                        [MsgType.ERROR, AppError.ATTEMPTS_EXCEEDED])
                    self.close = True
                print("      Auth Responded: " + response.hex(";"))
                self.wfile.write(self.session.build_app_record(response))
                return
            raise NotImplementedError(
                "We don't know what to do with non-application messages at this stage.")

        # Final stage: ongoing user commands
        if content_type is ssl.ContentType.Application:
            app_content = self.session.open_encrypted_record(tls_content)
            print(
                f"[LOG] {self.client_address}: App Recieved: {app_content.hex(';')}")
            response = self.handle_routine(app_content)
            print("      App Responded: " + response.hex(";"))
            self.wfile.write(self.session.build_app_record(response))
            return
        raise NotImplementedError(
            "We don't know what to do with non-application messages at this stage.")

    def handle(self):
        try:
            self.session = server_handle_handshake(self.rfile, self.wfile)
            if self.session is None:
                raise ssl.SSLError(
                    ssl.AlertLevel.FATAL, ssl.AlertType.HandshakeFailure, "Handshake was unsuccessful.")
            while not self.close:
                self.message_handler()
        except ssl.SSLError as e:
            print(f"[{e.level.name}] (ssl): {e.atype.name} {e.args}")
            self.wfile.write(self.session.build_alert_record(e.level, e.atype))
            if e.level is ssl.AlertLevel.FATAL:
                return
        except BaseException as e:
            print(f"[FATAL] (unknown): {e.args}")
            self.wfile.write(self.session.build_alert_record(
                ssl.AlertLevel.FATAL, ssl.AlertType.InternalError))
            return

    def finish(self):
        super().finish()
        print(f"[LOG] {self.client_address}: Session closed")


with ssv.ThreadingTCPServer(("localhost", PORT), Handler) as server:
    server.serve_forever()
