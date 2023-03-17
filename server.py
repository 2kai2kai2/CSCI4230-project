import socketserver as ssv
from typing import Optional
from database import Account, get_account
import shared.rpi_ssl as ssl
from shared.protocol import MsgType, AppError
from shared.card import Card


class Handler(ssv.StreamRequestHandler):
    """
    Parent reference: https://docs.python.org/3/library/socketserver.html#socketserver.StreamRequestHandler
    """

    def fetch_record(self) -> tuple[ssl.ContentType, bytes]:
        tls_header = self.rfile.read(5)
        content_type = ssl.ContentType.from_bytes(tls_header[0], 'big')
        assert tls_header[1:3] == b'\x03\x03'
        content_length = int.from_bytes(tls_header[3:5], 'big')

        tls_content = self.rfile.read(content_length)
        return (content_type, tls_content)

    def handle_handshake(self, tls_content: bytes):
        # SSL handshake
        raise NotImplementedError("oopsie!")

    def handle_account_auth(self, app_content: bytes):
        # We get a message, check the card, and verify it is correct.
        if app_content[0] != MsgType.ACCOUNT_AUTH:  # Must be account auth message
            response = bytes([MsgType.ERROR, AppError.INVALID_STAGE])
            self.wfile.write(self.session.build_app_record(response))
            return

        try:
            self.account = get_account(Card.from_bytes(app_content[1:]))
        except:
            response = bytes([MsgType.ACCOUNT_AUTH, 0x00])
        else:
            response = bytes([MsgType.ACCOUNT_AUTH, 0x01])
        self.wfile.write(self.session.build_app_record(response))

    def handle_routine(self, app_content: bytes):
        # Accept commands
        raise NotImplementedError("oopsie!")

    def setup(self):
        super().setup()
        # If this is not None, handshake is done
        self.session: Optional[ssl.Session] = None
        # If this is not None, account is authenticated
        self.account: Optional[Account] = None

        self.close = False

    def message_handler(self):
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
                try:
                    app_content = self.session.open_encrypted_record(
                        tls_content)
                except ssl.InvalidMAC:
                    response = self.session.build_alert_record(
                        ssl.AlertLevel.FATAL, ssl.AlertType.BadMAC)
                    self.wfile.write(response)
                    self.close = True
                    return

                self.handle_account_auth(app_content)
                return
            raise NotImplementedError(
                "We don't know what to do with non-application messages at this stage.")

        # Final stage: ongoing user commands
        if content_type is ssl.ContentType.Application:
            try:
                app_content = self.session.open_encrypted_record(tls_content)
            except ssl.InvalidMAC:
                response = self.session.build_alert_record(
                    ssl.AlertLevel.FATAL, ssl.AlertType.BadMAC)
                self.wfile.write(response)
                self.close = True
                return

            self.handle_routine(app_content)
            return
        raise NotImplementedError(
            "We don't know what to do with non-application messages at this stage.")

    def handle(self):
        while not self.close:
            try:
                self.message_handler()
            except:
                self.wfile.write(self.session.build_alert_record(
                    ssl.AlertLevel.FATAL, ssl.AlertType.InternalError))
                return

    def finish(self):
        super().finish()
        # Then do finishing stuff


with ssv.ThreadingTCPServer(("localhost", 125), Handler) as server:
    server.serve_forever()
