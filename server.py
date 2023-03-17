import socketserver as ssv
from typing import Optional
from database import Account, get_account
import shared.rpi_ssl as ssl


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

    def handle_account_auth(self, tls_content: bytes):
        # User sign-in stuff
        raise NotImplementedError("oopsie!")

    def handle_routine(self, tls_content: bytes):
        # Accept commands
        raise NotImplementedError("oopsie!")

    def setup(self):
        super().setup()
        # If this is not None, handshake is done
        self.session_key: Optional[ssl.Session] = None
        self.seq = 0  # Uses of session key
        # If this is not None, account is authenticated
        self.account: Optional[Account] = None

    def handle(self):
        content_type, tls_content = self.fetch_record()

        if self.session_key is None:
            # First stage: Handshake
            if content_type is ssl.ContentType.Handshake:
                self.handle_handshake(tls_content)
                return
            raise NotImplementedError(
                "We don't know what to do with non-handshake messages at this stage.")
        elif self.account is None:
            # Second stage: user authentication
            if content_type is ssl.ContentType.Application:
                self.handle_account_auth(tls_content)
                return
            raise NotImplementedError(
                "We don't know what to do with non-application messages at this stage.")

        # Final stage: ongoing user commands
        if content_type is ssl.ContentType.Application:
            self.handle_routine(tls_content)
            return
        raise NotImplementedError(
            "We don't know what to do with non-application messages at this stage.")

    def finish(self):
        super().finish()
        # Then do finishing stuff


with ssv.ThreadingTCPServer(("localhost", 125), Handler) as server:
    server.serve_forever()
