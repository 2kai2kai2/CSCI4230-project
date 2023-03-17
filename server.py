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

    def setup(self):
        super().setup()
        # If this is not None, handshake is done
        self.session_key: Optional[bytes] = None
        self.seq = 0  # Uses of session key
        # If this is not None, account is authenticated
        self.account: Optional[Account] = None

    def handle(self):
        content_type, tls_content = self.fetch_record()

        if self.session_key is None:
            assert content_type is ssl.ContentType.Handshake
            # SLL handshake
            return
        elif self.account is None:
            assert content_type is ssl.ContentType.Application
            # User sign-in stuff
            return
        assert content_type is ssl.ContentType.Application
        # Otherwise, accept commands

    def finish(self):
        super().finish()
        # Then do finishing stuff


with ssv.ThreadingTCPServer(("localhost", 125), Handler) as server:
    server.serve_forever()
