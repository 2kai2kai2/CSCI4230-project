import socketserver as ssv
from typing import Optional
from database import Account, get_account


class Handler(ssv.StreamRequestHandler):
    """
    Parent reference: https://docs.python.org/3/library/socketserver.html#socketserver.StreamRequestHandler
    """

    def setup(self):
        super().setup()
        # If this is not None, handshake is done
        self.session_key: Optional[bytes] = None
        self.seq = 0  # Uses of session key
        # If this is not None, account is authenticated
        self.account: Optional[Account] = None

    def handle(self):
        if self.session_key is None:
            # SLL handshake
            return
        elif self.account is None:
            # User sign-in stuff
            return
        # Otherwise, accept commands

    def finish(self):
        super().finish()
        # Then do finishing stuff


with ssv.ThreadingTCPServer(("localhost", 125), Handler) as server:
    server.serve_forever()
