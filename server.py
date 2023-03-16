import socketserver as ssv

class Handler(ssv.StreamRequestHandler):
    """
    Parent reference: https://docs.python.org/3/library/socketserver.html#socketserver.StreamRequestHandler
    """
    def setup(self):
        super().setup()
        # Then do setup stuff
    
    def handle(self):
        pass

    def finish(self):
        super().finish()
        # Then do finishing stuff

with ssv.ThreadingTCPServer(("localhost", 125), Handler) as server:
    server.serve_forever()
