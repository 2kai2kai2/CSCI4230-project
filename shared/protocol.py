from enum import IntEnum


class MsgType(IntEnum):
    """
    Application-level message type. Should be the first byte of the message contained in any TLS/SSL application record.

    For messages from client to server, this is the request type being made.

    For messages from server to client, this is either the same as the request, or `ERROR`.
    """

    ACCOUNT_AUTH = 0x00
    """
    Request
    ----
    `[0,1)` - `ACCOUNT_AUTH` (`0x00`) \\
    `[1,end)` - `Card.to_bytes()`

    Response
    ----
    `[0,1)` - `ACCOUNT_AUTH` (`0x00`) \\
    `[1,2)` - Success/Failure (`1` or `0`)
    """
    
    BALANCE = 0x01
    DEPOSIT = 0x02
    WITHDRAW = 0x03

    ERROR = 0xFF
    """
    Request/Response
    ----
    `[0,1)` - `ERROR` (`0xFF`) \\
    `[1,2)` - AppError code
    """


class AppError(IntEnum):
    """
    For TLS/SSL application records with `MsgType.ERROR`, the error code is specified in byte 2.
    """
    INVALID_STAGE = 0x00  # When a is not valid for the current stage or does not exist.
