"""
Contains shared implementation and constants for application-layer protocol
"""
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
    """
    Request
    ----
    `[0,1)` - `BALANCE` (`0x01`)

    Response
    ----
    `[0,1)` - `BALANCE` (`0x01`) \\
    `[1,9)` - Account balance in cents (unsigned)
    """

    DEPOSIT = 0x02
    """
    Request
    ----
    `[0,1)` - `DEPOSIT` (`0x02`) \\
    `[1,9)` - Amount in cents (unsigned)

    Response
    ----
    `[0,1)` - `DEPOSIT` (`0x02`)
    `[1,2)` - Success/Failure (`1` or `0`)
    """

    WITHDRAW = 0x03
    """
    Request
    ----
    `[0,1)` - `WITHDRAW` (`0x03`) \\
    `[1,9)` - Amount in cents (unsigned)

    Response
    ----
    `[0,1)` - `WITHDRAW` (`0x03`) \\
    `[1,2)` - Success/Failure (`1` or `0`)
    """

    ERROR = 0xFF
    """
    Should only be sent by server.

    Response
    ----
    `[0,1)` - `ERROR` (`0xFF`) \\
    `[1,2)` - AppError code
    """


class AppError(IntEnum):
    """
    For TLS/SSL application records with `MsgType.ERROR`, the error code is specified in byte 2.
    """
    INVALID_STAGE = 0x00 
    """When a request type is not valid for the current stage or does not exist."""
    
    BAD_MESSAGE = 0x01
    """When a request is incorrectly formatted."""

    ATTEMPTS_EXCEEDED = 0x02
    """When login attempts are exceeded."""

