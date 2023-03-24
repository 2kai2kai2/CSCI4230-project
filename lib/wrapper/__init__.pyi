
def encrypt_block(msg: bytes, key: bytes) -> bytes:
    """
    Encrypts a single block using AES.

    Parameters
    ----
      - `msg` - A 128-bit (16-byte) plaintext block to encrypt
      - `key` - A 256-bit (32-byte) symmetric key
    
    Returns
    ----
    The cooresponding 128-bit (16-byte) ciphertext block
    """
    
def decrypt_block(msg: bytes, key: bytes) -> bytes:
    """
    Decrypts a single block using AES.

    Parameters
    ----
      - `msg` - A 128-bit (16-byte) ciphertext block to encrypt
      - `key` - A 256-bit (32-byte) symmetric key
    
    Returns
    ----
    The cooresponding 128-bit (16-byte) plaintext block
    """

def encrypt_cbc(msg: bytes, key: bytes, IV: bytes) -> bytes:
    """
    Encrypts a sequence of blocks using AES with the CBC mode of operation.

    Parameters
    ----
      - `msg` - A plaintext to encrypt, where the length is a multiple of 128 bits (16 bytes)
      - `key` - A 256-bit (32-byte) symmetric key
      - `IV` - A 128-bit (16-byte) initialization vector
    
    Returns
    ----
    The cooresponding plaintext, with the same length as `msg`
    """


def decrypt_cbc(msg: bytes, key: bytes, IV: bytes) -> bytes:
    """
    Decrypts a sequence of blocks using AES with the CBC mode of operation.

    Parameters
    ----
      - `msg` - A ciphertext to decrypt, where the length is a multiple of 128 bits (16 bytes)
      - `key` - A 256-bit (32-byte) symmetric key
      - `IV` - The 128-bit (16-byte) initialization vector used to encrypt
    
    Returns
    ----
    The cooresponding ciphertext, with the same length as `msg`
    """