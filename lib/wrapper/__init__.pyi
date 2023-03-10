
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