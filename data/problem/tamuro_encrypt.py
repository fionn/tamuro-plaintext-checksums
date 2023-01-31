"""
From https://gist.github.com/tkeetch/b1b21f621813ff11a75930f80f1c9e5b with
slight edits, mostly for type annotations.
"""

import binascii
import secrets
import random
import crcmod

flag = "DELETED"

def generate_encryption_key() -> bytes:
    return secrets.token_bytes(256 // 8)

def encrypt(k: bytes, m: bytes) -> bytes:
    raise Exception("DELETED CODE")

def crc32(m: bytes) -> bytes:
    crc_function = crcmod.mkCrcFun(0x104C11DB7, rev=False, initCrc=0,
                                   xorOut=0xFFFFFFFF)
    return int(crc_function(m)).to_bytes(4, byteorder='big')

def checksum_and_encrypt(k: bytes, m: bytes) -> bytes:
    return encrypt(k, m) + crc32(m)

def generate_flag(secret_key: bytes) -> str:
    encrypted_flag = binascii.hexlify(encrypt(secret_key, bytes(flag, 'ascii'))).decode('ascii')
    print("flag = {encrypted_flag}")
    return encrypted_flag

def generate_encrypted_messages(secret_key: bytes) -> list[bytes]:
    c = []
    msg_lengths = list(range(1, len(flag)+3))
    random.shuffle(msg_lengths)

    print("Format: stream_cipher(k, msg) || crc32-big_endian(msg)")
    print("CRC Check = {} (crc-32-bzip2)".format(hex(int.from_bytes(crc32(bytes("123456789", 'ascii')), byteorder='big'))))
    print("Encrypted messages:")
    for msg_length in msg_lengths:
        p = secrets.token_bytes(msg_length)
        m = checksum_and_encrypt(secret_key, p)
        c.append(m)
        print("  " + binascii.hexlify(m).decode('ascii'))
    print("\n\n\n")
    return c

def main() -> None:
    secret_key = generate_encryption_key()
    encrypted_flag = generate_flag(secret_key)
    msgs = generate_encrypted_messages(secret_key)

if __name__ == "__main__":
    main()
