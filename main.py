#!/usr/bin/env python3
"""Tamuro "Plaintext Checksums" Solution"""

from typing import NamedTuple

from tamuro_encrypt import crc32


CiphertextChecksum = NamedTuple("CiphertextChecksum",
                                [("ciphertext", bytes), ("crc32", bytes)])


def ciphertext_checksum(data: bytes) -> CiphertextChecksum:
    assert len(data) > 4
    return CiphertextChecksum(data[:-4], data[-4:])


def to_bytes(x: int) -> bytes:
    """Integer to bytes"""
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def fixed_xor(a: bytes, b: bytes) -> bytes:
    """xor two byte sequences"""
    return bytes(i ^ j for (i, j) in zip(a, b, strict=True))


def get_message_keystream(ctcs: CiphertextChecksum,
                          keystream: bytes) -> tuple[bytes, bytes]:
    interval_size = len(ctcs.ciphertext) - len(keystream)
    known_message = fixed_xor(ctcs.ciphertext[:len(keystream)], keystream)
    for i in range(2 ** (8 * interval_size)):
        m_suffix = i.to_bytes(interval_size, "big")
        message = known_message + m_suffix
        if crc32(message) == ctcs.crc32:
            return message, fixed_xor(message, ctcs.ciphertext)
    raise Exception


def main() -> None:
    """Entry point"""
    assert int.from_bytes(crc32(b"123456789"), "big") == 0xfc891918

    encrypted_flag = to_bytes(0x22360906580dc6f4d26fc4b0d8327932d87cf1)

    data = []
    with open("data/data.txt") as data_fd:
        for line in data_fd.readlines():
            encrypted_message = bytes.fromhex(line.strip())
            data.append(ciphertext_checksum(encrypted_message))

    data.sort(key=lambda x: len(x.ciphertext))

    keystream = b""
    for ctcs in data:
        _, keystream = get_message_keystream(ctcs, keystream)
        print(keystream)

    flag = fixed_xor(encrypted_flag, keystream[:len(encrypted_flag)])
    print(f"Flag: {flag.decode()}")


if __name__ == "__main__":
    main()
