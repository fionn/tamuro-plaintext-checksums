#!/usr/bin/env python3
"""Tamuro "Plaintext Checksums" Solution"""

from typing import NamedTuple, Iterator

import crcmod

CiphertextChecksum = NamedTuple("CiphertextChecksum",
                                [("ciphertext", bytes), ("crc32", bytes)])


def ciphertext_checksum(data: bytes) -> CiphertextChecksum:
    """Factory for CiphertextChecksum objects"""
    assert len(data) > 4
    return CiphertextChecksum(data[:-4], data[-4:])


def to_bytes(x: int) -> bytes:
    """Integer to bytes"""
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def fixed_xor(a: bytes, b: bytes) -> bytes:
    """xor two byte sequences"""
    return bytes(i ^ j for (i, j) in zip(a, b, strict=True))


def crc32(m: bytes) -> bytes:
    """CRC32 from problem statement"""
    crc_function = crcmod.mkCrcFun(0x104C11DB7, rev=False, initCrc=0,
                                   xorOut=0xFFFFFFFF)
    return int(crc_function(m)).to_bytes(4, byteorder="big")


def load_data(path: str) -> Iterator[CiphertextChecksum]:
    """Yield ciphertext-checksum data from file"""
    with open(path) as data_fd:
        for line in data_fd.readlines():
            encrypted_message = bytes.fromhex(line.strip())
            yield ciphertext_checksum(encrypted_message)


def recover_keystream(ctcs: CiphertextChecksum,
                      keystream: bytes) -> bytes:
    """Recover the remaining keystream from an encrypted message"""
    interval_size = len(ctcs.ciphertext) - len(keystream)
    known_message = fixed_xor(ctcs.ciphertext[:len(keystream)], keystream)
    for i in range(2 ** (8 * interval_size)):
        m_suffix = i.to_bytes(interval_size, "big")
        message = known_message + m_suffix
        if crc32(message) == ctcs.crc32:
            return fixed_xor(message, ctcs.ciphertext)
    raise Exception


def attack(data: list[CiphertextChecksum], ciphertext: bytes) -> bytes:
    """Given a list of encrypted messages and a target ciphertext,
       return the decrypted ciphertext"""
    data.sort(key=lambda x: len(x.ciphertext))
    max_len = len(data[-1].ciphertext)

    keystream = b""
    for ctcs in data:
        keystream = recover_keystream(ctcs, keystream)
        print("0x" + keystream.hex() +  "··" * (max_len - len(keystream)),
              end="\r")
    print()

    return fixed_xor(ciphertext, keystream[:len(ciphertext)])


def main() -> None:
    """Entry point"""
    assert int.from_bytes(crc32(b"123456789"), "big") == 0xfc891918

    # Original message
    ciphertext = to_bytes(0xf3561b60119a18e67b6e96)
    data = list(load_data("data/data_74b627d.txt"))
    message = attack(data, ciphertext)
    print(f"m₀ = {message.decode()}")

    # Updated message
    ciphertext = to_bytes(0x22360906580dc6f4d26fc4b0d8327932d87cf1)
    data = list(load_data("data/data.txt"))
    message = attack(data, ciphertext)
    print(f"m₁ = {message.decode()}")


if __name__ == "__main__":
    main()
