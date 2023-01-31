# Tamuro Plaintext Checksums

## Challenge

This is a solution to the problem in [tkeetch/gist:b1b21f621813ff11a75930f80f1c9e5b](https://gist.github.com/tkeetch/b1b21f621813ff11a75930f80f1c9e5b) (also available in this repository at commit `5e965ba`), from [a tweet by TamuroLondon](https://twitter.com/TamuroLondon/status/1032983064182497283).

## Solution

Because we have the checksum of the plaintext, we have an oracle for whether we have a successful decryption.

The naïve brute force approach is intractable, but we can attack in order of length and record the keystream for each message.
Then xor this into the next message and only attack the remainder.
Continue until all messages are decrypted, which will give you more than enough of the keystream to decrypt the flag.

In the initial commit, the ciphertexts and encrypted flag are different. We attack both.

## Build and Run

Install `crcmod` and run `./tamuro.py`.
