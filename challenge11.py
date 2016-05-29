#!/usr/bin/env python3

""" (Task)
An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a
function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly)
before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC
the other half (just use random IVs each time for CBC). Use rand(2) to decide
which to use.

Detect the block cipher mode the function is using each time. You should end up
with a piece of code that, pointed at a block box that might be encrypting ECB
or CBC, tells you which one is happening.
"""


import os
import random

from Crypto.Cipher import AES

from challenge8 import find_repeat
from challenge9 import pkcs7_pad

RANDOM = random.SystemRandom()
MODE_CHOICES = "ECB CBC".split()


def pad(stream):
    """
    convenience function to pad stream out to a multiple of AES.block_size
    """
    stream_len = len(stream)
    remainder = stream_len % AES.block_size
    if remainder == 0:
        return stream

    padding_byte = AES.block_size - remainder
    return stream + bytes([padding_byte] * padding_byte)


def gen_random_key(size=AES.block_size):
    return os.urandom(size)


def encryption_oracle(msg=b"thing thing thing thing thing", mode_string="ECB"):
    assert mode_string in MODE_CHOICES, "unknown mode_string: '%s'" % mode_string

    prefix = os.urandom(RANDOM.randint(5, 10))
    suffix = os.urandom(RANDOM.randint(5, 10))

    stream = pad(prefix + msg + suffix)

    if mode_string == 'ECB':
        mode = AES.MODE_ECB
        iv = gen_random_key()
    elif mode_string == 'CBC':
        mode = AES.MODE_CBC
        iv = bytes(AES.block_size)
    key = gen_random_key()

    return AES.new(key, IV=iv, mode=mode).encrypt(stream)


def aes_mode_detect(stream):
    if find_repeat(stream):
        return "ECB"
    else:
        return "CBC"


if __name__ == '__main__':
    for i in range(10):
        real_mode = RANDOM.choice(MODE_CHOICES)
        detected_mode = aes_mode_detect(encryption_oracle(mode_string=real_mode))
        print(
                "try #" + str(i), ", real_mode:", real_mode,
                "detected_mode: ", detected_mode,
                "correct?", real_mode == detected_mode
        )
