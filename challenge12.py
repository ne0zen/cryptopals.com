#!/usr/bin/env python3

"""
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB
mode using a consistent but unknown key (for instance, assign a single random
key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string
by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the
oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with
1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the
cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step
anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for
instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the
oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to
the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the
first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your
dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.
Congratulations.
This is the first challenge we've given you whose solution will break real
crypto. Lots of people know that when you encrypt something in ECB mode, you
can see penguins through it. Not so many of them can decrypt the contents of
those ciphertexts, and now you can. If our experience is any guideline, this
attack will get you code execution in security tests about once a year.
"""

import base64
import os
import random
import binascii

from Crypto.Cipher import AES

from challenge11 import pad


RANDOM = random.SystemRandom()
RANDOM_KEY = None
UNKNOWN_STRING = base64.b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
""".strip())
print(len(UNKNOWN_STRING))

def encryption_oracle(msg=b""):
    global RANDOM_KEY

    # init global KEY, reuse once inited
    if not RANDOM_KEY:
        RANDOM_KEY = os.urandom(AES.block_size)

    padded_msg = pad(msg + UNKNOWN_STRING)
    return AES.new(RANDOM_KEY, mode=AES.MODE_ECB).encrypt(padded_msg)


# detect ECB (encrypt two blocks of garbage.
# compare first two blocks of resulting ciphertext, they should be equal for ECB)
def detect_ecb(encryption_oracle, block_size=16):
    detector_ct = encryption_oracle(b'A'*block_size*2)
    first_block = binascii.hexlify(detector_ct[:block_size])
    second_block = binascii.hexlify(detector_ct[block_size:block_size * 2])
    assert first_block == second_block, "doesnt look like ECB"


def solve_for_unknown_suffix():
    block_size = find_block_size(encryption_oracle)
    print("block_size found:", block_size)

    # detect ECB (encrypt two blocks of garbage.
    # compare two blocks of resulting ciphertext, they should be equal for ECB
    detect_ecb(encryption_oracle)

    ciphertext = encryption_oracle()
    length_of_ciphertext = len(ciphertext)

    # # decrypts a single block
    # known_string = b""
    # for ignored in range(block_size):
    #     # build prefix for oracle
    #     prefix = b"A" * (block_size - 1 - len(known_string))

    #     doctored_ct = encryption_oracle(prefix)[:block_size]

    #     # build possible ct blocks
    #     decrypted_char_by_possible_ct_blocks = {}
    #     for b in range(ord(' '), ord('~') + 1):
    #         stream = prefix + known_string + chr(b).encode()
    #         ct = encryption_oracle(stream)
    #         decrypted_char_by_possible_ct_blocks[ct[:block_size]] = b
    #     # print(f"unknown_string[{pos}]:", chr(decrypted_char_by_possible_ct_blocks[doctored_ct]))
    #     known_string += chr(decrypted_char_by_possible_ct_blocks[doctored_ct]).encode()
    # print("known_string:", known_string.decode())

    known_string = b""
    for padding_length in range(length_of_ciphertext - 1, 0, -1):
        print("known_string:\n", known_string.decode())
        # encrypt prefix and known string
        prefix = b"A" * padding_length
        doctored_ct = encryption_oracle(prefix)[:length_of_ciphertext]

        # build possible ct blocks
        decrypted_char_by_possible_ct = {}
        for b in range(0, 256):
            possible_char = chr(b).encode()
            doctored_pt = prefix + known_string + possible_char
            ct = encryption_oracle(doctored_pt)[:length_of_ciphertext]
            decrypted_char_by_possible_ct[ct] = possible_char
        decrypted_char = decrypted_char_by_possible_ct[doctored_ct]
        known_string += decrypted_char

def find_block_size(encryption_oracle):
    """
    finds blocksize of encryption method used in oracle
    per task instructions
    """
    for possible in range(2, 65):
        ciphertext = encryption_oracle(b"A" * possible * 2)
        slice1 = ciphertext[:possible]
        slice2 = ciphertext[possible:(possible * 2)]
        assert len(slice1) == len(slice2), "%d != %d" % (len(slice1), len(slice2))

        if slice1 == slice2:
            return possible


if __name__ == '__main__':
    # assert key set up properly
    encryption_oracle()
    assert RANDOM_KEY != None
    key1 = RANDOM_KEY
    encryption_oracle()
    assert RANDOM_KEY != None
    key2 = RANDOM_KEY
    assert key1 == key2

    solve_for_unknown_suffix()
