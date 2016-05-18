#!/usr/bin/env python3

import string


# constants
EXPECTED_IC = 1.73
UPPERCASE_LETTERS = bytes(string.ascii_uppercase, 'ascii')
ALPHABET_LEN = 26


def score(stream):
    upper_stream = stream.upper()

    n_times_n_minus_one = lambda n: n * n - 1
    index_of_coincidence = sum(n_times_n_minus_one(upper_stream.count(c)) for c in UPPERCASE_LETTERS) \
                            / (n_times_n_minus_one(len(stream)) / ALPHABET_LEN)

    return 1 / abs(EXPECTED_IC - index_of_coincidence) # something to maximize


def xor_single(cipher, key):
    stream = bytearray(len(cipher))
    for pos, msg_byte in enumerate(cipher):
        stream[pos] = msg_byte ^ key & 0xFF
    return stream


def find_key_solved(cipher, keyspace=range(ord('0'), ord('z'))):
    return max([(key, xor_single(cipher, key)) for key in keyspace], key=lambda t: score(t[1]))


if __name__ == '__main__':
    cipher = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    ## find max score, print decoded (doesn't keep key)
    key, solved = find_key_solved(cipher)
    print(key, solved.decode())
