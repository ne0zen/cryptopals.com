#!/usr/bin/env python3

import string

# source: https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
FREQUENCY_BY_CHAR = {
    b'A': 0.08167,
    b'B': 0.01492,
    b'C': 0.02782,
    b'D': 0.04253,
    b'E': 0.12702,
    b'F': 0.02228,
    b'G': 0.02015,
    b'H': 0.06094,
    b'I': 0.06966,
    b'J': 0.00153,
    b'K': 0.00772,
    b'L': 0.04025,
    b'M': 0.02406,
    b'N': 0.06749,
    b'O': 0.07507,
    b'P': 0.01929,
    b'Q': 0.00095,
    b'R': 0.05987,
    b'S': 0.06327,
    b'T': 0.09056,
    b'U': 0.02758,
    b'V': 0.00978,
    b'W': 0.02361,
    b'X': 0.0015,
    b'Y': 0.01974,
    b'Z': 0.00074,
    b' ': 0.20000
}
DEFAULT_KEYSPACE = bytes(string.printable, 'ascii')


def score(stream):
    """
    sigma(diff_from_freq ** 2), you want to minimize this to ensure english text
    """
    # upper case
    normalized = stream.upper()
    def num_diff_squared(char):
        return (FREQUENCY_BY_CHAR[char] * len(normalized) - (normalized.count(char))) ** 2
    sum_of_squares = round(sum(num_diff_squared(c) for c in FREQUENCY_BY_CHAR.keys()), 4)

    return sum_of_squares


def xor_single(key, cipher):
    assert 0 <= key <= 256, "key should be a single byte"
    stream = bytearray(len(cipher))
    for pos, msg_byte in enumerate(cipher):
        stream[pos] = msg_byte ^ key
    return stream


def find_key(cipher, keyspace=DEFAULT_KEYSPACE):
    """
    returns: key (single character string)
    """
    return min([(key, xor_single(key, cipher)) for key in keyspace], key=lambda t: score(t[1]))[0]


if __name__ == '__main__':
    cipher = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    key = find_key(cipher)
    solved = xor_single(key, cipher)
    print(key, solved.decode())
