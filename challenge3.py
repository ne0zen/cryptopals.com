#!/usr/bin/env python3

import string


# source: Gaines. Cryptanalysis ISBN-13: 978-0-486-20097-2, Appendix
FREQUENCY_BY_CHAR = {
    b'A': .0781,
    b'B': .0128,
    b'C': .0293,
    b'D': .0411,
    b'E': .1305,
    b'F': .0288,
    b'G': .0139,
    b'H': .0585,
    b'I': .0677,
    b'J': .0023,
    b'K': .0042,
    b'L': .0360,
    b'M': .0262,
    b'N': .0728,
    b'O': .0821,
    b'P': .0216,
    b'Q': .0014,
    b'R': .0664,
    b'S': .0646,
    b'T': .0902,
    b'U': .0277,
    b'V': .01,
    b'W': .0149,
    b'X': .0030,
    b'Y': .0151,
    b'Z': .0009,
    b' ': .2,
}
DEFAULT_KEYSPACE = range(ord('0'), ord('z'))


def score(stream):
    """
    sigma(diff_from_freq ** 2), you want to minimize this to ensure english text
    """
    upper = stream.upper()
    def freq_diff_squared(char):
        return (FREQUENCY_BY_CHAR[char] - (upper.count(char)/len(upper))) ** 2
    #print(bytes(FREQUENCY_BY_CHAR.keys()))
    return sum(freq_diff_squared(c) for c in FREQUENCY_BY_CHAR.keys())


def xor_single(key, cipher):
    assert len(key) == 1, "key should be a single byte/int"
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
