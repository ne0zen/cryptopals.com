#!/usr/bin/env python3

import binascii
import base64


def hex2base64(stream):
    """
    Convert hex to base64

    >>> stream = bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    ...
    >>> hex2base64(stream)
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    return base64.b64encode(stream)


def fixed_xor(msg, key):
    """
    takes two equal-length buffers and produces their XOR combination.

    >>> msg = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    ...
    >>> key = bytes.fromhex("686974207468652062756c6c277320657965")
    ...
    >>> fixed_xor(msg, key).hex()
    '746865206b696420646f6e277420706c6179'
    """
    assert len(msg) == len(key)
    result = bytearray(len(msg))

    for pos, msg_byte in enumerate(msg):
        result[pos] = msg_byte ^ key[pos]

    return result

if __name__ == '__main__':
    import doctest
    doctest.testmod()
