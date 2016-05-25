#!/usr/bin/env python3


def pkcs7_pad(block, desired_length):
    r"""
    pad using PKCS#7 padding, default blocksize is 8

    >>> pkcs7_pad(b"YELLOW SUBMARINE", 20)
    b'YELLOW SUBMARINE\x04\x04\x04\x04'
    """
    block_len = len(block)
    assert desired_length >= block_len,\
        "desired_length (%d) > len(block) %d!" % (desired_length, block_len)

    padding_byte = desired_length - block_len
    return block + bytes([padding_byte] * padding_byte)
