#!/usr/bin/env python3


def repeating_xor(key, stream):
    r"""
    xor stream with repeating key

    >>> msg = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    >>> key = b"ICE"
    >>> repeating_xor(key, msg).hex()
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    """
    key_len = len(key)
    result = bytearray(len(stream))

    key_idx = 0
    for i, m in enumerate(stream):
        result[i] = m ^ key[key_idx]
        key_idx = (key_idx + 1) % key_len

    return result
