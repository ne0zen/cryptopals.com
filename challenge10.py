#!/usr/bin/env python3

"""
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
messages, despite the fact that a block cipher natively only transforms
individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before
the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector, or
IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making
it encrypt instead of decrypt (verify this by decrypting whatever you encrypt
to test), and using your XOR function from the previous exercise to combine
them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW
SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
What's the point of even doing this stuff if you aren't going to learn from it?
"""

import math


from Crypto.Cipher import AES


from challenge5 import repeating_xor
from challenge9 import pkcs7_pad


BLOCK_SIZE_IN_BYTES = 16


def aes_ecb_encrypt(key, stream):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.encrypt(stream)


def aes_ecb_decrypt(key, stream):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.decrypt(stream)


# TODO: these aes_cbc_* functions are quite similar
def aes_cbc_encrypt(key, iv, stream):
    fail_msg = "stream should be a multiple of %d, size actually: %d" \
           % (BLOCK_SIZE_IN_BYTES, len(stream))
    assert len(stream) % BLOCK_SIZE_IN_BYTES == 0, fail_msg

    blocks = block_split(stream)

    result = []
    for idx, pt_block in enumerate(blocks):
        last_block = iv if idx == 0 else result[-1]

        # pad block if its too small...
        # TODO: should only be needed on the last block
        if len(pt_block) < BLOCK_SIZE_IN_BYTES:
            pt_block = pkcs7_pad(pt_block, BLOCK_SIZE_IN_BYTES)

        ct_block = aes_ecb_encrypt(key, repeating_xor(last_block, pt_block))
        result.append(ct_block)

    return bytes().join(result)


def aes_cbc_decrypt(key, iv, stream):
    fail_msg = "stream should be a multiple of %d, size actually: %d" \
           % (BLOCK_SIZE_IN_BYTES, len(stream))
    assert len(stream) % BLOCK_SIZE_IN_BYTES == 0, fail_msg

    blocks = block_split(stream)

    last_block = None
    result = []
    for idx, ct_block in enumerate(blocks):
        if idx == 0:
            last_block = iv

        pt_block = repeating_xor(last_block, aes_ecb_decrypt(key, ct_block))
        last_block = ct_block
        result.append(pt_block)

    return bytes().join(result)


def block_split(stream, block_size=BLOCK_SIZE_IN_BYTES):
    """
    split a strem into a list of blocks of size block_size
    """
    # TODO: this could possibly be a generator
    return [stream[i:i + BLOCK_SIZE_IN_BYTES]
            for i in range(0, len(stream), BLOCK_SIZE_IN_BYTES)]


if __name__ == '__main__':
    import base64

    IV = bytes.fromhex("00" * BLOCK_SIZE_IN_BYTES)
    KEY = b"YELLOW SUBMARINE"
    NUM_BYTES_TO_CMP = BLOCK_SIZE_IN_BYTES * 4

    with open('10.txt', 'rt') as f:
        encrypted_stream = base64.b64decode(f.read())

    print("decrypted:")
    print(aes_cbc_decrypt(KEY, IV, encrypted_stream).decode())

    expected = encrypted_stream
    actual = aes_cbc_encrypt(KEY, IV, aes_cbc_decrypt(KEY, IV, expected))
    assert expected == actual, "%s != %s" % (expected, actual)
    print("AES-CBC encrypt & decrypt are symmetrical!")
