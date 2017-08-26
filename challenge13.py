#!/usr/bin/env python3

import urllib.parse

from Crypto.Cipher import AES
from Crypto import Random


"""
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should
take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email
address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =).
Eat them, quote them, whatever you want to do, but don't let people set their
email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

A. Encrypt the encoded user profile under the key; "provide" that to the
"attacker".
B. Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid"
ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""

def profile_for(email_address):
    """generate user profile as url parameters, each value is encoded"""
    email_address = email_address.replace('&', '')
    email_address = email_address.replace('=', '')

    return (f'email={email_address}&uid=10&role=user')


def is_admin_profile(ciphertext):
    """
    parses profile and determines whether its role is admin
    """
    profile = decryptor(ciphertext).decode()
    parsed = urllib.parse.parse_qs(profile)
    return parsed['role'][0] == 'admin'


RANDOM_KEY = None
def encryption_oracle(email):
    global RANDOM_KEY

    if not RANDOM_KEY:
        RANDOM_KEY = Random.new().read(AES.key_size[0])
    profile = profile_for(email).encode()
    padded_profile = pad(profile)

    return AES.new(RANDOM_KEY, mode=AES.MODE_ECB).encrypt(padded_profile)


## Tests
def test_end_run_around_param_encoding_doesnt_work():
    bad_email = "foo@bar.com&role=admin"
    False == is_admin_profile(encryption_oracle(bad_email))


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


def unpad(stream):
    """
    removes PKCS#7 padding off end of a decrypted stream
    e.g.

    >>> unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04')
    b'YELLOW SUBMARINE'

    >>> unpad(b'YELLOW\x02\x02')
    b'YELLOW'
    """
    num_pad_bytes = stream[-1]
    return stream[:-num_pad_bytes]


def decryptor(ciphertext):
    plaintext = AES.new(RANDOM_KEY).decrypt(ciphertext)
    return unpad(plaintext)


#          1         2         3
# 123456789012345678901234567890123456789
# email=xxxxxxxxxxxxx&uid=10&role=user # a = 0:32
#       xxxxxxxxxxadmin...........     # b = 16:32
# email=xxxxxxxxxx&uid=10&role=user

def ecb_cut_and_paste():
    first = encryption_oracle('x' * 13)
    second = encryption_oracle('x' * 10 + 'admin' + "\x0b" * 11)

    encd_admin_profile = first[:32] + second[16:32]
    print("decryptor(encd_admin_profile):", decryptor(encd_admin_profile).decode())
    assert is_admin_profile(encd_admin_profile)





if __name__ == '__main__':
    ecb_cut_and_paste()
