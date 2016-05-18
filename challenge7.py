#!/usr/bin/env python3

import base64

from Crypto.Cipher import AES

cipher = AES.new("YELLOW SUBMARINE")

with open('7.txt') as f:
    ciphertext = base64.b64decode(f.read())
    print(cipher.decrypt(ciphertext).decode())
