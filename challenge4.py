#!/usr/bin/env python3

"""Detect single-character XOR
One of the 60-character strings in (4.txt) has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)"""

import binascii

import challenge3

keyspace = range(ord('0'), ord('z'))
keyspace = range(0, 256)

def getLines(fname):
    with open(fname, 'rt') as f:
        for line in f:
            yield bytes.fromhex(line.strip())

if __name__  == '__main__':
    lines = getLines('4.txt')
    best_score = 99999999
    best_solve = None
    best_line_no = None
    # while this could likely be minimized to a single min call...
    # the result wouldn't be as readable or as debuggable
    for line_no, line in enumerate(lines):
            key = challenge3.find_key(line)
            solved = challenge3.xor_single(key, line)
            score = challenge3.score(solved)
            if score < best_score:
                try:
                    decoded = solved.decode()
                    #print(line_no, key, score, decoded)
                    best_key = key
                    best_solve = decoded
                    best_score = score
                    best_line_no = line_no
                except UnicodeDecodeError:
                    pass
    print(best_line_no, best_key, best_score, best_solve)
