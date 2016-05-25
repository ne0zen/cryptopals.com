#!/usr/bin/env python3

import itertools

from challenge3 import find_key as find_xor_keychar
from challenge5 import repeating_xor


MAX_KEYSIZE = 40
NUM_KEYSIZE_TO_TRY = 3
NUM_CHUNKS_FOR_AVG_HAMMING_DIST = 3


def hamming_distance(stream1, stream2):
    r"""
    The Hamming distance is just the number of differing bits

    >>> hamming_distance(b"\x00", b"\x01")
    1
    >>> hamming_distance(b"\x01", b"\x02")
    2
    >>> hamming_distance(b"this is a test", b"wokka wokka!!!")
    37
    >>> hamming_distance(b"wokka wokka!!!", b"this is a test")
    37
    """
    assert len(stream1) == len(stream2), "{} != {}".format(len(stream1), len(stream2))

    # population count of a ^ b
    count = 0
    for xor in repeating_xor(stream1, stream2):
        while(xor):
            xor &= xor - 1
            count += 1
    return count


def find_keysize(stream):
    keysize_hdist_pairs = []
    keysize = 2
    while keysize < MAX_KEYSIZE:
        # get hamming distances over first N chunks of stream
        # so we can average
        first_n_hamming_distances = list(itertools.islice(
            (hamming_distance(stream[i:i+keysize], stream[i+keysize:i+keysize*2])
                for i in range(0, keysize * NUM_CHUNKS_FOR_AVG_HAMMING_DIST, keysize)),
            0,
            NUM_CHUNKS_FOR_AVG_HAMMING_DIST
        ))

        # div average by keysize to 'weight' the avg distance
        # so bit distances over large keysizes can be compared to small keysizes w/o bias
        weighted_hdist = sum(first_n_hamming_distances) \
            / NUM_CHUNKS_FOR_AVG_HAMMING_DIST / keysize
        keysize_hdist_pairs.append((keysize, weighted_hdist))
        keysize += 1

    # smallest weighted hamming dist are most likely
    most_likely = sorted(keysize_hdist_pairs, key=lambda p: p[1])
    return list(map(lambda p: p[0], most_likely[:NUM_KEYSIZE_TO_TRY]))


def crack_repeating_xor(stream):
    keysizes = find_keysize(stream)
    keys = []
    print("possible keysizes:", keysizes)
    for keysize in keysizes:
        # 'A1B2C3' -> ['ABC', '123'] for keysize of 2
        chunks = chunker(stream, keysize, fillvalue=0)
        blocks = list(zip(*chunks))

        key = bytes(map(find_xor_keychar, blocks))
        keys.append(key)

    # find best, could again be single call to min, but this is more debuggable
    min_so_far = 999999
    best = None
    for key in keys:
        solved = repeating_xor(key, stream)
        candidate = score(solved)
        if candidate < min_so_far:
            best = (candidate, key, solved)

    return best


# utility funcs

def chunker(iterable, n, fillvalue=None):  # 'grouper' from itertools docs
    """
    Collect data into fixed-length chunks or blocks
    >>> list(grouper('ABCDEFG', 3, None))
    [('A', 'B', 'C'), ('D', 'E', 'F'), ('G', None, None)]
    """
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


if __name__ == '__main__':
    import base64
    from challenge3 import score

    key = None

    with open('6.txt', 'rt') as f:
        stream = base64.b64decode(f.read())
    print("stream len:", len(stream))
    score, key, solved = crack_repeating_xor(stream)

    print("best score:", score, "key:", key, "solved:")
    print(solved.decode())
