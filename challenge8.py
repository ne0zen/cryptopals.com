#!/usr/bin/env python3


def get_streams(fname):
    with open(fname, 'rt') as f:
        for line in f:
            yield bytes.fromhex(line.strip())


def find_repeat(stream, chunk_size=16):
    """
    finds repeating chunks
    returns (chunk, number of times)
    >>> find_repeat(b'')
    ()
    >>> find_repeat(b'a'* 16 * 3)
    (b'aaaaaaaaaaaaaaaa', 3)
    >>> find_repeat(b'a'* 16 * 2 + b'b' * 16 + b'a' * 16)
    (b'aaaaaaaaaaaaaaaa', 3)
    """
    chunks = [stream[i:i + chunk_size] for i in range(0, len(stream), chunk_size)]
    for chunk in chunks:
        count = chunks.count(chunk)
        if count > 1:
            return chunk, count
    return tuple()

if __name__ == '__main__':
    for line_no, stream in enumerate(get_streams('8.txt')):
        editor_line_no = line_no + 1
        repeat = find_repeat(stream)
        if repeat:
            chunk, num = repeat
            print("on line {editor_line_no}, {chunk} repeats {num} times in {stream}".format(**locals()))
            break
