#!/usr/bin/env python3

import msgpack, sys

if __name__ == "__main__":
    encoded = sys.stdin.buffer.read();
    decoded = msgpack.unpackb(encoded);
    print(decoded)
