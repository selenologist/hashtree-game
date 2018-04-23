#!/usr/bin/env python3

import msgpack, sys, json

if __name__ == "__main__":
    encoded = sys.stdin.buffer.read();
    decoded = msgpack.unpackb(encoded, raw=False);
    j = json.dumps(decoded, indent=2)
    print(j)
