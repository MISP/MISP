#!/usr/bin/env python3
import sys

try:
    import zmq
except ImportError:
    print("ZeroMQ library could not be imported.", file=sys.stderr)
    sys.exit(1)

try:
    import redis
except ImportError:
    print("Redis library could not be imported.", file=sys.stderr)
    sys.exit(1)

print("OK")
sys.exit(0)
