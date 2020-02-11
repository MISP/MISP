#!/usr/bin/env python3
import sys
ok = True

try:
    import zmq
except ImportError:
    print("ZeroMQ library could not be imported.")
    ok = False

try:
    import redis
except ImportError:
    print("Redis library could not be imported.")
    ok = False
    
if ok:
    print("OK")
    sys.exit(0)
else:
    sys.exit(1)
