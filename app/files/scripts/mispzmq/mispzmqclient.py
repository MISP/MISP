#!/usr/bin/env python3
import sys
import zmq
import argparse


def main(port: int):
    context = zmq.Context()

    print("Connecting to MISP ZeroMQ server…", file=sys.stderr)
    socket = context.socket(zmq.SUB)
    socket.connect(f"tcp://localhost:{port}")
    socket.setsockopt(zmq.SUBSCRIBE, b"misp_")
    print(f"Connected to tcp://localhost:{port}", file=sys.stderr)

    while True:
        message = socket.recv()
        print(message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Example Python client for MISP ZMQ")
    parser.add_argument("--port", default=50000, type=int)
    parsed = parser.parse_args()

    try:
        main(parsed.port)
    except KeyboardInterrupt:
        pass
