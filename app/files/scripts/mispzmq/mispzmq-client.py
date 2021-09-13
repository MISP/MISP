import zmq
import argparse

parser = argparse.ArgumentParser(description="ZMQ test client")
parser.add_argument("-p", "--port", default=50000, help='Set TCP port of the MISP ZMQ (default: 50000)', type=int)
parser.add_argument("-r", "--host", default="127.0.0.1", help='Set host of the MISP ZMQ (default: 127.0.0.1)')
args = parser.parse_args()

context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://{}:{}".format(args.port, args.host))
socket.setsockopt(zmq.SUBSCRIBE, b'')

while True:
    string = socket.recv()
    topic, value = string.split(b' ', 1)
    print(topic, value)
