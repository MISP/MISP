#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Generic ZMQ client to gather events, attributes or sighting updates from a MISP instance
#
# This tool is part of the MISP core project and released under the GNU Affero
# General Public License v3.0
#
# Copyright (C) 2017 Alexandre Dulaunoy

import argparse
import sys
import zmq
import time
import pprint

pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)

parser = argparse.ArgumentParser(description='Generic ZMQ client to gather events, attributes and sighting updates from a MISP instance')
parser.add_argument("-p", "--port", default="50000", help='set TCP port of the MISP ZMQ (default: 50000)')
parser.add_argument("-r", "--host", default="127.0.0.1", help='set host of the MISP ZMQ (default: 127.0.0.1)')
parser.add_argument("-t", "--sleep", default=0.1, help='sleep time (default: 0.1)', type=int)
args = parser.parse_args()

port = args.port
host = args.host
context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://%s:%s" % (host, port))
socket.setsockopt(zmq.SUBSCRIBE, b'')

poller = zmq.Poller()
poller.register(socket, zmq.POLLIN)


def handleMessage(topic, s, message):
    print(topic, message)

while True:
    socks = dict(poller.poll(timeout=None))
    if socket in socks and socks[socket] == zmq.POLLIN:
        message = socket.recv()
        topic, s, m = message.decode('utf-8').partition(" ")
        handleMessage(topic, s, m)
        time.sleep(args.sleep)
