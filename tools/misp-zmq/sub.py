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
import json
import time
import pprint

pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)

parser = argparse.ArgumentParser(description='Generic ZMQ client to gather events, attributes and sighting updates from a MISP instance')
parser.add_argument("-s","--stats", default=False, action='store_true', help='print regular statistics on stderr')
parser.add_argument("-p","--port", default="50000", help='set TCP port of the MISP ZMQ (default: 50000)')
parser.add_argument("-r","--host", default="127.0.0.1", help='set host of the MISP ZMQ (default: 127.0.0.1)')
parser.add_argument("-o","--only", action="append", default=None, help="set filter (misp_json, misp_json_event, misp_json_attribute or misp_json_sighting) to limit the output a specific type (default: no filter)")
parser.add_argument("-t","--sleep", default=0.1, help='sleep time (default: 0.1)', type=int)
args = parser.parse_args()

if args.only is not None:
        filters = []
        for v in args.only:
                filters.append(v)
        sys.stderr.write("Following filters applied: {}\n".format(filters))
        sys.stderr.flush()

port = args.port
host = args.host
context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect ("tcp://%s:%s" % (host, port))
socket.setsockopt(zmq.SUBSCRIBE, b'')

poller = zmq.Poller()
poller.register(socket, zmq.POLLIN)

if args.stats:
    stats = dict()

while True:
    socks = dict(poller.poll(timeout=None))
    if socket in socks and socks[socket] == zmq.POLLIN:
            message = socket.recv()
            topic, s, m = message.decode('utf-8').partition(" ")
            if args.only:
                if topic not in filters:
                        continue
            print (m)
            if args.stats:
                stats[topic] = stats.get(topic, 0) + 1
                pp.pprint(stats)
            time.sleep(args.sleep)

