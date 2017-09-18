#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json

try:
    from pymisp import MISPEncode
    from pymisp.tools import make_binary_objects
except ImportError:
    pass


def check():
    missing_dependencies = {'pydeep': False, 'lief': False, 'magic': False, 'pymisp': False}
    try:
        import pymisp  # noqa
    except ImportError:
        missing_dependencies['pymisp'] = 'Please install pydeep: pip install pymisp'
    try:
        import pydeep  # noqa
    except ImportError:
        missing_dependencies['pydeep'] = 'Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git'
    try:
        import lief  # noqa
    except ImportError:
        missing_dependencies['lief'] = 'Please install lief, documentation here: https://github.com/lief-project/LIEF'
    try:
        import magic  # noqa
    except ImportError:
        missing_dependencies['magic'] = 'Please install python-magic: pip install python-magic.'
    return json.dumps(missing_dependencies)


def make_objects(path):
    to_return = {'objects': [], 'references': []}
    fo, peo, seos = make_binary_objects(path)

    if seos:
        for s in seos:
            to_return['objects'].append(s)
            if s.ObjectReference:
                to_return['references'] += s.ObjectReference

    if peo:
        to_return['objects'].append(peo)
        if peo.ObjectReference:
            to_return['references'] += peo.ObjectReference

    if fo:
        to_return['objects'].append(fo)
        if fo.ObjectReference:
            to_return['references'] += fo.ObjectReference
    return json.dumps(to_return, cls=MISPEncode)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract indicators out of binaries and returns MISP objects.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--path", help="Path to process.")
    group.add_argument("-c", "--check", action='store_true', help="Check the dependencies.")
    args = parser.parse_args()

    if args.check:
        print(check())
    if args.path:
        obj = make_objects(args.path)
        print(obj)
