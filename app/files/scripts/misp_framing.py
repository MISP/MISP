#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

import importlib
MODULE_TO_DIRECTORY = {
    "stix2": "cti-python-stix2",
    "stix": "python-stix",
    "cybox": "python-cybox",
    "mixbox": "mixbox",
    "misp_stix_converter": "misp-stix",
    "maec": "python-maec",
}
_CURRENT_PATH = Path(__file__).resolve().parent
_CURRENT_PATH_IDX = 0
for module_name, dir_path in MODULE_TO_DIRECTORY.items():
    try:
        importlib.import_module(module_name)
    except ImportError:
        sys.path.insert(_CURRENT_PATH_IDX, str(_CURRENT_PATH / dir_path))
        _CURRENT_PATH_IDX += 1
from misp_stix_converter import stix1_attributes_framing, stix1_framing, stix20_framing, stix21_framing


def stix_framing(args: argparse.Namespace) -> dict:
    arguments = (args.namespace, args.orgname, args.format, args.version)
    header, separator, footer = stix1_framing(*arguments) if args.scope == 'Event' else stix1_attributes_framing(*arguments)
    return {'header': header, 'separator': separator, 'footer': footer}


def stix2_framing(args: argparse.Namespace) -> dict:
    header, separator, footer = stix20_framing(args.uuid) if args.version == '2.0' else stix21_framing(args.uuid)
    return {'header': header, 'separator': separator, 'footer': footer}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Handle framing to return header, separator and footer for a given return format.')
    subparsers = parser.add_subparsers()

    stix1_parser = subparsers.add_parser('stix1', help='STIX1 framing.')
    stix1_parser.add_argument('-s', '--scope', default='Event', choices=['Attribute', 'Event'], help='Scope: which kind of data is exported.')
    stix1_parser.add_argument('-v', '--version', default='1.1.1', choices=['1.1.1', '1.2'], help='STIX1 version (1.1.1 or 1.2).')
    stix1_parser.add_argument('-f', '--format', default='xml', choices=['json', 'xml'], help='Return format (xml or json).')
    stix1_parser.add_argument('-n', '--namespace', default='https://misp-project.org', help='Default namespace to include in the namespaces defined in the STIX header.')
    stix1_parser.add_argument('-o', '--orgname', default='MISP', help='Default Org name associated with the namespace.')
    stix1_parser.set_defaults(func=stix_framing)

    stix2_parser = subparsers.add_parser('stix2', help='STIX2 framing.')
    stix2_parser.add_argument('-v', '--version', default='2.0', choices=['2.0', '2.1'], help='STIX2 version (2.0 or 2.1).')
    stix2_parser.add_argument('--uuid', help='UUID used to identity the STIX2 bundle.')
    stix2_parser.set_defaults(func=stix2_framing)

    try:
        args = parser.parse_args()
        print(json.dumps(args.func(args)))
    except SystemExit:
        print(json.dumps({'error': 'Framing arguments error, please check requirements for each return format.'}))
