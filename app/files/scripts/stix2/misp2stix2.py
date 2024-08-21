#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Copyright (C) 2017-2021 CIRCL Computer Incident Response Center Luxembourg (securitymadein.lu gie)
#    Copyright (C) 2017-2021 Christian Studer
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Union

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
from stix2.base import STIXJSONEncoder
from misp_stix_converter import MISPtoSTIX20Parser, MISPtoSTIX21Parser


def _handle_messages(field: str, feature: dict):
    for identifier, values in feature.items():
        values = '\n - '.join(values)
        if identifier != 'attributes collection':
            identifier = f'MISP event {identifier}'
        print(
            f'{field} encountered while parsing {identifier}:\n - {values}',
            file=sys.stderr
        )


def _process_misp_files(
        version: str, input_names: Union[list, None], debug: bool):
    if input_names is None:
        print(json.dumps({'error': 'No input file provided.'}))
        sys.exit(1)
    try:
        parser = MISPtoSTIX20Parser() if version == '2.0' else MISPtoSTIX21Parser()
        for name in input_names:
            parser.parse_json_content(name)
            with open(f'{name}.out', 'wt', encoding='utf-8') as f:
                f.write(
                    json.dumps(parser.stix_objects, cls=STIXJSONEncoder)
                )
        if parser.errors:
            _handle_messages('Errors', parser.errors)
        if debug and parser.warnings:
            _handle_messages('Warnings', parser.warnings)
        print(json.dumps({'success': 1}))
    except Exception as e:
        error = type(e).__name__ + ': ' + e.__str__()
        print(json.dumps({'error': error}))
        traceback.print_tb(e.__traceback__)
        print(error, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Export MISP into STIX2.')
    argparser.add_argument(
        '-v', '--version', default='2.1', choices=['2.0', '2.1'],
        help='STIX version (2.0 or 2.1).'
    )
    argparser.add_argument(
        '-i', '--input', nargs='+', required=True,
        help='Input file(s) containing MISP standard format.'
    )
    argparser.add_argument(
        '-d', '--debug', action='store_true',
        help='Allow debug mode with warnings.'
    )
    try:
        args = argparser.parse_args()
    except SystemExit:
        print(
            json.dumps(
                {
                    'error': 'Arguments error, please check you entered a valid'
                             ' version and provided input file names.'
                }
            )
        )
        sys.exit(1)

    _process_misp_files(args.version, args.input, args.debug)
    sys.exit(0)
