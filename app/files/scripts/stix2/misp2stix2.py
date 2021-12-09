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

_scripts_path = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_scripts_path / 'cti-python-stix2'))
sys.path.insert(1, str(_scripts_path / 'python-stix'))
sys.path.insert(2, str(_scripts_path / 'python-cybox'))
sys.path.insert(3, str(_scripts_path / 'mixbox'))
sys.path.insert(4, str(_scripts_path / 'misp-stix'))
from stix2.base import STIXJSONEncoder
from misp_stix_converter import MISPtoSTIX20Parser, MISPtoSTIX21Parser


def _handle_errors(errors: dict):
    for identifier, values in errors.items():
        values = '\n - '.join(values)
        if identifier != 'attributes collection':
            identifier = f'MISP event {identifier}'
        print(f'Errors encountered while parsing {identifier}:\n - {values}', file=sys.stderr)


def _process_misp_files(version: str, input_names: Union[list, None], debug: bool):
    if input_names is None:
        print(json.dumps({'error': 'No input file provided.'}))
        return
    try:
        parser = MISPtoSTIX20Parser() if version == '2.0' else MISPtoSTIX21Parser()
        for name in input_names:
            parser.parse_json_content(name)
            with open(f'{name}.out', 'wt', encoding='utf-8') as f:
                f.write(f'{json.dumps(parser.stix_objects, cls=STIXJSONEncoder)}')
        errors = parser.errors
        if errors:
            _handle_errors(errors)
        print(json.dumps({'success': 1}))
    except Exception as e:
        print(json.dumps({'error': e.__str__()}))
        traceback.print_tb(e.__traceback__)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Export MISP into STIX2.')
    argparser.add_argument('-v', '--version', default='2.0', choices=['2.0', '2.1'], help='STIX version (2.0 or 2.1).')
    argparser.add_argument('-i', '--input', nargs='+', help='Input file(s) containing MISP standard format.')
    argparser.add_argument('-d', '--debug', action='store_true', help='Allow debug mode with warnings.')
    try:
        args = argparser.parse_args()
        _process_misp_files(args.version, args.input, args.debug)
    except SystemExit:
        print(json.dumps({'error': 'Arguments error, please check you entered a valid version and provided input file names.'}))
