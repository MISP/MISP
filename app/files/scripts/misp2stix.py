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

_current_path = Path(__file__).resolve().parent
sys.path.insert(0, str(_current_path / 'cti-python-stix2'))
sys.path.insert(1, str(_current_path / 'python-stix'))
sys.path.insert(2, str(_current_path / 'python-cybox'))
sys.path.insert(3, str(_current_path / 'mixbox'))
sys.path.insert(4, str(_current_path / 'misp-stix'))
from stix.core import STIXPackage
from misp_stix_converter import MISPtoSTIX1EventsParser, _get_json_events, _get_xml_events


def _handle_errors(errors: dict):
    for identifier, values in errors.items():
        values = '\n - '.join(values)
        if identifier != 'attributes_collection':
            identifier = f'MISP event {identifier}'
        print(f'Errors encountered while parsing {identifier}:\n - {values}', file=sys.stderr)


def _process_misp_files(orgname: str, version: str, return_format:str, input_names: Union[list, None], debug: bool):
    if input_names is None:
        print('No input file provided.', file=sys.stderr)
        print(json.dumps({'success': 1}))
        return
    try:
        parser = MISPtoSTIX1EventsParser(orgname, version)
        for name in input_names[:-1]:
            parser.parse_json_content(name)
        name = input_names[-1]
        parser.parse_json_content(name)
        with open(f'{name}.out', 'wt', encoding='utf-8') as f:
            f.write(globals()[f'_get_{return_format}_events'](parser.stix_package))
        errors = parser.errors
        if errors:
            _handle_errors(errors)
        print(json.dumps({'success': 1}))
    except Exception as e:
        print(json.dumps(
            {
                'error': e.__str__(),
                'traceback': ''.join(traceback.format_tb(e.__traceback__))
            }
        ))


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Export MISP into STIX1.')
    argparser.add_argument('-v', '--version', default='1.1.1', choices=['1.1.1', '1.2'], help='STIX version (1.1.1 or 1.2).')
    argparser.add_argument('-f', '--format', default='xml', choices=['json', 'xml'], help='Output format (xml or json).')
    argparser.add_argument('-i', '--input', nargs='+', help='Input file(s) containing MISP standard format.')
    argparser.add_argument('-o', '--orgname', default='MISP', help='Default Org name to use if no Orgc value is provided.')
    argparser.add_argument('-d', '--debug', action='store_true', help='Allow debug mode with warnings.')
    try:
        args = argparser.parse_args()
        _process_misp_files(args.orgname, args.version, args.format, args.input, args.debug)
    except SystemExit:
        print(json.dumps({'error': 'Arguments error, please check you entered a valid version and provided input file names.'}))
