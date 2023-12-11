#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Copyright (C) 2017-2023 CIRCL Computer Incident Response Center Luxembourg
#    Copyright (C) 2017-2023 Christian Studer
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

_scripts_path = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_scripts_path / 'cti-python-stix2'))
sys.path.insert(1, str(_scripts_path / 'python-stix'))
sys.path.insert(2, str(_scripts_path / 'python-cybox'))
sys.path.insert(3, str(_scripts_path / 'mixbox'))
sys.path.insert(4, str(_scripts_path / 'misp-stix'))
from misp_stix_converter import (
    ExternalSTIX2toMISPParser, InternalSTIX2toMISPParser, _from_misp)
from stix2.parsing import parse as stix2_parser


def _handle_return_message(traceback):
    if isinstance(traceback, dict):
        messages = []
        for key, values in traceback.items():
            messages.append(f'- {key}')
            for value in values:
                messages.append(f'  - {value}')
        return '\n '.join(messages)
    return '\n - '.join(traceback)


def _process_stix_file(args: argparse.ArgumentParser):
    try:
        with open(args.input, 'rt', encoding='utf-8') as f:
            bundle = stix2_parser(
                f.read(), allow_custom=True, interoperability=True
            )
        stix_version = getattr(bundle, 'version', '2.1')
        to_call = 'Internal' if _from_misp(bundle.objects) else 'External'
        arguments = {
            'distribution': args.distribution,
            'galaxies_as_tags': args.galaxies_as_tags
        }
        if args.distribution == 4 and args.sharing_group_id is not None:
            arguments['sharing_group_id'] = args.sharing_group_id
        parser = globals()[f'{to_call}STIX2toMISPParser'](**arguments)
        parser.load_stix_bundle(bundle)
        parser.parse_stix_bundle()
        with open(f'{args.input}.out', 'wt', encoding='utf-8') as f:
            f.write(parser.misp_event.to_json())
        print(
            json.dumps(
                {
                    'success': 1,
                    'stix_version': stix_version
                }
            )
        )
        if args.debug:
            for feature in ('errors', 'warnings'):
                if getattr(parser, feature):
                    message = _handle_return_message(getattr(parser, feature))
                    print(
                        f'{feature.title()} encountered while importing '
                        f'STIX {stix_version} content:\n {message}',
                        file=sys.stderr
                    )
    except Exception as e:
        print(json.dumps({'error': e.__str__()}))
        traceback.print_tb(e.__traceback__)


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Import STIX 2 content to MISP.')
    argparser.add_argument(
        '-i', '--input', required=True, type=Path,
        help='Input file containing STIX 2 content.'
    )
    argparser.add_argument(
        '--distribution', type=int, default=0,
        help='Distribution level for the resulting MISP Event.'
    )
    argparser.add_argument(
        '--sharing_group_id', type=int,
        help='Sharing group id when the distribution level is 4.'
    )
    argparser.add_argument(
        '--debug', action='store_true',
        help='Display error and warning messages.'
    )
    argparser.add_argument(
        '--galaxies_as_tags', action='store_true',
        help='Import MISP Galaxies as tag names.'
    )
    try:
        args = argparser.parse_args()
        _process_stix_file(args)
    except SystemExit:
        print(
            json.dumps(
                {
                    'error': 'Arguments error, please check you provided an input file name'
                }
            )
        )

