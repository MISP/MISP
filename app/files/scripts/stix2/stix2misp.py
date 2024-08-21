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
from misp_stix_converter import (
    ExternalSTIX2toMISPParser, InternalSTIX2toMISPParser,
    MISP_org_uuid, _from_misp)
from stix2.parsing import parse as stix2_parser


def _get_stix_parser(from_misp, args):
    arguments = {
        'distribution': args.distribution,
        'galaxies_as_tags': args.galaxies_as_tags
    }
    if args.distribution == 4 and args.sharing_group_id is not None:
        arguments['sharing_group_id'] = args.sharing_group_id
    if from_misp:
        return 'InternalSTIX2toMISPParser', arguments
    arguments.update(
        {
            'cluster_distribution': args.cluster_distribution,
            'organisation_uuid': args.org_uuid
        }
    )
    if args.cluster_distribution == 4 and args.cluster_sharing_group_id is not None:
        arguments['cluster_sharing_group_id'] = args.cluster_sharing_group_id
    return 'ExternalSTIX2toMISPParser', arguments


def _handle_return_message(traceback):
    if isinstance(traceback, dict):
        messages = []
        for key, values in traceback.items():
            messages.append(f'- {key}')
            for value in values:
                messages.append(f'  - {value}')
        return '\n '.join(messages)
    return '\n - '.join(traceback)


def _process_stix_file(args: argparse.Namespace):
    try:
        with open(args.input, 'rt', encoding='utf-8') as f:
            bundle = stix2_parser(
                f.read(), allow_custom=True, interoperability=True
            )
        stix_version = getattr(bundle, 'version', '2.1')
        to_call, arguments = _get_stix_parser(_from_misp(bundle.objects), args)
        parser = globals()[to_call]()
        parser.load_stix_bundle(bundle)
        parser.parse_stix_bundle(single_event=True, **arguments)
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
        error = type(e).__name__ + ': ' + e.__str__()
        print(json.dumps({'error': error}))
        traceback.print_tb(e.__traceback__)
        print(error, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Import STIX 2 content to MISP.')
    argparser.add_argument(
        '-i', '--input', required=True, type=Path,
        help='Input file containing STIX 2 content.'
    )
    argparser.add_argument(
        '--org_uuid', default=MISP_org_uuid,
        help='Organisation UUID to use when creating custom Galaxy clusters.'
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
    argparser.add_argument(
        '--cluster_distribution', type=int, default=0,
        help='Cluster distribution level for clusters generated from STIX 2.x objects'
    )
    argparser.add_argument(
        '--cluster_sharing_group_id', type=int,
        help='Cluster sharing group id when the cluster distribution level is 4.'
    )
    try:
        args = argparser.parse_args()
    except SystemExit as e:
        print(
            json.dumps(
                {
                    'error': 'Arguments error, please check you provided an input file name'
                }
            )
        )
        sys.exit(1)

    _process_stix_file(args)
