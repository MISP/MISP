#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Copyright (C) 2017-2026 CIRCL Computer Incident Response Center Luxembourg
#    Copyright (C) 2017-2026 Christian Studer
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
    "misp_stix_converter": "misp-stix",
    "stix2": "cti-python-stix2",
    "stix": "python-stix",
    "cybox": "python-cybox",
    "mixbox": "mixbox",
    "maec": "python-maec"
}
_CURRENT_PATH = Path(__file__).resolve().parent
_CURRENT_PATH_IDX = 0
for module_name, dir_path in MODULE_TO_DIRECTORY.items():
    try:
        importlib.import_module(module_name)
    except ImportError:
        sys.path.insert(_CURRENT_PATH_IDX, str(_CURRENT_PATH / dir_path))
        _CURRENT_PATH_IDX += 1
from misp_stix_converter import (  # noqa
    MISP_org_uuid, MissingSTIXContentError, STIXInputSizeError,
    STIXLoadingError)
from misp_stix_converter.tools import (  # noqa
    get_stix1_parser, is_stix1_from_misp, load_stix1_package)


def _get_stix_parser(from_misp: bool, args: argparse.Namespace) -> tuple:
    """Which parser a document goes through, and what it is handed, is
    misp-stix's decision: the only thing this wrapper knows that misp-stix
    does not is what MISP asked the import to do with the result.

    A sharing group id only means something at distribution level 4, and the
    STIX 1 import form has no field for the title or the producer."""
    return get_stix1_parser(
        from_misp,
        distribution=args.distribution,
        sharing_group_id=(
            args.sharing_group_id if args.distribution == 4 else None
        ),
        title=None,
        producer=None,
        force_contextual_data=args.force_contextual_data,
        galaxies_as_tags=args.galaxies_as_tags,
        single_event=True,
        organisation_uuid=args.org_uuid,
        cluster_distribution=args.cluster_distribution,
        cluster_sharing_group_id=(
            args.cluster_sharing_group_id
            if args.cluster_distribution == 4 else None
        )
    )


def _handle_return_message(traceback):
    if isinstance(traceback, dict):
        messages = []
        for key, values in traceback.items():
            messages.append(f'- {key}')
            for value in values:
                messages.append(f'  - {value}')
        return '\n '.join(messages)
    return '\n - '.join(traceback)


def _error_message(error: Exception) -> str:
    """What MISP shows for a failed import: the cause in operator terms, and
    the exception class only where the failure is a bug rather than an
    input problem."""
    if isinstance(error, STIXInputSizeError):
        # upstream appends a hint about its `max_size` argument, which is not
        # something a MISP operator can act on
        message = str(error).split(' - raise the `max_size`')[0]
        return f'The STIX 1 document is too large to import: {message}'
    if isinstance(error, STIXLoadingError):
        # covers the namespace retry and the missing dependency case, which
        # keeps the `Missing python library: <name>` wording MISP's STIX
        # diagnostics hint is appended to
        return f'The STIX 1 document could not be loaded: {error}'
    if isinstance(error, MissingSTIXContentError):
        return f'The STIX 1 document contains nothing to import: {error}'
    return (
        'Internal error while importing STIX 1 content - '
        f'{type(error).__name__}: {error}'
    )


def _process_stix_file(args: argparse.Namespace):
    try:
        package = load_stix1_package(args.input)
        to_call, arguments = _get_stix_parser(
            is_stix1_from_misp(package), args
        )
        parser = to_call()
        parser.load_stix_package(package)
        parser.parse_stix_package(**arguments)
        stix_version = parser.stix_version
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
        error = _error_message(e)
        print(json.dumps({'error': error}))
        traceback.print_tb(e.__traceback__)
        print(error, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Import STIX 1 content to MISP.')
    argparser.add_argument(
        '-i', '--input', required=True, type=Path,
        help='Input file containing STIX 1 content.'
    )
    argparser.add_argument(
        '--org-uuid', default=MISP_org_uuid,
        help='Organisation UUID to use when creating custom Galaxy clusters.'
    )
    argparser.add_argument(
        '--distribution', type=int, default=0,
        help='Distribution level for the resulting MISP Event.'
    )
    argparser.add_argument(
        '--sharing-group-id', type=int,
        help='Sharing group id when the distribution level is 4.'
    )
    argparser.add_argument(
        '--debug', action='store_true',
        help='Display error and warning messages.'
    )
    argparser.add_argument(
        '--force-contextual-data', action='store_true',
        help='Convert contextual STIX objects as contextual MISP objects.'
    )
    argparser.add_argument(
        '--galaxies-as-tags', action='store_true',
        help='Import MISP Galaxies as tag names.'
    )
    argparser.add_argument(
        '--cluster-distribution', type=int, default=0,
        help='Cluster distribution level for clusters generated from STIX 1.x objects'
    )
    argparser.add_argument(
        '--cluster-sharing-group-id', type=int,
        help='Cluster sharing group id when the cluster distribution level is 4.'
    )
    try:
        args = argparser.parse_args()
    except SystemExit as e:
        print(
            json.dumps(
                {'error': 'Arguments error, please check you provided an input file name'}
            )
        )
        sys.exit(1)

    _process_stix_file(args)
