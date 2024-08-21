#!/usr/bin/env python3
import json
import os
import stix2
import sys
from argparse import ArgumentParser
from compare_events import Comparer
from query_rest_client import query_misp
from stix2validator import validate_file, print_results

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
from stix2misp import ExternalStixParser, StixFromMISPParser


def externalise_event(event):
    for stix_object in event['objects']:
        if stix_object['type'] == 'report':
            if 'misp:tool="misp2stix2"' in stix_object['labels']:
                stix_object['labels'] = [label for label in stix_object['labels'] if label != 'misp:tool="misp2stix2"']


def get_external(event):
    externalise_event(event)
    return ExternalStixParser(), stix2.parse(event, allow_custom=True, interoperability=True)


def get_internal(event):
    return StixFromMISPParser(), stix2.parse(event, allow_custom=True, interoperability=True)


def query_import(filename, externalise):
    with open(filename, 'rt', encoding='utf-8') as f:
        event = json.loads(f.read())
    stix_parser, event = get_external(event) if externalise else get_internal(event)
    stix_parser.handler(event, filename, [0, 5])
    stix_parser.save_file()


if __name__ == '__main__':
    parser = ArgumentParser(description='Full process of querying data from MISP and comparing the results after a STIX export then import')
    parser.add_argument('--setup', default='setup.json', help='Path to the file containing the required setup to connect to the MISP server.')
    parser.add_argument('--eventid', nargs='+', help='Filter on Event id')
    parser.add_argument('--withAttachments', type=int, help='Export Attributes with the attachments')
    parser.add_argument('-i', '--input', type=str, help='Name of the input file to use instead of requesting MISP to gather an event.')
    parser.add_argument('-o', '--output', type=str, help='Name of the output file to save the result of the query in')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete all the files generated')
    parser.add_argument('-x', '--externalise', action='store_true', help='Make the STIX file look like it has been generated from an external source')
    args = parser.parse_args()
    if args.input:
        filenames = (f'test_json_{args.input}.json', f'test_stix2_{args.input}.json.stix2')
        query_import(f'test_stix2_{args.input}.json', args.externalise)
    else:
        if not args.output:
            sys.exit('Please provide an output name for the test files.')
        output = args.output
        filenames = []
        for return_type in ('json', 'stix2'):
            args.output = f"test_{return_type}_{output}.json"
            args.returnFormat = return_type
            query_misp(args)
            filenames.append(args.output)
        to_delete = [filename for filename in filenames]
        stix_analyse = validate_file(filenames[1])
        print_results(stix_analyse)
        query_import(filenames[1], args.externalise)
        filenames[1] = f'{filenames[1]}.stix2'
        to_delete.append(filenames[1])
    comparer = Comparer(*filenames)
    comparer.compare_attributes()
    comparer.compare_objects()
    comparer.compare_tags()
    comparer.compare_galaxies()
    comparer.compare_references()
    if args.delete and not args.input:
        for filename in to_delete:
            os.remove(filename)
