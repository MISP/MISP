#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Copyright (C) 2017-2021 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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


import json
import sys
from pathlib import Path
from stix2.base import STIXJSONEncoder

sys.path.append(str(Path(__file__).resolve().parent.parent / 'misp-stix'))
from misp_stix_converter import MISPtoSTIX20Parser


def _handle_errors(errors: dict):
    for identifier, values in errors.items():
        values = '\n - '.join(values)
        if identifier != 'attributes collection':
            identifier = f'MISP event {identifier}'
        print(f'Errors encountered while parsing {identifier}:\n - {values}', file=sys.stderr)


def _process_misp_files(input_names: list):
    try:
        parser = MISPtoSTIX20Parser()
        for name in input_names[:-1]:
            parser.parse_json_content(name)
            with open(f'{name}.out', 'wt', encoding='utf-8') as f:
                f.write(f'{json.dumps(parser.stix_objects, cls=STIXJSONEncoder)},')
        name = input_names[-1]
        parser.parse_json_content(name)
        with open(f'{name}.out', 'wt', encoding='utf-8') as f:
            f.write(json.dumps(parser.stix_objects, cls=STIXJSONEncoder))
        errors = parser.errors
        if errors:
            _handle_errors(errors)
        print(json.dumps({'success': 1}))
    except Exception as e:
        print(json.dumps({'error': e.__str__()}))


if __name__ == "__main__":
    _process_misp_files(sys.argv[1:])
