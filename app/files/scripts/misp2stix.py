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
from cybox.core.observable import Observables
from stix.core import Campaigns, CoursesOfAction, ExploitTargets, Indicators, ThreatActors
from stix.core.ttps import TTPs
from misp_stix_converter import (
    MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser, _get_events,
    _get_campaigns, _get_campaigns_footer, _get_campaigns_header,
    _get_courses_of_action, _get_courses_of_action_footer, _get_courses_of_action_header,
    _get_indicators, _get_indicators_footer, _get_indicators_header,
    _get_observables, _get_observables_footer, _get_observables_header,
    _get_threat_actors, _get_threat_actors_footer, _get_threat_actors_header,
    _get_ttps, _get_ttps_footer, _get_ttps_header
)


class StixExport:
    def __init__(self, format: str, debug: bool):
        self.__return_format = format
        self.__debug = debug

    @property
    def debug(self) -> bool:
        return self.__debug

    @property
    def return_format(self) -> str:
        return self.__return_format

    def _handle_errors(self):
        for identifier, values in self._parser.errors.items():
            values = '\n - '.join(values)
            if identifier != 'attributes_collection':
                identifier = f'MISP event {identifier}'
            print(f'Errors encountered while parsing {identifier}:\n - {values}', file=sys.stderr)

    def parse_misp_files(self, filenames: list):
        try:
            for filename in filenames:
                self._parser.parse_json_content(filename)
                self._handle_stix_output(filename)
            results = {'success': 1}
            if hasattr(self, '_output_files'):
                for feature, filename in self._output_files.items():
                    with open(filename, 'at', encoding='utf-8') as f:
                        f.write(globals()[f'_get_{feature}_footer'](self.return_format))
                results['filenames'] = tuple(self._output_files.values())
            errors = self._parser.errors
            if self._parser.errors:
                self._handle_errors()
            print(json.dumps(results))

        except Exception as e:
            error = type(e).__name__ + ': ' + e.__str__()
            print(json.dumps({'error': error}))
            traceback.print_tb(e.__traceback__)
            print(error, file=sys.stderr)
            sys.exit(1)


class StixAttributesExport(StixExport):
    def __init__(self, orgname: str, format: str, version: str, debug: bool):
        super().__init__(format, debug)
        self._parser = MISPtoSTIX1AttributesParser(orgname, version)
        self.__features = (
            'observables', 'indicators', 'ttps', 'exploit_targets',
            'courses_of_action', 'campaigns', 'threat_actors'
        )
        self._output_files = {}

    @property
    def features(self) -> tuple:
        return self.__features

    @staticmethod
    def _check_campaigns_length(campaigns: Campaigns) -> bool:
        return len(campaigns.campaign) > 0

    @staticmethod
    def _check_courses_of_action_length(courses_of_action: CoursesOfAction) -> bool:
        return len(courses_of_action.course_of_action) > 0

    @staticmethod
    def _check_exploit_targets_length(exploit_targets: ExploitTargets) -> bool:
        return len(exploit_targets.exploit_target) > 0

    @staticmethod
    def _check_indicators_length(indicators: Indicators) -> bool:
        return len(indicators.indicator) > 0

    @staticmethod
    def _check_observables_length(observables: Observables) -> bool:
        return len(observables.observables) > 0

    @staticmethod
    def _check_threat_actors_length(threat_actors: ThreatActors) -> bool:
        return len(threat_actors.threat_actor) > 0

    @staticmethod
    def _check_ttps_length(ttps: TTPs) -> bool:
        return len(ttps.ttp) > 0

    def _handle_stix_output(self, filename: str):
        for feature in self.features:
            values = getattr(self._parser.stix_package, feature)
            if values is not None and getattr(self, f'_check_{feature}_length')(values):
                if feature not in self._output_files:
                    output_file = f'{filename}_{feature}'
                    with open(output_file, 'wt', encoding='utf-8') as f:
                        f.write(globals()[f'_get_{feature}_header'](self.return_format))
                    self._output_files[feature] = output_file
                    with open(self._output_files[feature], 'at', encoding='utf-8') as f:
                        f.write(globals()[f'_get_{feature}'](values, self.return_format))
                    continue
                with open(self._output_files[feature], 'at', encoding='utf-8') as f:
                    values = globals()[f'_get_{feature}'](values, self.return_format)
                    if self.return_format == 'json':
                        values = f', {values}'
                    f.write(values)


class StixEventsExport(StixExport):
    def __init__(self, orgname: str, format: str, version: str, debug: bool):
        super().__init__(format, debug)
        self._parser = MISPtoSTIX1EventsParser(orgname, version)

    def _handle_stix_output(self, filename: str):
        with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
            package = _get_events(self._parser.stix_package, self.return_format)
            f.write(package if self.return_format == 'xml' else package.replace('stix:STIX_Package', 'stix:Package'))


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Export MISP into STIX1.')
    argparser.add_argument('-s', '--scope', default='Event', choices=('Attribute', 'Event'), help='Scope: which kind of data is exported.')
    argparser.add_argument('-v', '--version', default='1.1.1', choices=('1.1.1', '1.2'), help='STIX version (1.1.1 or 1.2).')
    argparser.add_argument('-f', '--format', default='xml', choices=('json', 'xml'), help='Output format (xml or json).')
    argparser.add_argument('-i', '--input', nargs='+', help='Input file(s) containing MISP standard format.')
    argparser.add_argument('-o', '--orgname', default='MISP', help='Default Org name to use if no Orgc value is provided.')
    argparser.add_argument('-d', '--debug', action='store_true', help='Allow debug mode with warnings.')
    try:
        args = argparser.parse_args()
    except SystemExit:
        print(json.dumps({'error': 'Arguments error, please check you entered a valid version and provided input file names.'}))
        sys.exit(1)

    if args.input is None:
        print(json.dumps({'error': 'No input file provided.'}))
        sys.exit(1)

    arguments = (args.orgname, args.format, args.version, args.debug)
    exporter = globals()[f'Stix{args.scope}sExport'](*arguments)
    exporter.parse_misp_files(args.input)
    sys.exit(0)
