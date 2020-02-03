#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Copyright (C) 2017-2018 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#    Copyright (C) 2017-2018 Christian Studer
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

import sys
import json
import os
import time
import io
import re
import stix2
from collections import defaultdict
from pathlib import Path
from pymisp import MISPEvent, MISPObject, MISPAttribute, PyMISPInvalidFormat
from stix2misp_mapping import misp_types_mapping


class StixParser():
    _misp_dir = Path(os.path.realpath(__file__)).parents[4]
    _misp_objects_path = _misp_dir / 'app' / 'files' / 'misp-objects' / 'objects'
    _pymisp_dir = _misp_dir / 'PyMISP'
    with open(_pymisp_dir / 'pymisp' / 'data' / 'describeTypes.json', 'r') as f:
        _misp_types = json.loads(f.read())['result'].get('types')
    _galaxy_types = ('intrusion-set', 'malware', 'threat-actor', 'tool')
    _stix2misp_mapping = {'marking-definition': '_load_marking',
                             'relationship': '_load_relationship',
                             'report': '_load_report',
                             'indicator': '_parse_indicator',
                             'observed-data': '_parse_observable',
                             'identity': '_load_identity'}
    _stix2misp_mapping.update({special_type: '_load_undefined' for special_type in ('attack-pattern', 'course-of-action', 'vulnerability')})
    _stix2misp_mapping.update({galaxy_type: '_load_galaxy' for galaxy_type in _galaxy_types})
    _timeline_mapping = {'indicator': ('valid_from', 'valid_until'),
                         'observed-data': ('first_observed', 'last_observed')}

    def __init__(self):
        super().__init__()
        self.misp_event = MISPEvent()
        self.relationship = defaultdict(list)
        self.tags = set()

    def handler(self, event, filename, args):
        self.filename = filename
        self.stix_version = 'STIX {}'.format(event.get('spec_version'))
        try:
            event_distribution = args[0]
            if not isinstance(event_distribution, int):
                event_distribution = int(event_distribution) if event_distribution.isdigit() else 0
        except IndexError:
            event_distribution = 0
        try:
            attribute_distribution = args[1]
            if attribute_distribution == 'event':
                attribute_distribution = 5
            if not isinstance(attribute_distribution, int):
                attribute_distribution = int(attribute_distribution) if attribute_distribution.isdigit() else 5
        except IndexError:
            attribute_distribution = 5
        self.synonyms_to_tag_names = args[2] if len(args) > 2 else '/var/www/MISP/app/files/scripts/synonymsToTagNames.json'
        self.parse_event(event.objects)

    def _load_galaxy(self, galaxy):
        try:
            self.galaxy[galaxy['id'].split('--')[1]] = {'object': galaxy, 'used': False}
        except AttributeError:
            self.galaxy = {galaxy['id'].split('--')[1]: {'object': galaxy, 'used': False}}

    def _load_identity(self, identity):
        try:
            self.identity[identity['id'].split('--')[1]] = identity['name']
        except AttributeError:
            self.identity = {identity['id'].split('--')[1]: identity['name']}

    def _load_marking(self, marking):
        tag = self.parse_marking(marking)
        try:
            self.marking_definition[marking['id'].split('--')[1]] = {'object': tag, 'used': False}
        except AttributeError:
            self.marking_definition = {marking['id'].split('--')[1]: {'object': tag, 'used': False}}

    def _load_relationship(self, relationship):
        self.relationship[relationship.source_ref.split('--')[1]].append(relationship)

    def _load_report(self, report):
        try:
            self.report[report['id'].split('--')[1]] = report
        except AttributeError:
            self.report = {report['id'].split('--')[1]: report}

    def _load_undefined(self, stix_object):
        try:
            self.objects_to_parse[stix_object['id'].split('--')[1]] = stix_object
        except AttributeError:
            self.objects_to_parse = {stix_object['id'].split('--')[1]: stix_object}

    def save_file(self):
        event = self.misp_event.to_json()
        event = json.loads(event)
        # print(json.dumps(event, indent=4))

    ################################################################################
    ##                 PARSING FUNCTIONS USED BY BOTH SUBCLASSES.                 ##
    ################################################################################

    def create_attribute_with_tag(self, attribute_dict, marking_refs):
        attribute = MISPAttribute()
        attribute.from_dict(**attribute_dict)
        try:
            self.marking_refs[attribute.uuid] = (marking.split('--')[1] for marking in marking_refs)
        except AttributeError:
            self.marking_refs = {attribute.uuid: (marking.split('--')[1] for marking in marking_refs)}
        return attribute

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    @staticmethod
    def getTimestampfromDate(date):
        try:
            return int(date.timestamp())
        except AttributeError:
            return int(time.mktime(time.strptime(date.split('+')[0], "%Y-%m-%d %H:%M:%S")))

    @staticmethod
    def _handle_data(data):
        return io.BytesIO(data.encode())

    @staticmethod
    def parse_marking(marking):
        marking_type = marking.definition_type
        tag = getattr(marking.definition, marking_type)
        return "{}:{}".format(marking_type, tag)


class StixFromMISPParser(StixParser):
    _objects_mapping = {'asn': {'observable': 'attributes_from_asn_observable', 'pattern': 'pattern_asn'},
                         'credential': {'observable': 'observable_credential', 'pattern': 'pattern_credential'},
                         'domain-ip': {'observable': 'attributes_from_domain_ip_observable', 'pattern': 'pattern_domain_ip'},
                         'email': {'observable': 'observable_email', 'pattern': 'pattern_email'},
                         'file': {'observable': 'observable_file', 'pattern': 'pattern_file'},
                         'ip-port': {'observable': 'observable_ip_port', 'pattern': 'pattern_ip_port'},
                         'network-connection': {'observable': 'observable_connection', 'pattern': 'pattern_connection'},
                         'network-socket': {'observable': 'observable_socket', 'pattern': 'pattern_socket'},
                         'process': {'observable': 'attributes_from_process_observable', 'pattern': 'pattern_process'},
                         'registry-key': {'observable': 'attributes_from_regkey_observable', 'pattern': 'pattern_regkey'},
                         'url': {'observable': 'attributes_from_url_observable', 'pattern': 'pattern_url'},
                         'user-account': {'observable': 'attributes_from_user_account_observable',
                                          'pattern': 'attributes_from_user_account_pattern'},
                         'WindowsPEBinaryFile': {'observable': 'observable_pe', 'pattern': 'pattern_pe'},
                         'x509': {'observable': 'attributes_from_x509_observable', 'pattern': 'pattern_x509'}}
    _object_from_refs = {'course-of-action': 'parse_MISP_course_of_action', 'vulnerability': 'parse_vulnerability',
                          'custom_object': 'parse_custom'}
    _object_from_refs.update(dict.fromkeys(['indicator', 'observed-data'], 'parse_usual_object'))
    _attributes_fetcher_mapping = {'indicator': 'fetch_attributes_from_indicator',
                                    'observed-data': 'fetch_attributes_from_observable',
                                    'vulnerability': 'fetch_attributes_from_vulnerability'}

    def __init__(self):
        super().__init__()
        self._stix2misp_mapping.update({'custom_object': '_parse_custom'})

    def parse_event(self, stix_objects):
        for stix_object in stix_objects:
            object_type = stix_object['type']
            if object_type.startswith('x-misp-object'):
                object_type = 'custom_object'
            if object_type in self._stix2misp_mapping:
                getattr(self, self._stix2misp_mapping[object_type])(stix_object)
            else:
                print(f'not found: {object_type}')
            # getattr(self, self._stix2misp_mapping[object_type] if object_type in self._stix2misp_mapping else '_load_special_object')

    def _parse_custom(self, custom):
        if 'from_object' in custom['labels']:
            self.parse_custom_object(custom)
        else:
            self.parse_custom_attribute(custom)

    def _parse_indicator(self, indicator):
        if 'from_object' in indicator['labels']:
            self.parse_indicator_object(indicator)
        else:
            self.parse_indicator_attribute(indicator)

    def _parse_observable(self, observable):
        if 'from_object' in observable['labels']:
            self.parse_observable_object(observable)
        else:
            self.parse_observable_attribute(observable)

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################

    def parse_custom_object(self, custom):
        name = custom['type'].split('x-misp-object-')[1]
        misp_object = MISPObject(name, misp_objects_path_custom=self._misp_objects_path)
        misp_object.timestamp = self.getTimestampfromDate(custom['x_misp_timestamp'])
        misp_object.uuid = custom['id'].split('--')[1]
        try:
            misp_object.category = custom['category']
        except KeyError:
            misp_object.category = self.get_misp_category(custom['labels'])
        attributes = []
        for key, value in custom['x_misp_values'].items():
            attribute_type, object_relation = key.split('_')
            if isinstance(value, list):
                for single_value in value:
                    misp_object.add_attribute(**{'type': attribute_type, 'value': single_value,
                                                 'object_relation': object_relation})
            else:
                misp_object.add_attribute(**{'type': attribute_type, 'value': value,
                                             'object_relation': object_relation})
        self.misp_event.add_object(**misp_object)

    def parse_custom_attribute(self, custom):
        attribute_type = custom['type'].split('x-misp-object-')[1]
        if attribute_type not in self._misp_types:
            replacement = ' ' if attribute_type == 'named-pipe' else '|'
            attribute_type = attribute_type.replace('-', replacement)
        attribute = {'type': attribute_type,
                     'timestamp': self.getTimestampfromDate(custom['x_misp_timestamp']),
                     'to_ids': bool(custom['labels'][1].split('=')[1]),
                     'value': custom['x_misp_value'],
                     'category': self.get_misp_category(custom['labels']),
                     'uuid': custom['id'].split('--')[1]}
        if custom.get('object_marking_refs'):
            attribute = self.create_attribute_with_tag(attribute, custom['object_marking_refs'])
        self.misp_event.add_attribute(**attribute)

    def parse_indicator_attribute(self, indicator):
        attribute = self.create_attribute_dict(indicator)
        print(indicator)
        attribute['to_ids'] = True
        pattern = indicator.pattern.replace('\\\\', '\\')
        if attribute['type'] in ('malware-sample', 'attachment'):
            value, data = self.parse_attribute_pattern_with_data(pattern)
            attribute.update({feature: value for feature, value in zip(('value', 'data'), (value, io.BytesIO(data.encode())))})
        else:
            attribute['value'] = self.parse_attribute_pattern(pattern)
        if hasattr(indicator, 'object_marking_refs'):
            attribute = self.create_attribute_with_tag(attribute, indicator.object_marking_refs)
        self.misp_event.add_attribute(**attribute)


    def parse_indicator_object(self, indicator):
        object_uuid = indicator.id.split('--')[1]

    def parse_observable_attribute(self, observable):
        attribute = self.create_attribute_dict(observable)
        print(observable)
        attribute['to_ids'] = False
        objects = observable.objects
        value = misp_types_mapping[attribute['type']](objects, attribute['type'])
        if isinstance(value, tuple):
            value, data = value
            attribute['data'] = io.BytesIO(data.encode())
        attribute['value'] = value
        if hasattr(observable, 'object_marking_refs'):
            attribute = self.create_attribute_with_tag(attribute, indicator.object_marking_refs)
        self.misp_event.add_attribute(**attribute)

    def parse_observable_object(self, observable):
        object_uuid = observable.id.split('--')[1]

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    def create_attribute_dict(self, stix_object):
        labels = stix_object['labels']
        attribute_uuid = stix_object.id.split('--')[1]
        attribute = {'uuid': attribute_uuid,
                     'type': self.get_misp_type(labels),
                     'category': self.get_misp_category(labels),
                     'timestamp': self.getTimestampfromDate(stix_object.modified)}
        tags = [{'name': label} for label in labels[3:]]
        if tags:
            attribute['Tag'] = tags
        first, last = self._timeline_mapping[stix_object._type]
        first_seen = getattr(stix_object, first)
        if stix_object.created != first_seen and stix_object.modified != first_seen:
            attribute = {'first_seen': first_seen}
            if hasattr(stix_object, last):
                attribute['last_seen'] = getattr(stix_object, last)
        elif hasattr(stix_object, last):
            attribute.update({'first_seen': first_seen, 'last_seen': getattr(stix_object, last)})
        return attribute

    @staticmethod
    def get_misp_category(labels):
        return labels[1].split('=')[1].strip('"')

    @staticmethod
    def get_misp_type(labels):
        return labels[0].split('=')[1].strip('"')

    @staticmethod
    def parse_attribute_pattern(pattern):
        if ' AND ' in pattern:
            pattern_parts = pattern.strip('[]').split(' AND ')
            if len(pattern_parts) == 3:
                _, value1 = pattern_parts[2].split(' = ')
                _, value2 = pattern_parts[0].split(' = ')
                return '{}|{}'.format(value1.strip("'"), value2.strip("'"))
            else:
                _, value1 = pattern_parts[0].split(' = ')
                _, value2 = pattern_parts[1].split(' = ')
                if value1 in ("'ipv4-addr'", "'ipv6-addr'"):
                    return value2.strip("'")
                return '{}|{}'.format(value1.strip("'"), value2.strip("'"))
        else:
            return pattern.split(' = ')[1].strip("]'")

    def parse_attribute_pattern_with_data(self, pattern):
        if 'artifact:payload_bin' not in pattern:
            return self.parse_attribute_pattern(pattern)
        pattern_parts = pattern.strip('[]').split(' AND ')
        if len(pattern_parts) == 3:
            filename = pattern_parts[0].split(' = ')[1]
            md5 = pattern_parts[1].split(' = ')[1]
            return "{}|{}".format(filename.strip("'"), md5.strip("'")), pattern_parts[2].split(' = ')[1].strip("'")
        return pattern_parts[0].split(' = ')[1].strip("'"), pattern_parts[1].split(' = ')[1].strip("'")


class ExternalStixParser(StixParser):
    _object_from_refs = {'course-of-action': 'parse_course_of_action', 'vulnerability': 'parse_external_vulnerability',
                          'indicator': 'parse_external_indicator', 'observed-data': 'parse_external_observable'}
    _observable_mapping = {('artifact', 'file'): 'parse_file_object_observable',
                            ('autonomous-system',): 'parse_asn_observable',
                            ('autonomous-system', 'ipv4-addr'): 'parse_asn_observable',
                            ('autonomous-system', 'ipv6-addr'): 'parse_asn_observable',
                            ('autonomous-system', 'ipv4-addr', 'ipv6-addr'): 'parse_asn_observable',
                            ('domain-name',): 'parse_domain_ip_observable',
                            ('domain-name', 'ipv4-addr'): 'parse_domain_ip_observable',
                            ('domain-name', 'ipv6-addr'): 'parse_domain_ip_observable',
                            ('domain-name', 'ipv4-addr', 'network-traffic'): 'parse_ip_port_or_network_socket_observable',
                            ('domain-name', 'ipv6-addr', 'network-traffic'): 'parse_ip_port_or_network_socket_observable',
                            ('domain-name', 'ipv4-addr', 'ipv6-addr', 'network-traffic'): 'parse_ip_port_or_network_socket_observable',
                            ('domain-name', 'network-traffic'): 'parse_network_socket_observable',
                            ('domain-name', 'network-traffic', 'url'): 'parse_url_object_observable',
                            ('email-addr',): 'parse_email_address_observable',
                            ('email-addr', 'email-message'): 'parse_email_observable',
                            ('email-addr', 'email-message', 'file'): 'parse_email_observable',
                            ('email-message',): 'parse_email_observable',
                            ('file',): 'parse_file_observable',
                            ('ipv4-addr',): 'parse_ip_address_observable',
                            ('ipv6-addr',): 'parse_ip_address_observable',
                            ('ipv4-addr', 'network-traffic'): 'parse_ip_network_traffic_observable',
                            ('ipv6-addr', 'network-traffic'): 'parse_ip_network_traffic_observable',
                            ('mac-addr',): 'parse_mac_address_observable',
                            ('mutex',): 'parse_mutex_observable',
                            ('process',): 'parse_process_observable',
                            ('x509-certificate',): 'parse_x509_observable',
                            ('url',): 'parse_url_observable',
                            ('user-account',): 'parse_user_account_observable',
                            ('windows-registry-key',): 'parse_regkey_observable'}
    _pattern_mapping = {('directory',): 'parse_file_pattern',
                         ('directory', 'file'): 'parse_file_pattern',
                         ('domain-name',): 'parse_domain_ip_port_pattern',
                         ('domain-name', 'ipv4-addr', 'url'): 'parse_domain_ip_port_pattern',
                         ('domain-name', 'ipv6-addr', 'url'): 'parse_domain_ip_port_pattern',
                         ('email-addr',): 'parse_email_address_pattern',
                         ('file',): 'parse_file_pattern',
                         ('ipv4-addr',): 'parse_ip_address_pattern',
                         ('ipv6-addr',): 'parse_ip_address_pattern',
                         ('network-traffic',): 'parse_network_traffic_pattern',
                         ('process',): 'parse_process_pattern',
                         ('url',): 'parse_url_pattern',
                         ('user-account',): 'parse_user_account_pattern',
                         ('windows-registry-key',): 'parse_regkey_pattern',
                         ('x509-certificate',): 'parse_x509_pattern'}
    _pattern_forbidden_relations = (' LIKE ', ' FOLLOWEDBY ', ' MATCHES ', ' ISSUBSET ', ' ISSUPERSET ', ' REPEATS ')
    _single_attribute_fields = ('type', 'value', 'to_ids')

    def __init__(self):
        super().__init__()

    def parse_event(self, stix_objects):
        for stix_object in stix_objects:
            object_type = stix_object['type']
            getattr(self, self._stix2misp_mapping[object_type] if object_type in self._stix2misp_mapping else '_load_special_object')(stix_object)

    def _parse_indicator(self, indicator):
        print(f'has marking refs: {hasattr(indicator, "object_marking_refs")}')
        print(indicator.object_marking_refs)

    def _parse_observable(self, observable):
        print(f'has marking refs: {hasattr(observable, "object_marking_refs")}')

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################


def from_misp(stix_objects):
    for stix_object in stix_objects:
        if stix_object._type == "report" and 'misp:tool="misp2stix2"' in stix_object.get('labels', []):
            return True
    return False


def main(args):
    filename = Path(os.path.dirname(args[0]), args[1])
    with open(filename, 'rt', encoding='utf-8') as f:
        event = stix2.parse(f.read(), allow_custom=True, interoperability=True)
    stix_parser = StixFromMISPParser() if from_misp(event.objects) else ExternalStixParser()
    stix_parser.handler(event, filename, args[2:])
    stix_parser.save_file()
    print(1)


if __name__ == '__main__':
    main(sys.argv)
