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
import stix2misp_mapping
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from pymisp import MISPEvent, MISPObject, MISPAttribute, PyMISPInvalidFormat


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
    _stix2misp_mapping.update({special_type: '_parse_undefined' for special_type in ('attack-pattern', 'course-of-action', 'vulnerability')})
    _stix2misp_mapping.update({galaxy_type: '_load_galaxy' for galaxy_type in _galaxy_types})
    _special_mapping = {'attack-pattern': 'parse_attack_pattern',
                        'course-of-action': 'parse_course_of_action',
                        'vulnerability': 'parse_vulnerability'}
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
        self._synonyms_to_tag_names = args[2] if len(args) > 2 else '/var/www/MISP/app/files/scripts/synonymsToTagNames.json'
        self.parse_event(event.objects)

    def _load_galaxy(self, galaxy):
        try:
            self.galaxy[galaxy['id'].split('--')[1]] = {'tag_names': self.parse_galaxy(galaxy), 'used': False}
        except AttributeError:
            self.galaxy = {galaxy['id'].split('--')[1]: {'tag_names': self.parse_galaxy(galaxy), 'used': False}}

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
        target_uuid = relationship.target_ref.split('--')[1]
        reference = (target_uuid, relationship.relationship_type)
        source_uuid = relationship.source_ref.split('--')[1]
        self.relationship[source_uuid].append(reference)

    def _load_report(self, report):
        try:
            self.report[report['id'].split('--')[1]] = report
        except AttributeError:
            self.report = {report['id'].split('--')[1]: report}

    def _load_synonyms_to_tag_names(self):
        with open(self._synonyms_to_tag_names, 'rt', encoding='utf-8') as f:
            synonyms_to_tag_names = json.loads(f.read())
        self._synonyms_to_tag_names = synonyms_to_tag_names

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

    def _get_tag_names_from_synonym(self, name):
        try:
            return self._synonyms_to_tag_names[name]
        except TypeError:
            self._load_synonyms_to_tag_names()
            return self._synonyms_to_tag_names[name]

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

    def parse_timeline(self, stix_object):
        misp_object = {'timestamp': self.getTimestampfromDate(stix_object.modified)}
        try:
            first, last = self._timeline_mapping[stix_object._type]
            first_seen = getattr(stix_object, first)
            if stix_object.created != first_seen and stix_object.modified != first_seen:
                misp_object['first_seen'] = first_seen
                if hasattr(stix_object, last):
                    misp_object['last_seen'] = getattr(stix_object, last)
            elif hasattr(stix_object, last):
                misp_object.update({'first_seen': first_seen, 'last_seen': getattr(stix_object, last)})
        except KeyError:
            pass
        return misp_object


class StixFromMISPParser(StixParser):
    _objects_mapping = {'asn': {'observable': 'parse_asn_observable',
                                'pattern': 'parse_asn_pattern'},
                         'credential': {'observable': 'parse_credential_observable',
                                        'pattern': 'parse_credential_pattern'},
                         'domain-ip': {'observable': 'parse_domain_ip_observable',
                                       'pattern': 'parse_domain_ip_pattern'},
                         'email': {'observable': 'parse_email_observable',
                                   'pattern': 'parse_email_pattern'},
                         'file': {'observable': 'parse_file_observable',
                                  'pattern': 'parse_file_pattern'},
                         'ip-port': {'observable': 'parse_ip_port_observable',
                                     'pattern': 'parse_ip_port_pattern'},
                         'network-connection': {'observable': 'parse_network_connection_observable',
                                                'pattern': 'parse_network_connection_pattern'},
                         'network-socket': {'observable': 'parse_network_socket_observable',
                                            'pattern': 'parse_network_socket_pattern'},
                         'process': {'observable': 'parse_process_observable',
                                     'pattern': 'parse_process_pattern'},
                         'registry-key': {'observable': 'parse_regkey_observable',
                                          'pattern': 'parse_regkey_pattern'},
                         'url': {'observable': 'parse_url_observable',
                                 'pattern': 'parse_url_pattern'},
                         'user-account': {'observable': 'parse_user_account_observable',
                                          'pattern': 'parse_user_account_pattern'},
                         'WindowsPEBinaryFile': {'observable': 'parse_pe_observable',
                                                 'pattern': 'parse_pe_pattern'},
                         'x509': {'observable': 'parse_x509_observable',
                                  'pattern': 'parse_x509_pattern'}}
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
                print(f'not found: {object_type}', file=sys.stderr)

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

    def _parse_undefined(self, stix_object):
        if any(label.startswith('misp-galaxy:') for label in stix_object.get('labels', [])):
            self._load_galaxy(stix_object)
        else:
            getattr(self, self._special_mapping[stix_object._type])(stix_object)

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################

    def fill_misp_object(self, misp_object, stix_object, mapping):
        for feature, value in stix_object.items():
            if feature not in mapping:
                if feature.startswith('x_misp_'):
                    attribute = self.parse_custom_property(feature)
                else:
                    continue
            else:
                attribute = deepcopy(mapping[feature])
            attribute.update({'value': value, 'to_ids': False})
            misp_object.add_attribute(**attribute)

    def parse_attack_pattern(self, attack_pattern):
        misp_object, _ = self.create_misp_object(attack_pattern)
        if hasattr(attack_pattern, 'external_references'):
            misp_object.add_attribute(**{
                'type': 'text', 'object_relation': 'id',
                'value': attack_pattern.external_references[0]['external_id'].split('-')[1]
            })
        self.fill_misp_object(misp_object, attack_pattern, stix2misp_mapping.attack_pattern_mapping)
        self.misp_event.add_object(**misp_object)

    def parse_course_of_action(self, course_of_action):
        misp_object, _ = self.create_misp_object(course_of_action)
        self.fill_misp_object(misp_object, course_of_action, stix2misp_mapping.course_of_action_mapping)
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

    def parse_galaxy(self, galaxy):
        if hasattr(galaxy, 'labels'):
            return tuple(label for label in galaxy.labels if label.startswith('misp-galaxy:'))
        try:
            return tuple(self._get_tag_names_from_synonym(galaxy.name))
        except KeyError:
            print(f'Unknown {galaxy._type} name: {galaxy.name}', file=sys.stderr)
            return tuple()

    def parse_indicator_attribute(self, indicator):
        attribute = self.create_attribute_dict(indicator)
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
        misp_object, object_type = self.create_misp_object(indicator)
        pattern = indicator.pattern.replace('\\\\', '\\').strip('[]').split(' AND ')
        try:
            attributes = getattr(self, self._objects_mapping[object_type]['pattern'])(pattern)
        except KeyError:
            print(f"Unable to map {object_type} object:\n{indicator}", file=sys.stderr)
            return
        if isinstance(attributes, tuple):
            attributes, target_uuid = attributes
            misp_object.add_reference(target_uuid, 'includes')
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.misp_event.add_object(**misp_object)

    def parse_observable_attribute(self, observable):
        attribute = self.create_attribute_dict(observable)
        attribute['to_ids'] = False
        objects = observable.objects
        value = stix2misp_mapping.misp_types_mapping[attribute['type']](objects, attribute['type'])
        if isinstance(value, tuple):
            value, data = value
            attribute['data'] = io.BytesIO(data.encode())
        attribute['value'] = value
        if hasattr(observable, 'object_marking_refs'):
            attribute = self.create_attribute_with_tag(attribute, indicator.object_marking_refs)
        self.misp_event.add_attribute(**attribute)

    def parse_observable_object(self, observable):
        misp_object, object_type = self.create_misp_object(observable)
        observable_object = observable.objects
        try:
            attributes = getattr(self, self._objects_mapping[object_type]['observable'])(observable_object)
        except KeyError:
            print(f"Unable to map {object_type} object:\n{observable}", file=sys.stderr)
            return
        if isinstance(attributes, tuple):
            attributes, target_uuid = attributes
            misp_object.add_reference(target_uuid, 'includes')
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.misp_event.add_object(**misp_object)

    def parse_vulnerability(self, vulnerability):
        attributes = self.fill_observable_attributes(vulnerability, stix2misp_mapping.vulnerability_mapping)
        if hasattr(vulnerability, 'external_references'):
            for reference in vulnerability.external_references:
                if reference['source_name'] == 'url':
                    attributes.append({'type': 'link', 'object_relation': 'references', 'value': reference['url']})
        if len(attributes) > 1:
            vulnerability_object, _ = self.create_misp_object(vulnerability)
            for attribute in attributes:
                vulnerability_object.add_attribute(**attribute)
            self.misp_event.add_object(**vulnerability_object)
        else:
            attribute = self.create_attribute_dict(vulnerability)
            attribute['value'] = attributes[0]['value']
            self.misp_event.add_attribute(**attribute)

    ################################################################################
    ##                        OBSERVABLE PARSING FUNCTIONS                        ##
    ################################################################################

    def fill_observable_attributes(self, observable, object_mapping):
        attributes = []
        for key, value in observable.items():
            if key in object_mapping:
                attribute = deepcopy(object_mapping[key])
            elif key.startswith('x_misp_'):
                attribute = self.parse_custom_property(key)
                if isinstance(value, list):
                    for single_value in value:
                        single_attribute = {'value': single_value, 'to_ids': False}
                        single_attribute.update(attribute)
                        attributes.append(single_attribute)
                    continue
            else:
                continue
            attribute.update({'value': value, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    @staticmethod
    def filter_main_object(observable, main_type):
        references = {}
        main_objects = []
        for key, value in observable.items():
            if isinstance(value, getattr(stix2, main_type)):
                main_objects.append(value)
            else:
                references[key] = value
        return main_objects[0], references

    def parse_asn_observable(self, observable):
        attributes = []
        for observable_object in observable.values():
            attributes.extend(self.fill_observable_attributes(observable_object, stix2misp_mapping.asn_mapping))
        return attributes

    def parse_credential_observable(self, observable):
        return self.fill_observable_attributes(observable['0'], stix2misp_mapping.credential_mapping)

    @staticmethod
    def parse_domain_ip_observable(observable):
        attributes = []
        for object in observable.values():
            attribute = deepcopy(stix2misp_mapping.domain_ip_mapping[object._type])
            attribute.update({'value': object.value, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    def parse_email_observable(self, observable):
        email, references = self.filter_main_object(observable, 'EmailMessage')
        attributes = self.fill_observable_attributes(email, stix2misp_mapping.email_mapping)
        if hasattr(email, 'from_ref'):
            reference = references[email.from_ref]
            attributes.append({'type': 'email-src', 'object_relation': 'from',
                               'value': reference.value, 'to_ids': False})
        for feature in ('to_refs', 'cc_refs'):
            if hasattr(email, feature):
                for ref_id in getattr(email, feature):
                    reference = references[ref_id]
                    attributes.append({'type': 'email-dst', 'object_relation': feature.split('_')[0],
                                       'value': reference.value, 'to_ids': False})
        if hasattr(email, 'additional_header_fields'):
            attributes.extend(self.fill_observable_attributes(email.additional_header_fields, stix2misp_mapping.email_mapping))
        if hasattr(email, 'body_multipart'):
            for body_multipart in email.body_multipart:
                reference = references[body_multipart['body_raw_ref']]
                value = body_multipart['content_disposition'].split('=')[-1].strip("'")
                if 'screenshot' in body_multipart['content_disposition']:
                    attributes.append({'type': 'attachment', 'object_relation': 'screenshot', 'to_ids': False,
                                       'value': value, 'data': reference.payload_bin})
                else:
                    attributes.append({'type': 'email-attachment', 'object_relation': 'attachment',
                                       'value': value, 'to_ids': False})
        return attributes

    def parse_file_observable(self, observable):
        file, references = self.filter_main_object(observable, 'File')
        attributes = self.fill_observable_attributes(file, stix2misp_mapping.file_mapping)
        if hasattr(file, 'hashes'):
            attributes.extend(self.fill_observable_attributes(file.hashes, stix2misp_mapping.file_mapping))
        if hasattr(file, 'content_ref'):
            reference = references[file.content_ref]
            value, type = (f'{file.name}|{file.hashes["MD5"]}', 'malware-sample') if 'MD5' in file.hashes else (file.name, 'attachment')
            attributes.append({'type': type, 'object_relation': type, 'value': value,
                               'to_ids': False, 'data': reference.payload_bin})
        if hasattr(file, 'parent_directory_ref'):
            reference = references[file.parent_directory_ref]
            attributes.append({'type': 'text', 'object_relation': 'path',
                               'value': reference.path, 'to_ids': False})
        return attributes

    def parse_ip_port_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable, 'NetworkTraffic')
        references = {key: {'object': value, 'used': False} for key, value in references.items()}
        attributes = []
        for feature in ('src', 'dst'):
            port = f'{feature}_port'
            if hasattr(network_traffic, port):
                attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[port])
                attribute.update({'value': getattr(network_traffic, port), 'to_ids': False})
                attributes.append(attribute)
            ref = f'{feature}_ref'
            if hasattr(network_traffic, ref):
                attributes.append(self._parse_network_traffic_reference(references[getattr(network_traffic, ref)], feature, 'ip_port_mapping'))
        for reference in references.values():
            if not reference['used']:
                attribute = deepcopy(stix2misp_mapping.ip_port_mapping[reference['object']._type])
                attribute.update({'value': reference['object'].value, 'to_ids': False})
                attributes.append(attribute)
        return attributes

    def parse_network_connection_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable, 'NetworkTraffic')
        references = {key: {'object': value, 'used': False} for key, value in references.items()}
        attributes = self._parse_network_traffic(network_traffic, references)
        if hasattr(network_traffic, 'protocols'):
            attributes.extend(self._parse_network_traffic_protocol(protocol) for protocol in network_traffic.protocols if protocol in stix2misp_mapping.connection_protocols)
        attributes.extend(self._parse_network_traffic_references(references))
        return attributes

    def parse_network_socket_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable, 'NetworkTraffic')
        references = {key: {'object': value, 'used': False} for key, value in references.items()}
        attributes = self._parse_network_traffic(network_traffic, references)
        if hasattr(network_traffic, 'extensions') and network_traffic.extensions:
            attributes.extend(self._parse_socket_extension(network_traffic.extensions['socket-ext']))
        attributes.extend(self._parse_network_traffic_references(references))
        return attributes

    def _parse_network_traffic(self, network_traffic, references):
        attributes = []
        for feature in ('src', 'dst'):
            port = f'{feature}_port'
            if hasattr(network_traffic, port):
                attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[port])
                attribute.update({'value': getattr(network_traffic, port), 'to_ids': False})
                attributes.append(attribute)
            ref = f'{feature}_ref'
            if hasattr(network_traffic, ref):
                attributes.append(self._parse_network_traffic_reference(references[getattr(network_traffic, ref)], feature, 'network_connection_mapping'))
            if hasattr(network_traffic, f'{ref}s'):
                attributes.extend(self._parse_network_traffic_reference(references[ref], feature, 'network_connection_mapping') for ref in getattr(network_traffic, f'{ref}s'))
        return attributes

    @staticmethod
    def _parse_network_traffic_protocol(protocol):
        return {'type': 'text', 'value': protocol, 'to_ids': False,
                'object_relation': f'layer{stix2misp_mapping.connection_protocols[protocol]}-protocol'}

    @staticmethod
    def _parse_network_traffic_reference(reference, feature, mapping):
        attribute = {key: value.format(feature) for key, value in getattr(stix2misp_mapping, mapping)[reference['object']._type].items()}
        attribute.update({'value': reference['object'].value, 'to_ids': False})
        reference['used'] = True
        return attribute

    @staticmethod
    def _parse_network_traffic_references(references):
        attributes = []
        for reference in references.values():
            if not reference['used']:
                attribute = {key: value.format('dst') for key, value in stix2misp_mapping.network_connection_mapping[reference['object']._type.items()]}
                attribute.update({'value': reference['object'].value, 'to_ids': False})
                attributes.append(attribute)
        return attributes

    def parse_pe_observable(self, observable):
        pe_object = MISPObject('pe', misp_objects_path_custom=self._misp_objects_path)
        extension = observable['0']['extensions']['windows-pebinary-ext']
        self.fill_misp_object(pe_object, extension, stix2misp_mapping.pe_mapping)
        for section in extension['sections']:
            section_object = MISPObject('pe-section', misp_objects_path_custom=self._misp_objects_path)
            self.fill_misp_object(section_object, section, stix2misp_mapping.pe_section_mapping)
            if hasattr(section, 'hashes'):
                self.fill_misp_object(section_object, section.hashes, stix2misp_mapping.pe_section_mapping)
            pe_object.add_reference(section_object.uuid, 'includes')
            self.misp_event.add_object(**section_object)
        self.misp_event.add_object(**pe_object)
        return self.parse_file_observable(observable), pe_object.uuid

    def parse_process_observable(self, observable):
        references = {}
        for key, value in observable.items():
            if isinstance(value, stix2.Process) and hasattr(value, 'name'):
                process = value
            else:
                references[key] = value
        attributes = self.fill_observable_attributes(process, stix2misp_mapping.process_mapping)
        if hasattr(process, 'parent_ref'):
            attributes.append(self._parse_process_reference(references[process.parent_ref], 'parent'))
        if hasattr(process, 'child_refs'):
            for reference in process.child_refs:
                attributes.append(self._parse_process_reference(references[reference], 'child'))
        if hasattr(process, 'binary_ref'):
            reference = references[process.binary_ref]
            attribute = deepcopy(stix2misp_mapping.process_image_mapping)
            attribute.update({'value': reference.name, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    @staticmethod
    def _parse_process_reference(reference, feature):
        attribute = deepcopy(stix2misp_mapping.pid_attribute_mapping)
        attribute.update({'object_relation': f'{feature}-pid', 'value': reference.pid, 'to_ids': False})
        return attribute

    def parse_regkey_observable(self, observable):
        attributes = []
        for key, value in observable['0'].items():
            if key in stix2misp_mapping.regkey_mapping:
                attribute = deepcopy(stix2misp_mapping.regkey_mapping[key])
                attribute.update({'value': value.replace('\\\\', '\\'), 'to_ids': False})
                attributes.append(attribute)
        if 'values' in observable['0']:
            attributes.extend(self.fill_observable_attributes(observable['0'].values[0], stix2misp_mapping.regkey_mapping))
        return attributes

    @staticmethod
    def _parse_socket_extension(extension):
        attributes = []
        for element in extension:
            if element in stix2misp_mapping.network_traffic_mapping:
                attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[element])
                value = extension[element]
                if element in ('is_listening', 'is_blocking'):
                    if value is False:
                        continue
                    value = element.split('_')[1]
                attribute.update({'value': value, 'to_ids': False})
                attributes.append(attribute)
        return attributes

    def parse_url_observable(self, observable):
        attributes = []
        for object in observable.values():
            feature = 'dst_port' if isinstance(object, stix2.NetworkTraffic) else 'value'
            attribute = deepcopy(stix2misp_mapping.url_mapping[object._type])
            attribute.update({'value': getattr(object, feature), 'to_ids': False})
            attributes.append(attribute)
        return attributes

    def parse_user_account_observable(self, observable):
        observable = observable['0']
        attributes = self.fill_observable_attributes(observable, stix2misp_mapping.user_account_mapping)
        if 'extensions' in observable and 'unix-account-ext' in observable['extensions']:
            extension = observable['extensions']['unix-account-ext']
            if 'groups' in extension:
                for group in extension['groups']:
                    attributes.append({'type': 'text', 'object_relation': 'group',
                                       'to_ids': False, 'disable_correlation': True,
                                       'value': group})
            attributes.extend(self.fill_observable_attributes(extension, stix2misp_mapping.user_account_mapping))
        return attributes

    def parse_x509_observable(self, observable):
        attributes = self.fill_observable_attributes(observable['0'], stix2misp_mapping.x509_mapping)
        if hasattr(observable['0'], 'hashes') and observable['0'].hashes:
            attributes.extend(self.fill_observable_attributes(observable['0'].hashes, stix2misp_mapping.x509_mapping))
        return attributes

    ################################################################################
    ##                         PATTERN PARSING FUNCTIONS.                         ##
    ################################################################################

    def fill_pattern_attributes(self, pattern, object_mapping):
        attributes = []
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type not in object_mapping:
                if pattern_type.startswith('x_misp_'):
                    attribute = self.parse_custom_property(pattern_type)
                    attribute['value'] = pattern_value.strip("'")
                    attributes.append(attribute)
                continue
            attribute = deepcopy(object_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        return attributes

    def parse_asn_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.asn_mapping)

    def parse_credential_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.credential_mapping)

    def parse_domain_ip_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.domain_ip_mapping)

    def parse_email_pattern(self, pattern):
        attributes = []
        attachments = defaultdict(dict)
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if 'body_multipart' in pattern_type:
                pattern_type = pattern_type.split('.')
                feature = 'data' if pattern_type[-1] == 'payload_bin' else 'value'
                attachments[pattern_type[0][-2]][feature] = pattern_value.strip("'")
                continue
            if pattern_type not in stix2misp_mapping.email_mapping:
                if 'x_misp_' in pattern_type:
                    attribute = self.parse_custom_property(pattern_type)
                    attribute['value'] = pattern_value.strip("'")
                    attributes.append(attribute)
                continue
            attribute = deepcopy(stix2misp_mapping.email_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        for attachment in attachments.values():
            if 'data' in attachment:
                attribute = {'type': 'attachment', 'object_relation': 'screenshot', 'data': attachment['data']}
            else:
                attribute = {'type': 'email-attachment', 'object_relation': 'attachment'}
            attribute['value'] = attachment['value']
            attributes.append(attribute)
        return attributes

    def parse_file_pattern(self, pattern):
        attributes = []
        malware_sample = {}
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type in ("file:hashes.'md5'", 'file:name', 'file:content_ref.payload_bin'):
                malware_sample[pattern_type] = pattern_value
            if pattern_type not in stix2misp_mapping.file_mapping:
                continue
            attribute = deepcopy(stix2misp_mapping.file_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        if 'file:content_ref.payload_bin' in malware_sample:
            attributes.append({
                'type': 'malware-sample',
                'object_relation': 'malware-sample',
                'value': '|'.join(malware_sample[feature] for feature in ('file:name', "file:hashes.'md5'")),
                'data': malware_sample['file:content_ref.payload_bin']
            })
        return attributes

    def parse_ip_port_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.network_traffic_mapping)

    @staticmethod
    def parse_network_connection_pattern(pattern):
        attributes = []
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type not in stix2misp_mapping.network_traffic_mapping:
                if pattern_type.startswith('network-traffic:protocols['):
                    pattern_value = pattern_value.strip("'")
                    attributes.append({
                        'type': 'text', 'value': pattern_value,
                        'object_relation': 'layer%s-protocol' % stix2misp_mapping.connection_protocols[pattern_value]
                    })
                continue
            attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        return attributes

    @staticmethod
    def parse_network_socket_pattern(pattern):
        attributes = []
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type not in stix2misp_mapping.network_traffic_mapping:
                continue
            attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[pattern_type])
            if "network-traffic:extensions.'socket-ext'.is_" in pattern_type:
                pattern_value = pattern_type.split('_')[1]
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        return attributes

    def parse_pe_pattern(self, pattern):
        attributes = []
        sections = defaultdict(dict)
        pe = MISPObject('pe', misp_objects_path_custom=self._misp_objects_path)
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if ':extensions.' in pattern_type:
                if '.sections[' in pattern_type:
                    pattern_type = pattern_type.split('.')
                    relation = pattern_type[-1].strip("'")
                    if relation in stix2misp_mapping.pe_section_mapping:
                        sections[pattern_type[2][-2]][relation] = pattern_value.strip("'")
                else:
                    pattern_type = pattern_type.split('.')[-1]
                    if pattern_type not in stix2misp_mapping.pe_mapping:
                        if pattern_type.startswith('x_misp_'):
                            attribute = self.parse_custom_property(pattern_type)
                            attribute['value'] = pattern_value.strip("'")
                            pe.add_attribute(**attribute)
                        continue
                    attribute = deepcopy(stix2misp_mapping.pe_mapping[pattern_type])
                    attribute['value'] = pattern_value.strip("'")
                    attributes.append(attribute)
            else:
                if pattern_type not in stix2misp_mapping.file_mapping:
                    if pattern_type.startswith('x_misp_'):
                        attribute = self.parse_custom_property(pattern_type)
                        attribute['value'] = pattern_value.strip("'")
                        attributes.append(attribute)
                    continue
                attribute = deepcopy(stix2misp_mapping.file_mapping[pattern_type])
                attribute['value'] = pattern_value.strip("'")
                attributes.append(attribute)
        for section in sections.values():
            pe_section = MISPObject('pe-section', misp_objects_path_custom=self._misp_objects_path)
            for feature, value in section.items():
                attribute = deepcopy(stix2misp_mapping.pe_section_mapping[feature])
                attribute['value'] = value
                pe_section.add_attribute(**attribute)
            pe.add_reference(pe_section.uuid, 'includes')
            self.misp_event.add_object(**pe_section)
        self.misp_event.add_object(**pe)
        return attributes, pe.uuid

    def parse_process_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.process_mapping)

    def parse_regkey_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.regkey_mapping)

    def parse_url_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.url_mapping)

    @staticmethod
    def parse_user_account_pattern(pattern):
        attributes = []
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            pattern_type = pattern_type.split('.')[-1].split('[')[0] if "extensions.'unix-account-ext'" in pattern_type else pattern_type.split(':')[-1]
            if pattern_type not in stix2misp_mapping.user_account_mapping:
                continue
            attribute = deepcopy(stix2misp_mapping.user_account_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        return attributes

    def parse_x509_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, stix2misp_mapping.x509_mapping)

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    def create_attribute_dict(self, stix_object):
        labels = stix_object['labels']
        attribute_uuid = stix_object.id.split('--')[1]
        attribute = {'uuid': attribute_uuid,
                     'type': self.get_misp_type(labels),
                     'category': self.get_misp_category(labels)}
        tags = [{'name': label} for label in labels[3:]]
        if tags:
            attribute['Tag'] = tags
        attribute.update(self.parse_timeline(stix_object))
        return attribute

    def create_misp_object(self, stix_object):
        labels = stix_object['labels']
        object_type = self.get_misp_type(labels)
        misp_object = MISPObject('file' if object_type == 'WindowsPEBinaryFile' else object_type,
                                 misp_objects_path_custom=self._misp_objects_path)
        misp_object.uuid = stix_object.id.split('--')[1]
        misp_object.update(self.parse_timeline(stix_object))
        return misp_object, object_type

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

    @staticmethod
    def parse_custom_property(property):
        properties = property.split('_')
        return {'type': properties[2], 'object_relation': '-'.join(properties[3:])}


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
            if object_type in self._stix2misp_mapping:
                getattr(self, self._stix2misp_mapping[object_type])(stix_object)

    def _parse_indicator(self, indicator):
        print(f'has marking refs: {hasattr(indicator, "object_marking_refs")}')
        print(indicator.object_marking_refs)

    def _parse_observable(self, observable):
        print(f'has marking refs: {hasattr(observable, "object_marking_refs")}')

    def _parse_undefined(self, stix_object):
        try:
            self.objects_to_parse[stix_object['id'].split('--')[1]] = stix_object
        except AttributeError:
            self.objects_to_parse = {stix_object['id'].split('--')[1]: stix_object}

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################


def from_misp(stix_objects):
    for stix_object in stix_objects:
        if stix_object['type'] == "report" and 'misp:tool="misp2stix2"' in stix_object.get('labels', []):
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
