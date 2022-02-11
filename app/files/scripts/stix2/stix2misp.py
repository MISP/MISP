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
import pymisp
import stix2misp_mapping
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
_misp_dir = Path(os.path.realpath(__file__)).parents[4]
_misp_objects_path = _misp_dir / 'app' / 'files' / 'misp-objects' / 'objects'
_misp_types = pymisp.AbstractMISP().describe_types.get('types')
from pymisp import MISPEvent, MISPObject, MISPAttribute

_scripts_path = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_scripts_path / 'cti-python-stix2'))
import stix2


class StixParser():
    _galaxy_types = ('intrusion-set', 'malware', 'threat-actor', 'tool')
    _stix2misp_mapping = {'marking-definition': '_load_marking',
                          'relationship': '_load_relationship',
                          'report': '_load_report',
                          'indicator': '_parse_indicator',
                          'observed-data': '_parse_observable',
                          'identity': '_load_identity'}
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
        self.galaxy = {}
        self.marking_definition = {}

    def handler(self, event, filename, args):
        self.filename = filename
        self.stix_version = f"STIX {event['spec_version'] if event.get('spec_version') else '2.1'}"
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
        synonyms_to_tag_names = args[2] if len(args) > 2 else '/var/www/MISP/app/files/scripts/synonymsToTagNames.json'
        with open(synonyms_to_tag_names, 'rt', encoding='utf-8') as f:
            self._synonyms_to_tag_names = json.loads(f.read())
        self.parse_event(event)

    def _load_galaxy(self, galaxy):
        self.galaxy[galaxy['id'].split('--')[1]] = {'tag_names': self.parse_galaxy(galaxy), 'used': False}

    def _load_identity(self, identity):
        try:
            self.identity[identity['id'].split('--')[1]] = identity['name']
        except AttributeError:
            self.identity = {identity['id'].split('--')[1]: identity['name']}

    def _load_marking(self, marking):
        tag = self.parse_marking(marking)
        self.marking_definition[marking['id'].split('--')[1]] = {'object': tag, 'used': False}

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

    def save_file(self):
        event = self.misp_event.to_json()
        with open(f'{self.filename}.stix2', 'wt', encoding='utf-8') as f:
            f.write(event)

    ################################################################################
    ##                 PARSING FUNCTIONS USED BY BOTH SUBCLASSES.                 ##
    ################################################################################

    def handle_markings(self):
        if hasattr(self, 'marking_refs'):
            for attribute in self.misp_event.attributes:
                if attribute.uuid in self.marking_refs:
                    for marking_uuid in self.marking_refs[attribute.uuid]:
                        attribute.add_tag(self.marking_definition[marking_uuid]['object'])
                        self.marking_definition[marking_uuid]['used'] = True
        if self.marking_definition:
            for marking_definition in self.marking_definition.values():
                if not marking_definition['used']:
                    self.tags.add(marking_definition['object'])
        if self.tags:
            for tag in self.tags:
                self.misp_event.add_tag(tag)

    @staticmethod
    def _parse_email_body(body, references):
        attributes = []
        for body_multipart in body:
            reference = references.pop(body_multipart['body_raw_ref'])
            feature = body_multipart['content_disposition'].split(';')[0]
            if feature in stix2misp_mapping.email_references_mapping:
                attribute = deepcopy(stix2misp_mapping.email_references_mapping[feature])
            else:
                print(f'Unknown content disposition in the following email body: {body_multipart}', file=sys.stderr)
                continue
            if isinstance(reference, stix2.v20.observables.Artifact):
                attribute.update({
                    'value': body_multipart['content_disposition'].split('=')[-1].strip("'"),
                    'data': reference.payload_bin,
                    'to_ids': False
                })
            else:
                attribute.update({
                    'value': reference.name,
                    'to_ids': False
                })
            attributes.append(attribute)
        return attributes

    @staticmethod
    def _parse_email_references(email_message, references):
        attributes = []
        if hasattr(email_message, 'from_ref'):
            reference = references.pop(email_message.from_ref)
            attribute = {
                'value': reference.value,
                'to_ids': False
            }
            attribute.update(stix2misp_mapping.email_references_mapping['from_ref'])
            attributes.append(attribute)
        for feature in ('to_refs', 'cc_refs'):
            if hasattr(email_message, feature):
                for ref_id in getattr(email_message, feature):
                    reference = references.pop(ref_id)
                    attribute = {
                        'value': reference.value,
                        'to_ids': False
                    }
                    attribute.update(stix2misp_mapping.email_references_mapping[feature])
                    attributes.append(attribute)
        return attributes

    def parse_galaxies(self):
        for galaxy in self.galaxy.values():
            if not galaxy['used']:
                for tag_name in galaxy['tag_names']:
                    self.tags.add(tag_name)

    @staticmethod
    def _parse_network_connection_reference(feature_type, feature, value):
        if feature == 'type':
            return {type: value.format(feature_type) for type, value in stix2misp_mapping.network_traffic_references_mapping[value].items()}
        return {feature: value}

    @staticmethod
    def _parse_network_traffic_protocol(protocol):
        return {'type': 'text', 'value': protocol, 'to_ids': False,
                'object_relation': f'layer{stix2misp_mapping.connection_protocols[protocol]}-protocol'}

    @staticmethod
    def _parse_observable_reference(reference, mapping, feature=None):
        attribute = {
            'value': reference.value,
            'to_ids': False
        }
        if feature is not None:
            attribute.update({key: value.format(feature) for key, value in getattr(stix2misp_mapping, mapping)[reference._type].items()})
            return attribute
        attribute.update({key: value for key, value in getattr(stix2misp_mapping, mapping)[reference._type].items()})
        return attribute

    def parse_pe(self, extension):
        pe_object = MISPObject('pe', misp_objects_path_custom=_misp_objects_path)
        self.fill_misp_object(pe_object, extension, 'pe_mapping')
        for section in extension['sections']:
            section_object = MISPObject('pe-section', misp_objects_path_custom=_misp_objects_path)
            self.fill_misp_object(section_object, section, 'pe_section_mapping')
            if hasattr(section, 'hashes'):
                self.fill_misp_object(section_object, section.hashes, 'pe_section_mapping')
            self.misp_event.add_object(section_object)
            pe_object.add_reference(section_object.uuid, 'includes')
        self.misp_event.add_object(pe_object)
        return pe_object.uuid

    def parse_relationships(self):
        attribute_uuids = tuple(attribute.uuid for attribute in self.misp_event.attributes)
        object_uuids = tuple(object.uuid for object in self.misp_event.objects)
        for source, references in self.relationship.items():
            if source in object_uuids:
                source_object = self.misp_event.get_object_by_uuid(source)
                for reference in references:
                    target, reference = reference
                    if target in attribute_uuids or target in object_uuids:
                        source_object.add_reference(target, reference)
            elif source in attribute_uuids:
                for attribute in self.misp_event.attributes:
                    if attribute.uuid == source:
                        for reference in references:
                            target, reference = reference
                            if target in self.galaxy:
                                for tag_name in self.galaxy[target]['tag_names']:
                                    attribute.add_tag(tag_name)
                                self.galaxy[target]['used'] = True
                        break

    def parse_report(self, event_uuid=None):
        event_infos = set()
        self.misp_event.uuid = event_uuid if event_uuid and len(self.report) > 1 else tuple(self.report.keys())[0]
        for report in self.report.values():
            if hasattr(report, 'name') and report.name:
                event_infos.add(report.name)
            if hasattr(report, 'labels') and report.labels:
                for label in report.labels:
                    self.tags.add(label)
            if hasattr(report, 'object_marking_refs') and report.object_marking_refs:
                for marking_ref in report.object_marking_refs:
                    marking_ref = marking_ref.split('--')[1]
                    try:
                        self.tags.add(self.marking_definition[marking_ref]['object'])
                        self.marking_definition[marking_ref]['used'] = True
                    except KeyError:
                        continue
            if hasattr(report, 'external_references'):
                for reference in report.external_references:
                    self.misp_event.add_attribute(**{'type': 'link', 'value': reference['url']})
        if len(event_infos) == 1:
            self.misp_event.info = event_infos.pop()
        else:
            self.misp_event.info = f'Imported with MISP import script for {self.stix_version}'

    @staticmethod
    def _parse_user_account_groups(groups):
        attributes = [{'type': 'text', 'object_relation': 'group', 'to_ids': False,
                       'disable_correlation': True, 'value': group} for group in groups]
        return attributes

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    @staticmethod
    def _choose_with_priority(container, first_choice, second_choice):
        return first_choice if first_choice in container else second_choice

    def filter_main_object(self, observable, main_type, test_function='_standard_test_filter'):
        references = {}
        main_objects = []
        for key, value in observable.items():
            if getattr(self, test_function)(value, main_type):
                main_objects.append(value)
            else:
                references[key] = value
        if len(main_objects) > 1:
            print(f'More than one {main_type} objects in this observable: {observable}', file=sys.stderr)
        return main_objects[0] if main_objects else None, references

    @staticmethod
    def getTimestampfromDate(date):
        try:
            return int(date.timestamp())
        except AttributeError:
            return int(time.mktime(time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")))

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

    @staticmethod
    def _process_test_filter(value, main_type):
        _is_main_process = any(feature in value for feature in ('parent_ref', 'child_refs'))
        return isinstance(value, getattr(stix2.v20.observables, main_type)) and _is_main_process

    @staticmethod
    def _standard_test_filter(value, main_type):
        return isinstance(value, getattr(stix2.v20.observables, main_type))

    def update_marking_refs(self, attribute_uuid, marking_refs):
        try:
            self.marking_refs[attribute_uuid] = tuple(marking.split('--')[1] for marking in marking_refs)
        except AttributeError:
            self.marking_refs = {attribute_uuid: tuple(marking.split('--')[1] for marking in marking_refs)}


class StixFromMISPParser(StixParser):
    def __init__(self):
        super().__init__()
        self._stix2misp_mapping.update({'custom_object': '_parse_custom'})
        self._stix2misp_mapping.update({special_type: '_parse_undefined' for special_type in ('attack-pattern', 'course-of-action', 'vulnerability')})
        self._custom_objects = tuple(filename.name.replace('_', '-') for filename  in _misp_objects_path.glob('*') if '_' in filename.name)

    def parse_event(self, stix_event):
        for stix_object in stix_event.objects:
            object_type = stix_object['type']
            if object_type.startswith('x-misp-object'):
                object_type = 'custom_object'
            if object_type in self._stix2misp_mapping:
                getattr(self, self._stix2misp_mapping[object_type])(stix_object)
            else:
                print(f'not found: {object_type}', file=sys.stderr)
        if self.relationship:
            self.parse_relationships()
        if self.galaxy:
            self.parse_galaxies()
        if hasattr(self, 'report'):
            self.parse_report()
        self.handle_markings()

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

    def fill_misp_object(self, misp_object, stix_object, mapping,
                         to_call='_fill_observable_object_attribute'):
        for feature, value in stix_object.items():
            if feature not in getattr(stix2misp_mapping, mapping):
                if feature.startswith('x_misp_'):
                    attribute = self.parse_custom_property(feature)
                    if isinstance(value, list):
                        self._fill_misp_object_from_list(misp_object, attribute, value)
                        continue
                else:
                    continue
            else:
                attribute = deepcopy(getattr(stix2misp_mapping, mapping)[feature])
            attribute.update(getattr(self, to_call)(feature, value))
            misp_object.add_attribute(**attribute)

    @staticmethod
    def _fill_misp_object_from_list(misp_object, mapping, values):
        for value in values:
            attribute = {'value': value}
            attribute.update(mapping)
            misp_object.add_attribute(**attribute)

    def parse_attack_pattern(self, attack_pattern):
        misp_object, _ = self.create_misp_object(attack_pattern)
        if hasattr(attack_pattern, 'external_references'):
            for reference in attack_pattern.external_references:
                value = reference['external_id'].split('-')[1] if reference['source_name'] == 'capec' else reference['url']
                misp_object.add_attribute(**{
                    'type': 'text', 'object_relation': 'id',
                    'value': value
                })
        self.fill_misp_object(misp_object, attack_pattern, 'attack_pattern_mapping',
                              '_fill_observable_object_attribute')
        self.misp_event.add_object(**misp_object)

    def parse_course_of_action(self, course_of_action):
        misp_object, _ = self.create_misp_object(course_of_action)
        self.fill_misp_object(misp_object, course_of_action, 'course_of_action_mapping',
                              '_fill_observable_object_attribute')
        self.misp_event.add_object(**misp_object)

    def parse_custom_attribute(self, custom):
        attribute_type = custom['type'].split('x-misp-object-')[1]
        if attribute_type not in _misp_types:
            replacement = ' ' if attribute_type == 'named-pipe' else '|'
            attribute_type = attribute_type.replace('-', replacement)
        attribute = {'type': attribute_type,
                     'timestamp': self.getTimestampfromDate(custom['modified']),
                     'to_ids': bool(custom['labels'][1].split('=')[1]),
                     'value': custom['x_misp_value'],
                     'category': self.get_misp_category(custom['labels']),
                     'uuid': custom['id'].split('--')[1]}
        if custom.get('object_marking_refs'):
            self.update_marking_refs(attribute['uuid'], custom['object_marking_refs'])
        self.misp_event.add_attribute(**attribute)

    def parse_custom_object(self, custom):
        name = custom['type'].split('x-misp-object-')[1]
        if name in self._custom_objects:
            name = name.replace('-', '_')
        misp_object = MISPObject(name, misp_objects_path_custom=_misp_objects_path)
        misp_object.timestamp = self.getTimestampfromDate(custom['modified'])
        misp_object.uuid = custom['id'].split('--')[1]
        try:
            misp_object.category = custom['category']
        except KeyError:
            misp_object.category = self.get_misp_category(custom['labels'])
        for key, value in custom['x_misp_values'].items():
            attribute_type, object_relation = key.replace('_DOT_', '.').split('_')
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
            return [label for label in galaxy.labels if label.startswith('misp-galaxy:')]
        try:
            return self._synonyms_to_tag_names[galaxy.name]
        except KeyError:
            print(f'Unknown {galaxy._type} name: {galaxy.name}', file=sys.stderr)
            return [f'misp-galaxy:{galaxy._type}="{galaxy.name}"']

    def parse_indicator_attribute(self, indicator):
        attribute = self.create_attribute_dict(indicator)
        attribute['to_ids'] = True
        pattern = indicator.pattern.replace('\\\\', '\\')
        if attribute['type'] in ('malware-sample', 'attachment'):
            value, data = self.parse_attribute_pattern_with_data(pattern)
            attribute.update({feature: value for feature, value in zip(('value', 'data'), (value, io.BytesIO(data.encode())))})
        else:
            attribute['value'] = self.parse_attribute_pattern(pattern)
        self.misp_event.add_attribute(**attribute)

    def parse_indicator_object(self, indicator):
        misp_object, object_type = self.create_misp_object(indicator)
        pattern = self._handle_pattern(indicator.pattern).replace('\\\\', '\\').split(' AND ')
        try:
            attributes = getattr(self, stix2misp_mapping.objects_mapping[object_type]['pattern'])(pattern)
        except KeyError:
            print(f"Unable to map {object_type} object:\n{indicator}", file=sys.stderr)
            return
        if isinstance(attributes, tuple):
            attributes, target_uuid = attributes
            misp_object.add_reference(target_uuid, 'includes')
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.misp_event.add_object(misp_object)

    def parse_observable_attribute(self, observable):
        attribute = self.create_attribute_dict(observable)
        attribute['to_ids'] = False
        objects = observable.objects
        value = self.parse_single_attribute_observable(objects, attribute['type'])
        if isinstance(value, tuple):
            value, data = value
            attribute['data'] = data
        attribute['value'] = value
        self.misp_event.add_attribute(**attribute)

    def parse_observable_object(self, observable):
        misp_object, object_type = self.create_misp_object(observable)
        observable_object = observable.objects
        try:
            attributes = getattr(self, stix2misp_mapping.objects_mapping[object_type]['observable'])(observable_object)
        except KeyError:
            print(f"Unable to map {object_type} object:\n{observable}", file=sys.stderr)
            return
        if isinstance(attributes, tuple):
            attributes, target_uuid = attributes
            misp_object.add_reference(target_uuid, 'includes')
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.misp_event.add_object(misp_object)

    def parse_vulnerability(self, vulnerability):
        attributes = self.fill_observable_attributes(vulnerability, 'vulnerability_mapping')
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

    @staticmethod
    def _define_hash_type(hash_type):
        if 'sha' in hash_type:
            return f'SHA-{hash_type.split("sha")[1]}'
        return hash_type.upper() if hash_type == 'md5' else hash_type

    @staticmethod
    def _fetch_file_observable(observable_objects):
        for key, observable in observable_objects.items():
            if observable['type'] == 'file':
                return key
        return '0'

    @staticmethod
    def _fill_observable_attribute(attribute_type, object_relation, value):
        return {'type': attribute_type,
                'object_relation': object_relation,
                'value': value,
                'to_ids': False}

    def fill_observable_attributes(self, observable, object_mapping):
        attributes = []
        for key, value in observable.items():
            if key in getattr(stix2misp_mapping, object_mapping):
                attribute = deepcopy(getattr(stix2misp_mapping, object_mapping)[key])
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

    def _handle_multiple_file_fields(self, file):
        attributes = []
        for feature, attribute_type in zip(('filename', 'path', 'fullpath'), ('filename', 'text', 'text')):
            key = f'x_misp_multiple_{feature}'
            if key in file:
                attributes.append(self._fill_observable_attribute(attribute_type, feature, file.pop(key)))
            elif f'{key}s' in file:
                attributes.extend(self._fill_observable_attribute(attribute_type, feature, value) for value in file.pop(key))
        attributes.extend(self.fill_observable_attributes(file, 'file_mapping'))
        return attributes

    def parse_asn_observable(self, observable):
        attributes = []
        mapping = 'asn_mapping'
        for observable_object in observable.values():
            if isinstance(observable_object, stix2.v20.observables.AutonomousSystem):
                attributes.extend(self.fill_observable_attributes(observable_object, mapping))
            else:
                attributes.append(self._parse_observable_reference(observable_object, mapping))
        return attributes

    def _parse_attachment(self, observable):
        if len(observable) > 1:
            return self._parse_name(observable, index='1'), self._parse_payload(observable)
        return self._parse_name(observable)

    def parse_credential_observable(self, observable):
        return self.fill_observable_attributes(observable['0'], 'credential_mapping')

    def _parse_domain_ip_attribute(self, observable):
        return f'{self._parse_value(observable)}|{self._parse_value(observable, index="1")}'

    @staticmethod
    def parse_domain_ip_observable(observable):
        attributes = []
        for observable_object in observable.values():
            attribute = deepcopy(stix2misp_mapping.domain_ip_mapping[observable_object._type])
            attribute.update({'value': observable_object.value, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    @staticmethod
    def _parse_email_message(observable, attribute_type):
        return observable['0'].get(attribute_type.split('-')[1])

    def parse_email_observable(self, observable):
        email, references = self.filter_main_object(observable, 'EmailMessage')
        attributes = self.fill_observable_attributes(email, 'email_mapping')
        if hasattr(email, 'additional_header_fields'):
            attributes.extend(self.fill_observable_attributes(email.additional_header_fields, 'email_mapping'))
        attributes.extend(self._parse_email_references(email, references))
        if hasattr(email, 'body_multipart') and email.body_multipart:
            attributes.extend(self._parse_email_body(email.body_multipart, references))
        return attributes

    @staticmethod
    def _parse_email_reply_to(observable):
        return observable['0'].additional_header_fields.get('Reply-To')

    def parse_file_observable(self, observable):
        file, references = self.filter_main_object(observable, 'File')
        references = {key: {'object': value, 'used': False} for key, value in references.items()}
        file = {key: value for key, value in file.items()}
        multiple_fields = any(f'x_misp_multiple_{feature}' in file for feature in ('filename', 'path', 'fullpath'))
        attributes = self._handle_multiple_file_fields(file) if multiple_fields else self.fill_observable_attributes(file, 'file_mapping')
        if 'hashes' in file:
            attributes.extend(self.fill_observable_attributes(file['hashes'], 'file_mapping'))
        if 'content_ref' in file:
            reference = references[file['content_ref']]
            value = f'{reference["object"].name}|{reference["object"].hashes["MD5"]}'
            attributes.append({'type': 'malware-sample', 'object_relation': 'malware-sample', 'value': value,
                               'to_ids': False, 'data': reference['object'].payload_bin})
            reference['used'] = True
        if 'parent_directory_ref' in file:
            reference = references[file['parent_directory_ref']]
            attributes.append({'type': 'text', 'object_relation': 'path',
                               'value': reference['object'].path, 'to_ids': False})
            reference['used'] = True
        for reference in references.values():
            if not reference['used']:
                attributes.append({
                    'type': 'attachment',
                    'object_relation': 'attachment',
                    'value': reference['object'].name,
                    'data': reference['object'].payload_bin,
                    'to_ids': False
                })
        return attributes

    def _parse_filename_hash(self, observable, attribute_type, index='0'):
        hash_type = attribute_type.split('|')[1]
        filename = self._parse_name(observable, index=index)
        hash_value = self._parse_hash(observable, hash_type, index=index)
        return f'{filename}|{hash_value}'

    def _parse_hash(self, observable, attribute_type, index='0'):
        hash_type = self._define_hash_type(attribute_type)
        return observable[index]['hashes'].get(hash_type)

    def parse_ip_port_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable, 'NetworkTraffic')
        attributes = []
        for feature in ('src', 'dst'):
            port = f'{feature}_port'
            if hasattr(network_traffic, port):
                attribute = deepcopy(stix2misp_mapping.ip_port_mapping[port])
                attribute.update({'value': getattr(network_traffic, port), 'to_ids': False})
                attributes.append(attribute)
            ref = f'{feature}_ref'
            if hasattr(network_traffic, ref):
                attributes.append(self._parse_observable_reference(references.pop(getattr(network_traffic, ref)), 'ip_port_references_mapping', feature))
        for reference in references.values():
            attribute = deepcopy(stix2misp_mapping.ip_port_references_mapping[reference._type])
            attribute.update({'value': reference.value, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    def _parse_malware_sample(self, observable):
        if len(observable) > 1:
            value = self._parse_filename_hash(observable, 'filename|md5', '1')
            return value, self._parse_payload(observable)
        return self._parse_filename_hash(observable, 'filename|md5')

    @staticmethod
    def _parse_name(observable, index='0'):
        return observable[index].get('name')

    def _parse_network_attribute(self, observable):
        port = self._parse_port(observable, index='1')
        return f'{self._parse_value(observable)}|{port}'

    def parse_network_connection_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable, 'NetworkTraffic')
        attributes = self._parse_network_traffic(network_traffic, references)
        if hasattr(network_traffic, 'protocols'):
            attributes.extend(self._parse_network_traffic_protocol(protocol) for protocol in network_traffic.protocols if protocol in stix2misp_mapping.connection_protocols)
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, 'domain_ip_mapping'))
        return attributes

    def parse_network_socket_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable, 'NetworkTraffic')
        attributes = self._parse_network_traffic(network_traffic, references)
        if hasattr(network_traffic, 'protocols'):
            attributes.append({'type': 'text', 'object_relation': 'protocol', 'to_ids': False,
                               'value': network_traffic.protocols[0].strip("'")})
        if hasattr(network_traffic, 'extensions') and network_traffic.extensions:
            attributes.extend(self._parse_socket_extension(network_traffic.extensions['socket-ext']))
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, 'domain_ip_mapping'))
        return attributes

    def _parse_network_traffic(self, network_traffic, references):
        attributes = []
        mapping = 'network_traffic_references_mapping'
        for feature in ('src', 'dst'):
            port = f'{feature}_port'
            if hasattr(network_traffic, port):
                attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[port])
                attribute.update({'value': getattr(network_traffic, port), 'to_ids': False})
                attributes.append(attribute)
            ref = f'{feature}_ref'
            if hasattr(network_traffic, ref):
                attributes.append(self._parse_observable_reference(references.pop(getattr(network_traffic, ref)), mapping, feature))
            if hasattr(network_traffic, f'{ref}s'):
                for ref in getattr(network_traffic, f'{ref}s'):
                    attributes.append(self._parse_observable_reference(references.pop(ref), mapping, feature))
        return attributes

    @staticmethod
    def _parse_number(observable):
        return observable['0'].get('number')

    @staticmethod
    def _parse_payload(observable):
        return observable['0'].payload_bin

    def parse_pe_observable(self, observable):
        key = self._fetch_file_observable(observable)
        extension = observable[key]['extensions']['windows-pebinary-ext']
        pe_uuid = self.parse_pe(extension)
        return self.parse_file_observable(observable), pe_uuid

    @staticmethod
    def _parse_port(observable, index='0'):
        port_observable = observable[index]
        return port_observable['src_port'] if 'src_port' in port_observable else port_observable['dst_port']

    def parse_process_observable(self, observable):
        process, references = self.filter_main_object(observable, 'Process', test_function='_process_test_filter')
        attributes = self.fill_observable_attributes(process, 'process_mapping')
        if hasattr(process, 'parent_ref'):
            attributes.extend(self.fill_observable_attributes(references[process.parent_ref], 'parent_process_reference_mapping'))
        if hasattr(process, 'child_refs'):
            for reference in process.child_refs:
                attributes.extend(self.fill_observable_attributes(references[reference], 'child_process_reference_mapping'))
        if hasattr(process, 'binary_ref'):
            reference = references[process.binary_ref]
            attribute = deepcopy(stix2misp_mapping.process_image_mapping)
            attribute.update({'value': reference.name, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    @staticmethod
    def _parse_regkey_attribute(observable):
        return observable['0'].get('key')

    def parse_regkey_observable(self, observable):
        attributes = []
        for key, value in observable['0'].items():
            if key in stix2misp_mapping.regkey_mapping:
                attribute = deepcopy(stix2misp_mapping.regkey_mapping[key])
                attribute.update({'value': value.replace('\\\\', '\\'), 'to_ids': False})
                attributes.append(attribute)
        if 'values' in observable['0']:
            attributes.extend(self.fill_observable_attributes(observable['0']['values'][0], 'regkey_mapping'))
        return attributes

    def _parse_regkey_value(self, observable):
        regkey = self._parse_regkey_attribute(observable)
        return f'{regkey}|{observable["0"]["values"][0].get("data")}'

    def parse_single_attribute_observable(self, observable, attribute_type):
        if attribute_type in stix2misp_mapping.attributes_type_mapping:
            return getattr(self, stix2misp_mapping.attributes_type_mapping[attribute_type])(observable, attribute_type)
        return getattr(self, stix2misp_mapping.attributes_mapping[attribute_type])(observable)

    def _parse_socket_extension(self, extension):
        attributes = []
        extension = {key: value for key, value in extension.items()}
        if 'x_misp_text_address_family' in extension:
            extension.pop('address_family')
        for element, value in extension.items():
            if element in stix2misp_mapping.network_socket_extension_mapping:
                attribute = deepcopy(stix2misp_mapping.network_socket_extension_mapping[element])
                if element in ('is_listening', 'is_blocking'):
                    if value is False:
                        continue
                    value = element.split('_')[1]
            elif element.startswith('x_misp_'):
                attribute = self.parse_custom_property(element)
            else:
                continue
            attribute.update({'value': value, 'to_ids': False})
            attributes.append(attribute)
        return attributes

    @staticmethod
    def parse_url_observable(observable):
        attributes = []
        for object in observable.values():
            feature = 'dst_port' if isinstance(object, stix2.v20.observables.NetworkTraffic) else 'value'
            attribute = deepcopy(stix2misp_mapping.url_mapping[object._type])
            attribute.update({'value': getattr(object, feature), 'to_ids': False})
            attributes.append(attribute)
        return attributes

    def parse_user_account_observable(self, observable):
        observable = observable['0']
        attributes = self.fill_observable_attributes(observable, 'user_account_mapping')
        if 'extensions' in observable and 'unix-account-ext' in observable['extensions']:
            extension = observable['extensions']['unix-account-ext']
            if 'groups' in extension:
                attributes.extend(self._parse_user_account_groups(extension['groups']))
            attributes.extend(self.fill_observable_attributes(extension, 'user_account_mapping'))
        return attributes

    @staticmethod
    def _parse_value(observable, index='0'):
        return observable[index].get('value')

    def _parse_x509_attribute(self, observable, attribute_type):
        hash_type = attribute_type.split('-')[-1]
        return self._parse_hash(observable, hash_type)

    def parse_x509_observable(self, observable):
        attributes = self.fill_observable_attributes(observable['0'], 'x509_mapping')
        if hasattr(observable['0'], 'hashes') and observable['0'].hashes:
            attributes.extend(self.fill_observable_attributes(observable['0'].hashes, 'x509_mapping'))
        return attributes

    ################################################################################
    ##                         PATTERN PARSING FUNCTIONS.                         ##
    ################################################################################

    def fill_pattern_attributes(self, pattern, object_mapping):
        attributes = []
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type not in getattr(stix2misp_mapping, object_mapping):
                if 'x_misp_' in pattern_type:
                    attribute = self.parse_custom_property(pattern_type)
                    attribute['value'] = pattern_value.strip("'")
                    attributes.append(attribute)
                continue
            attribute = deepcopy(getattr(stix2misp_mapping, object_mapping)[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        return attributes

    def parse_asn_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'asn_mapping')

    def parse_credential_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'credential_mapping')

    def parse_domain_ip_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'domain_ip_mapping')

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
        attachment = {}
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type in stix2misp_mapping.attachment_types:
                attachment[pattern_type] = pattern_value.strip("'")
            if pattern_type not in stix2misp_mapping.file_mapping:
                continue
            attribute = deepcopy(stix2misp_mapping.file_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        if 'file:content_ref.payload_bin' in attachment:
            filename = self._choose_with_priority(attachment, 'file:content_ref.name', 'file:name')
            md5 = self._choose_with_priority(attachment, "file:content_ref.hashes.'MD5'", "file:hashes.'MD5'")
            attributes.append({
                'type': 'malware-sample',
                'object_relation': 'malware-sample',
                'value': f'{attachment[filename]}|{attachment[md5]}',
                'data': attachment['file:content_ref.payload_bin']
            })
        if 'artifact:payload_bin' in attachment:
            attributes.append({
                'type': 'attachment',
                'object_relation': 'attachment',
                'value': attachment['artifact:x_misp_text_name'] if 'artifact:x_misp_text_name' in attachment else attachment['file:name'],
                'data': attachment['artifact:payload_bin']
            })
        return attributes

    def parse_ip_port_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'ip_port_mapping')

    def parse_network_connection_pattern(self, pattern):
        attributes = []
        references = defaultdict(dict)
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            if pattern_type not in stix2misp_mapping.network_traffic_mapping:
                pattern_value = pattern_value.strip("'")
                if pattern_type.startswith('network-traffic:protocols['):
                    attributes.append({
                        'type': 'text', 'value': pattern_value,
                        'object_relation': f'layer{stix2misp_mapping.connection_protocols[pattern_value]}-protocol'
                    })
                elif any(pattern_type.startswith(f'network-traffic:{feature}_ref') for feature in ('src', 'dst')):
                    feature_type, ref = pattern_type.split(':')[1].split('_')
                    ref, feature = ref.split('.')
                    ref = f"{feature_type}_{'0' if ref == 'ref' else ref.strip('ref[]')}"
                    references[ref].update(self._parse_network_connection_reference(feature_type, feature, pattern_value))
                continue
            attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        attributes.extend(attribute for attribute in references.values())
        return attributes

    def parse_network_socket_pattern(self, pattern):
        attributes = []
        references = defaultdict(dict)
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            pattern_value = pattern_value.strip("'")
            if pattern_type not in stix2misp_mapping.network_traffic_mapping:
                if pattern_type in stix2misp_mapping.network_socket_extension_mapping:
                    attribute = deepcopy(stix2misp_mapping.network_socket_extension_mapping[pattern_type])
                    if pattern_type.startswith("network-traffic:extensions.'socket-ext'.is_"):
                        if pattern_value != 'True':
                            continue
                        pattern_value = pattern_type.split('_')[1]
                else:
                    if pattern_type.startswith('network-traffic:protocols['):
                        attributes.append({'type': 'text', 'object_relation': 'protocol', 'value': pattern_value})
                    elif any(pattern_type.startswith(f'network-traffic:{feature}_ref') for feature in ('src', 'dst')):
                        feature_type, ref = pattern_type.split(':')[1].split('_')
                        ref, feature = ref.split('.')
                        ref = f"{feature_type}_{'0' if ref == 'ref' else ref.strip('ref[]')}"
                        references[ref].update(self._parse_network_connection_reference(feature_type, feature, pattern_value))
                    continue
            else:
                attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[pattern_type])
            attribute['value'] = pattern_value
            attributes.append(attribute)
        attributes.extend(attribute for attribute in references.values())
        return attributes

    def parse_pe_pattern(self, pattern):
        attributes = []
        sections = defaultdict(dict)
        pe = MISPObject('pe', misp_objects_path_custom=_misp_objects_path)
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
                    pe.add_attribute(**attribute)
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
            pe_section = MISPObject('pe-section', misp_objects_path_custom=_misp_objects_path)
            for feature, value in section.items():
                attribute = deepcopy(stix2misp_mapping.pe_section_mapping[feature])
                attribute['value'] = value
                pe_section.add_attribute(**attribute)
            self.misp_event.add_object(pe_section)
            pe.add_reference(pe_section.uuid, 'includes')
        self.misp_event.add_object(pe)
        return attributes, pe.uuid

    def parse_process_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'process_mapping')

    def parse_regkey_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'regkey_mapping')

    def parse_url_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'url_mapping')

    @staticmethod
    def parse_user_account_pattern(pattern):
        attributes = []
        for pattern_part in pattern:
            pattern_type, pattern_value = pattern_part.split(' = ')
            pattern_type = pattern_type.split('.')[-1].split('[')[0] if "extensions.'unix-account-ext'" in pattern_type else pattern_type.split(':')[-1]
            if pattern_type not in stix2misp_mapping.user_account_mapping:
                if pattern_type.startswith('group'):
                    attributes.append({'type': 'text', 'object_relation': 'group', 'value': pattern_value.strip("'")})
                continue
            attribute = deepcopy(stix2misp_mapping.user_account_mapping[pattern_type])
            attribute['value'] = pattern_value.strip("'")
            attributes.append(attribute)
        return attributes

    def parse_x509_pattern(self, pattern):
        return self.fill_pattern_attributes(pattern, 'x509_mapping')

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
        if hasattr(stix_object, 'description') and stix_object.description:
            attribute['comment'] = stix_object.description
        if hasattr(stix_object, 'object_marking_refs'):
            self.update_marking_refs(attribute_uuid, stix_object.object_marking_refs)
        return attribute

    def create_misp_object(self, stix_object):
        labels = stix_object['labels']
        object_type = self.get_misp_type(labels)
        misp_object = MISPObject('file' if object_type == 'WindowsPEBinaryFile' else object_type,
                                 misp_objects_path_custom=_misp_objects_path)
        misp_object.uuid = stix_object.id.split('--')[1]
        if hasattr(stix_object, 'description') and stix_object.description:
            misp_object.comment = stix_object.description
        misp_object.update(self.parse_timeline(stix_object))
        return misp_object, object_type

    @staticmethod
    def _fill_object_attribute(feature, value):
        return {'value': str(value) if feature in ('entropy', 'size') else value}

    @staticmethod
    def _fill_observable_object_attribute(feature, value):
        return {'value': str(value) if feature in ('entropy', 'size') else value,
                'to_ids': False}

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
        if 'file:content_ref.payload_bin' not in pattern:
            return self.parse_attribute_pattern(pattern)
        pattern_parts = pattern.strip('[]').split(' AND ')
        if len(pattern_parts) == 3:
            filename = pattern_parts[0].split(' = ')[1]
            md5 = pattern_parts[1].split(' = ')[1]
            return "{}|{}".format(filename.strip("'"), md5.strip("'")), pattern_parts[2].split(' = ')[1].strip("'")
        return pattern_parts[0].split(' = ')[1].strip("'"), pattern_parts[1].split(' = ')[1].strip("'")

    @staticmethod
    def parse_custom_property(custom_property):
        properties = custom_property.split('_')
        return {'type': properties[2], 'object_relation': '-'.join(properties[3:])}


class ExternalStixParser(StixParser):
    def __init__(self):
        super().__init__()
        self._stix2misp_mapping.update({'attack-pattern': 'parse_attack_pattern',
                                        'course-of-action': 'parse_course_of_action',
                                        'vulnerability': 'parse_vulnerability'})

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################

    def parse_event(self, stix_event):
        for stix_object in stix_event.objects:
            object_type = stix_object['type']
            if object_type in self._stix2misp_mapping:
                getattr(self, self._stix2misp_mapping[object_type])(stix_object)
            else:
                print(f'not found: {object_type}', file=sys.stderr)
        if self.relationship:
            self.parse_relationships()
        if self.galaxy:
            self.parse_galaxies()
        event_uuid = stix_event.id.split('--')[1]
        if hasattr(self, 'report'):
            self.parse_report(event_uuid=event_uuid)
        else:
            self.misp_event.uuid = event_uuid
            self.misp_event.info = 'Imported with the STIX to MISP import script.'
        self.handle_markings()

    def parse_galaxy(self, galaxy):
        galaxy_names = self._check_existing_galaxy_name(galaxy.name)
        if galaxy_names is not None:
            return galaxy_names
        return [f'misp-galaxy:{galaxy._type}="{galaxy.name}"']

    def _parse_indicator(self, indicator):
        pattern = indicator.pattern
        if any(relation in pattern for relation in stix2misp_mapping.pattern_forbidden_relations) or all(relation in pattern for relation in (' OR ', ' AND ')):
            self.add_stix2_pattern_object(indicator)
        separator = ' OR ' if ' OR ' in pattern else ' AND '
        self.parse_usual_indicator(indicator, separator)

    def _parse_observable(self, observable):
        types = self._parse_observable_types(observable.objects)
        try:
            getattr(self, stix2misp_mapping.observable_mapping[types])(observable)
        except KeyError:
            print(f'Type(s) not supported at the moment: {types}\n', file=sys.stderr)

    def _parse_undefined(self, stix_object):
        try:
            self.objects_to_parse[stix_object['id'].split('--')[1]] = stix_object
        except AttributeError:
            self.objects_to_parse = {stix_object['id'].split('--')[1]: stix_object}

    def add_stix2_pattern_object(self, indicator):
        misp_object = MISPObject('stix2-pattern', misp_objects_path_custom=_misp_objects_path)
        misp_object.uuid = indicator.id.split('--')[1]
        misp_object.update(self.parse_timeline(indicator))
        version = f'STIX {indicator.pattern_version}' if hasattr(indicator, 'pattern_version') else 'STIX 2.0'
        misp_object.add_attribute(**{'type': 'text', 'object_relation': 'version', 'value': version})
        misp_object.add_attribute(**{'type': 'stix2-pattern', 'object_relation': 'stix2-pattern',
                                     'value': indicator.pattern})
        self.misp_event.add_object(**misp_object)

    @staticmethod
    def fill_misp_object(misp_object, stix_object, mapping):
        for key, feature in getattr(stix2misp_mapping, mapping).items():
            if hasattr(stix_object, key):
                attribute = deepcopy(feature)
                attribute['value'] = getattr(stix_object, key)
                misp_object.add_attribute(**attribute)

    @staticmethod
    def fill_misp_object_from_dict(misp_object, stix_object, mapping):
        for key, feature in getattr(stix2misp_mapping, mapping).items():
            if key in stix_object:
                attribute = deepcopy(feature)
                attribute['value'] = stix_object[key]
                misp_object.add_attribute(**attribute)

    def parse_attack_pattern(self, attack_pattern):
        galaxy_names = self._check_existing_galaxy_name(attack_pattern.name)
        if galaxy_names is not None:
            self.galaxy[attack_pattern['id'].split('--')[1]] = {'tag_names': galaxy_names, 'used': False}
        else:
            misp_object = self.create_misp_object(attack_pattern)
            if hasattr(attack_pattern, 'external_references'):
                for reference in attack_pattern.external_references:
                    source_name = reference['source_name']
                    value = reference['external_id'].split('-')[1] if source_name == 'capec' else reference['url']
                    attribute = deepcopy(stix2misp_mapping.attack_pattern_references_mapping[source_name]) if source_name in stix2misp_mapping.attack_pattern_references_mapping else stix2misp_mapping.references_attribute_mapping
                    attribute['value'] = value
                    misp_object.add_attribute(**attribute)
            self.fill_misp_object(misp_object, attack_pattern, 'attack_pattern_mapping')
            self.misp_event.add_object(**misp_object)

    def parse_course_of_action(self, course_of_action):
        galaxy_names = self._check_existing_galaxy_name(course_of_action.name)
        if galaxy_names is not None:
            self.galaxy[course_of_action['id'].split('--')[1]] = {'tag_names': galaxy_names, 'used': False}
        else:
            misp_object = self.create_misp_object(course_of_action)
            self.fill_misp_object(misp_object, course_of_action, 'course_of_action_mapping')
            self.misp_event.add_object(**misp_object)

    def parse_usual_indicator(self, indicator, separator):
        pattern = tuple(part.strip() for part in self._handle_pattern(indicator.pattern).split(separator))
        types = self._parse_pattern_types(pattern)
        try:
            getattr(self, stix2misp_mapping.pattern_mapping[types])(indicator, separator)
        except KeyError:
            print(f'Type(s) not supported at the moment: {types}\n', file=sys.stderr)
            self.add_stix2_pattern_object(indicator)

    def parse_vulnerability(self, vulnerability):
        galaxy_names = self._check_existing_galaxy_name(vulnerability.name)
        if galaxy_names is not None:
            self.galaxy[vulnerability['id'].split('--')[1]] = {'tag_names': galaxy_names, 'used': False}
        else:
            attributes = self._get_attributes_from_observable(vulnerability, 'vulnerability_mapping')
            if hasattr(vulnerability, 'external_references'):
                for reference in vulnerability.external_references:
                    if reference['source_name'] == 'url':
                        attribute = deepcopy(stix2misp_mapping.references_attribute_mapping)
                        attribute['value'] = reference['url']
                        attributes.append(attribute)
            if len(attributes) == 1 and attributes[0]['object_relation'] == 'id':
                attributes[0]['type'] = 'vulnerability'
            self.handle_import_case(vulnerability, attributes, 'vulnerability')

    ################################################################################
    ##                        OBSERVABLE PARSING FUNCTIONS                        ##
    ################################################################################

    @staticmethod
    def _fetch_reference_type(references, object_type):
        for key, reference in references.items():
            if isinstance(reference, getattr(stix2.v20.observables, object_type)):
                return key
        return None

    @staticmethod
    def _fetch_user_account_type_observable(observable_objects):
        for observable_object in observable_objects.values():
            if hasattr(observable_object, 'extensions') or any(key not in ('user_id', 'credential', 'type') for key in observable_object):
                return 'user-account', 'user_account_mapping'
        return 'credential', 'credential_mapping'

    @staticmethod
    def _get_attributes_from_observable(stix_object, mapping):
        attributes = []
        for key, value in stix_object.items():
            if key in getattr(stix2misp_mapping, mapping) and value:
                attribute = deepcopy(getattr(stix2misp_mapping, mapping)[key])
                attribute.update({'value': value, 'to_ids': False})
                attributes.append(attribute)
        return attributes

    def get_network_traffic_attributes(self, network_traffic, references):
        attributes = self._get_attributes_from_observable(network_traffic, 'network_traffic_mapping')
        mapping = 'network_traffic_references_mapping'
        attributes.extend(self.parse_network_traffic_references(network_traffic, references, mapping))
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, mapping, 'dst'))
        return attributes

    @staticmethod
    def _handle_attachment_type(stix_object, is_reference, filename):
        _has_md5 = hasattr(stix_object, 'hashes') and 'MD5' in stix_object.hashes
        if is_reference and _has_md5:
            return 'malware-sample', f'{filename}|{stix_object.hashes["MD5"]}'
        return 'attachment', filename

    def handle_pe_observable(self, attributes, extension, observable):
        pe_uuid = self.parse_pe(extension)
        file = self.create_misp_object(observable, 'file')
        file.add_reference(pe_uuid, 'includes')
        for attribute in attributes:
            file.add_attribute(**attribute)
        self.misp_event.add_object(file)

    @staticmethod
    def _is_reference(network_traffic, reference):
        for feature in ('src', 'dst'):
            for reference_type in (f'{feature}_{ref}' for ref in ('ref', 'refs')):
                if reference in network_traffic.get(reference_type, []):
                    return True
        return False

    @staticmethod
    def _network_traffic_has_extension(network_traffic):
        if not hasattr(network_traffic, 'extensions'):
            return None
        if 'socket-ext' in network_traffic.extensions:
            return 'parse_socket_extension_observable'
        return None

    def parse_asn_observable(self, observable):
        autonomous_system, references = self.filter_main_object(observable.objects, 'AutonomousSystem')
        mapping = 'asn_mapping'
        attributes = self._get_attributes_from_observable(autonomous_system, mapping)
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, mapping))
        self.handle_import_case(observable, attributes, 'asn')

    def parse_domain_ip_observable(self, observable):
        domain, references = self.filter_main_object(observable.objects, 'DomainName')
        mapping = 'domain_ip_mapping'
        attributes = [self._parse_observable_reference(domain, mapping)]
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, mapping))
        self.handle_import_case(observable, attributes, 'domain-ip')

    def parse_domain_ip_network_traffic_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable.objects, 'NetworkTraffic')
        extension = self._network_traffic_has_extension(network_traffic)
        if extension:
            attributes, object_name = getattr(self, extension)(network_traffic, references)
            return self.handle_import_case(observable, attributes, object_name)
        if self._required_protocols(network_traffic.protocols):
            attributes = self.parse_network_connection_object(network_traffic, references)
            return self.handle_import_case(observable, attributes, 'network-connection')
        attributes, object_name = self.parse_network_traffic_objects(network_traffic, references)
        self.handle_import_case(observable, attributes, object_name)

    def parse_domain_network_traffic_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable.objects, 'NetworkTraffic')
        extension = self._network_traffic_has_extension(network_traffic)
        if extension:
            attributes, object_name = getattr(self, extension)(network_traffic, references)
            return self.handle_import_case(observable, attributes, object_name)
        attributes = self.parse_network_connection_object(network_traffic, references)
        self.handle_import_case(observable, attributes, 'network-connection')

    def parse_email_address_observable(self, observable):
        self.add_attributes_from_observable(observable, 'email-src', 'value')

    def parse_email_observable(self, observable):
        email_message, references = self.filter_main_object(observable.objects, 'EmailMessage')
        attributes = self._get_attributes_from_observable(email_message, 'email_mapping')
        if hasattr(email_message, 'additional_header_fields'):
            attributes.extend(self._get_attributes_from_observable(email_message.additional_header_fields, 'email_mapping'))
        attributes.extend(self._parse_email_references(email_message, references))
        if hasattr(email_message, 'body_multipart') and email_message.body_multipart:
            attributes.extend(self._parse_email_body(email_message.body_multipart, references))
        if references:
            print(f'Unable to parse the following observable objects: {references}', file=sys.stderr)
        self.handle_import_case(observable, attributes, 'email')

    def parse_file_observable(self, observable):
        file_object, references = self.filter_main_object(observable.objects, 'File')
        attributes = self._get_attributes_from_observable(file_object, 'file_mapping')
        if 'hashes' in file_object:
            attributes.extend(self._get_attributes_from_observable(file_object.hashes, 'file_mapping'))
        if references:
            filename = file_object.name if hasattr(file_object, 'name') else 'unknown_filename'
            for key, reference in references.items():
                if isinstance(reference, stix2.v20.observables.Artifact):
                    _is_content_ref = 'content_ref' in file_object and file_object.content_ref == key
                    attribute_type, value = self._handle_attachment_type(reference, _is_content_ref, filename)
                    attribute = {
                        'type': attribute_type,
                        'object_relation': attribute_type,
                        'value': value,
                        'to_ids': False
                    }
                    if hasattr(reference, 'payload_bin'):
                        attribute['data'] = reference.payload_bin
                    attributes.append(attribute)
                elif isinstance(reference, stix2.v20.observables.Directory):
                    attribute = {
                        'type': 'text',
                        'object_relation': 'path',
                        'value': reference.path,
                        'to_ids': False
                    }
                    attributes.append(attribute)
        if hasattr(file_object, 'extensions'):
            # Support of more extension types probably in the future
            if 'windows-pebinary-ext' in file_object.extensions:
                # Here we do not go to the standard route of "handle_import_case"
                # because we want to make sure a file object is created
                return self.handle_pe_observable(attributes, file_object.extensions['windows-pebinary-ext'], observable)
            extension_types = (extension_type for extension_type in file_object.extensions.keys())
            print(f'File extension type(s) not supported at the moment: {", ".join(extension_types)}', file=sys.stderr)
        self.handle_import_case(observable, attributes, 'file', _force_object=('file-encoding', 'path'))

    def parse_ip_address_observable(self, observable):
        attributes = []
        for observable_object in observable.objects.values():
            attribute = {
                'value': observable_object.value,
                'to_ids': False
            }
            attribute.update(stix2misp_mapping.ip_attribute_mapping)
            attributes.append(attribute)
        self.handle_import_case(observable, attributes, 'ip-port')

    def parse_ip_network_traffic_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable.objects, 'NetworkTraffic')
        extension = self._network_traffic_has_extension(network_traffic)
        if extension:
            attributes, object_name = getattr(self, extension)(network_traffic, references)
            return self.handle_import_case(observable, attributes, object_name)
        attributes = self.parse_ip_port_object(network_traffic, references)
        self.handle_import_case(observable, attributes, 'ip-port')

    def parse_ip_port_object(self, network_traffic, references):
        attributes = self._get_attributes_from_observable(network_traffic, 'network_traffic_mapping')
        attributes.extend(self.parse_network_traffic_references(network_traffic, references, 'ip_port_references_mapping'))
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, 'domain_ip_mapping'))
        return attributes

    def parse_mac_address_observable(self, observable):
        self.add_attributes_from_observable(observable, 'mac-address', 'value')

    def parse_network_connection_object(self, network_traffic, references):
        attributes = self.get_network_traffic_attributes(network_traffic, references)
        attributes.extend(self.parse_protocols(network_traffic.protocols, 'observable object'))
        return attributes

    def parse_network_traffic_objects(self, network_traffic, references):
        _has_domain = self._fetch_reference_type(references.values(), 'DomainName')
        if _has_domain and self._is_reference(network_traffic, _has_domain):
            return self.parse_network_connection_object(network_traffic, references), 'network-connection'
        return self.parse_ip_port_object(network_traffic, references), 'ip-port'

    def parse_network_traffic_references(self, network_traffic, references, mapping):
        attributes = []
        for feature in ('src', 'dst'):
            ref = f'{feature}_ref'
            if hasattr(network_traffic, ref):
                reference = getattr(network_traffic, ref)
                attributes.append(self._parse_observable_reference(references.pop(reference), mapping, feature))
            if hasattr(network_traffic, f'{ref}s'):
                for reference in getattr(network_traffic, f'{ref}s'):
                    attributes.append(self._parse_observable_reference(references.pop(reference), mapping, feature))
        return attributes

    def parse_mutex_observable(self, observable):
        self.add_attributes_from_observable(observable, 'mutex', 'name')

    def parse_process_observable(self, observable):
        process, references = self.filter_main_object(observable.objects, 'Process', test_function='_process_test_filter')
        attributes = self._get_attributes_from_observable(process, 'process_mapping')
        if hasattr(process, 'parent_ref'):
            attributes.extend(self._get_attributes_from_observable(references.pop(process.parent_ref), 'parent_process_reference_mapping'))
        if hasattr(process, 'child_refs'):
            for reference in process.child_refs:
                attributes.extend(self._get_attributes_from_observable(references.pop(reference), 'child_process_reference_mapping'))
        if hasattr(process, 'binary_ref'):
            reference = references.pop(process.binary_ref)
            attribute = {
                'value': reference.name,
                'to_ids': False
            }
            attribute.update(stix2misp_mapping.process_image_mapping)
            attributes.append(attribute)
        if references:
            print(f'Unable to parse the following observable objects: {references}', file=sys.stderr)
        self.handle_import_case(observable, attributes, 'process', _force_object=True)

    def parse_protocols(self, protocols, object_type):
        attributes = []
        protocols = (protocol.upper() for protocol in protocols)
        for protocol in protocols:
            try:
                attributes.append(self._parse_network_traffic_protocol(protocol))
            except KeyError:
                print(f'Unknown protocol in network-traffic {object_type}: {protocol}', file=sys.stderr)
        return attributes

    def parse_regkey_observable(self, observable):
        attributes = []
        for observable_object in observable.objects.values():
            attributes.extend(self._get_attributes_from_observable(observable_object, 'regkey_mapping'))
            if 'values' in observable_object:
                for registry_value in observable_object['values']:
                    attributes.extend(self._get_attributes_from_observable(registry_value, 'regkey_mapping'))
        self.handle_import_case(observable, attributes, 'registry-key')

    def parse_socket_extension_observable(self, network_traffic, references):
        attributes = self.get_network_traffic_attributes(network_traffic, references)
        for key, value in network_traffic.extensions['socket-ext'].items():
            if key not in stix2misp_mapping.network_socket_extension_mapping:
                print(f'Unknown socket extension field in observable object: {key}', file=sys.stderr)
                continue
            if key.startswith('is_') and not value:
                continue
            attribute = {
                'value': key.split('_')[1] if key.startswith('is_') else value,
                'to_ids': False
            }
            attribute.update(stix2misp_mapping.network_socket_extension_mapping[key])
            attributes.append(attribute)
        return attributes, 'network-socket'

    def parse_url_observable(self, observable):
        network_traffic, references = self.filter_main_object(observable.objects, 'NetworkTraffic')
        attributes = self._get_attributes_from_observable(network_traffic, 'network_traffic_mapping') if network_traffic else []
        if references:
            for reference in references.values():
                attributes.append(self._parse_observable_reference(reference, 'url_mapping'))
        self.handle_import_case(observable, attributes, 'url')

    def parse_user_account_extension(self, extension):
        attributes = self._parse_user_account_groups(extension['groups']) if 'groups' in extension else []
        attributes.extend(self._get_attributes_from_observable(extension, 'user_account_mapping'))
        return attributes

    def parse_user_account_observable(self, observable):
        attributes = []
        object_name, mapping = self._fetch_user_account_type_observable(observable.objects)
        for observable_object in observable.objects.values():
            attributes.extend(self._get_attributes_from_observable(observable_object, mapping))
            if hasattr(observable_object, 'extensions') and observable_object.extensions.get('unix-account-ext'):
                attributes.extend(self.parse_user_account_extension(observable_object.extensions['unix-account-ext']))
        self.handle_import_case(observable, attributes, object_name)

    def parse_x509_observable(self, observable):
        attributes = []
        for observable_object in observable.objects.values():
            attributes.extend(self._get_attributes_from_observable(observable_object, 'x509_mapping'))
            if hasattr(observable_object, 'hashes'):
                attributes.extend(self._get_attributes_from_observable(observable_object.hashes, 'x509_mapping'))
        self.handle_import_case(observable, attributes, 'x509')

    ################################################################################
    ##                         PATTERN PARSING FUNCTIONS.                         ##
    ################################################################################

    @staticmethod
    def _fetch_user_account_type_pattern(pattern):
        for stix_object in pattern:
            if 'extensions' in stix_object or all(key not in stix_object for key in ('user_id', 'credential', 'type')):
                return 'user-account', 'user_account_mapping'
        return 'credential', 'credential_mapping'

    def get_attachment(self, attachment, filename):
        attribute = {
            'type': 'attachment',
            'object_relation': 'attachment',
            'value': attachment.pop(filename)
        }
        data_feature = self._choose_with_priority(attachment, 'file:content_ref.payload_bin', 'artifact:payload_bin')
        attribute['data'] = attachment.pop(data_feature)
        return attribute

    def get_attributes_from_pattern(self, pattern, mapping, separator):
        attributes = []
        for pattern_part in pattern.strip('[]').split(separator):
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            try:
                attribute = deepcopy(getattr(stix2misp_mapping, mapping)[pattern_type])
            except KeyError:
                print(f'Pattern type not supported at the moment: {pattern_type}', file=sys.stderr)
                continue
            attribute['value'] = pattern_value
            attributes.append(attribute)
        return attributes

    def get_malware_sample(self, attachment, filename):
        md5_feature = self._choose_with_priority(attachment, "file:content_ref.hashes.'MD5'", "file:hashes.'MD5'")
        attribute = {
            'type': 'malware-sample',
            'object_relation': 'malware-sample',
            'value': f'{attachment.pop(filename)}|{attachment.pop(md5_feature)}'
        }
        data_feature = self._choose_with_priority(attachment, 'file:content_ref.payload_bin', 'artifact:payload_bin')
        attribute['data'] = attachment.pop(data_feature)
        return attribute

    def _handle_file_attachments(self, attachment):
        attributes = []
        if any('content_ref' in feature for feature in attachment.keys()):
            attribute_type = 'attachment'
            value = attachment['file:name'] if 'file:name' in attachment else 'unknown_filename'
            if "file:content_ref.hashes.'MD5'" in attachment:
                attribute_type = 'malware-sample'
                md5 = attachment.pop("file:content_ref.hashes.'MD5'")
                value = f'{value}|{md5}'
            data = self._choose_with_priority(attachment, 'file:content_ref.payload_bin', 'artifact:payload_bin')
            attribute = {
                'type': attribute_type,
                'object_relation': attribute_type,
                'value': value,
                'data': attachment.pop(data)
            }
            attributes.append(attribute)
        if 'artifact:payload_bin' in attachment:
            attribute = {
                'type': 'attachment',
                'object_relation': 'attachment',
                'value': attachment['file:name'],
                'data': attachment.pop('artifact:payload_bin')
            }
            attributes.append(attribute)
        return attributes

    def parse_as_pattern(self, indicator, separator):
        attributes = self.get_attributes_from_pattern(indicator.pattern, 'asn_mapping', separator)
        self.handle_import_case(indicator, attributes, 'asn')

    def parse_domain_ip_port_pattern(self, indicator, separator):
        attributes = []
        references = defaultdict(dict)
        for pattern_part in self._handle_pattern(indicator.pattern).split(separator):
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            if pattern_type not in stix2misp_mapping.domain_ip_mapping:
                if any(pattern_type.startswith(f'network-traffic:{feature}_ref') for feature in ('src', 'dst')):
                    feature_type, ref = pattern_type.split(':')[1].split('_')
                    ref, feature = ref.split('.')
                    ref = f"{feature_type}_{'0' if ref == 'ref' else ref.strip('ref[]')}"
                    references[ref].update(self._parse_network_connection_reference(feature_type, feature, pattern_value))
                else:
                    print(f'Pattern type not currently mapped: {pattern_type}', file=sys.stderr)
                continue
            attribute = deepcopy(stix2misp_mapping.domain_ip_mapping[pattern_type])
            attribute['value'] = pattern_value
            attributes.append(attribute)
        if references:
            attributes.extend(references.values())
        object_name = 'ip-port' if 'network-traffic' in indicator.pattern else 'domain-ip'
        self.handle_import_case(indicator, attributes, object_name)

    def parse_email_address_pattern(self, indicator, separator):
        self.add_attributes_from_indicator(indicator, 'email-src', separator)

    def parse_email_message_pattern(self, indicator, separator):
        attributes = []
        attachments = defaultdict(dict)
        for pattern_part in self._handle_pattern(indicator.pattern).split(separator):
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            if pattern_type not in stix2misp_mapping.email_mapping:
                if pattern_type.startswith('email-message:body_multipart'):
                    features = pattern_type.split('.')
                    if len(features) == 3 and features[1] == 'body_raw_ref':
                        index = features[0].split('[')[1].strip(']') if '[' in features[0] else '0'
                        key = 'data' if features[2] == 'payload_bin' else 'value'
                        attachments[index][key] = pattern_value
                        continue
                print(f'Pattern type not supported at the moment: {pattern_type}', file=sys.stderr)
                continue
            attribute = deepcopy(stix2misp_mapping.email_mapping[pattern_type])
            attribute['value'] = pattern_value
            attributes.append(attribute)
        if attachments:
            for attachment in attachments.values():
                attribute = {
                    'type': 'attachment',
                    'object_relation': 'screenshot'
                } if 'data' in attachment else {
                    'type': 'email-attachment',
                    'object_relation': 'attachment'
                }
                attribute.update(attachment)
                attributes.append(attribute)
        self.handle_import_case(indicator, attributes, 'email')

    def parse_file_pattern(self, indicator, separator):
        attributes = []
        attachment = {}
        extensions = defaultdict(lambda: defaultdict(dict))
        for pattern_part in self._handle_pattern(indicator.pattern).split(separator):
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            if pattern_type in stix2misp_mapping.attachment_types:
                attachment[pattern_type] = pattern_value.strip("'")
                continue
            if pattern_type not in stix2misp_mapping.file_mapping:
                if 'extensions' in pattern_type:
                    features = pattern_type.split('.')[1:]
                    extension_type = features.pop(0).strip("'")
                    if 'section' in features[0] and features[0] != 'number_of_sections':
                        index = features[0].split('[')[1].strip(']') if '[' in features[0] else '0'
                        extensions[extension_type][f'section_{index}'][features[-1].strip("'")] = pattern_value
                    else:
                        extensions[extension_type]['.'.join(features)] = pattern_value
                continue
            attribute = deepcopy(stix2misp_mapping.file_mapping[pattern_type])
            attribute['value'] = pattern_value
            attributes.append(attribute)
        if any(key.endswith('payload_bin') for key in attachment.keys()):
            attributes.extend(self._handle_file_attachments(attachment))
        if attachment:
            for pattern_type, value in attachment.items():
                if pattern_type in stix2misp_mapping.file_mapping:
                    attribute = deepcopy(stix2misp_mapping.file_mapping[pattern_type])
                    attribute['value'] = value
                    attributes.append(attribute)
        if extensions:
            file_object = self.create_misp_object(indicator, 'file')
            self.parse_file_extension(file_object, attributes, extensions)
        else:
            self.handle_import_case(indicator, attributes, 'file', _force_object=('file-encoding', 'path'))

    def parse_file_extension(self, file_object, attributes, extensions):
        for attribute in attributes:
            file_object.add_attribute(**attribute)
        if 'windows-pebinary-ext' in extensions:
            pe_extension = extensions['windows-pebinary-ext']
            pe_object = MISPObject('pe', misp_objects_path_custom=_misp_objects_path)
            sections = self._get_sections(pe_extension)
            self.fill_misp_object_from_dict(pe_object, pe_extension, 'pe_mapping')
            if sections:
                for section in sections:
                    section_object = MISPObject('pe-section')
                    self.fill_misp_object_from_dict(section_object, section, 'pe_section_mapping')
                    self.misp_event.add_object(section_object)
                    pe_object.add_reference(section_object.uuid, 'includes')
            self.misp_event.add_object(pe_object)
            file_object.add_reference(pe_object.uuid, 'includes')
        self.misp_event.add_object(file_object)

    def parse_ip_address_pattern(self, indicator, separator):
        self.add_attributes_from_indicator(indicator, 'ip-dst', separator)

    def parse_mac_address_pattern(self, indicator, separator):
        self.add_attributes_from_indicator(indicator, 'mac-address', separator)

    def parse_mutex_pattern(self, indicator, separator):
        self.add_attributes_from_indicator(indicator, 'mutex', separator)

    def parse_network_connection_pattern(self, indicator, attributes, references):
        attributes.extend(self._parse_network_pattern_references(references, 'network_traffic_references_mapping'))
        self.handle_import_case(indicator, attributes, 'network-connection')

    @staticmethod
    def _parse_network_pattern_references(references, mapping):
        attributes = []
        for feature, reference in references.items():
            feature = feature.split('_')[0]
            attribute = {key: value.format(feature) for key, value in getattr(stix2misp_mapping, mapping)[reference['type']].items()}
            attribute['value'] = reference['value']
            attributes.append(attribute)
        return attributes

    def parse_network_socket_pattern(self, indicator, attributes, references, extension):
        attributes.extend(self._parse_network_pattern_references(references, 'network_traffic_references_mapping'))
        for key, value in extension.items():
            if key not in stix2misp_mapping.network_socket_extension_mapping:
                print(f'Unknown socket extension field in pattern: {key}', file=sys.stderr)
                continue
            if key.startswith('is_') and not json.loads(value.lower()):
                continue
            attribute = deepcopy(stix2misp_mapping.network_socket_extension_mapping[key])
            attribute['value'] = key.split('_')[1] if key.startswith('is_') else value
            attributes.append(attribute)
        self.handle_import_case(indicator, attributes, 'network-socket')

    def parse_network_traffic_pattern(self, indicator, separator):
        attributes = []
        protocols = []
        references = defaultdict(dict)
        extensions = defaultdict(dict)
        for pattern_part in self._handle_pattern(indicator.pattern).split(separator):
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            if pattern_type in stix2misp_mapping.network_traffic_mapping:
                attribute = deepcopy(stix2misp_mapping.network_traffic_mapping[pattern_type])
                attribute['value'] = pattern_value.strip("'")
                attributes.append(attribute)
                continue
            if pattern_type.startswith('network-traffic:protocols['):
                protocols.append(pattern_value)
            elif any(pattern_type.startswith(f'network-traffic:{feature}_ref') for feature in ('src', 'dst')):
                feature_type, ref = pattern_type.split(':')[1].split('_')
                ref, feature = ref.split('.')
                ref = f"{feature_type}_{'0' if ref == 'ref' else ref.strip('ref[]')}"
                references[ref].update({feature: pattern_value})
            elif pattern_type.startswith('network-traffic:extensions.'):
                _, extension_type, feature = pattern_type.split('.')
                extensions[extension_type.strip("'")][feature] = pattern_value
            else:
                print(f'Pattern type not supported at the moment: {pattern_type}', file=sys.stderr)
        if extensions:
            if 'socket-ext' in extensions:
                return self.parse_network_socket_pattern(indicator, attributes, references, extensions['socket-ext'])
            print(f'Unknown network extension(s) in pattern: {", ".join(extensions.keys())}', file=sys.stderr)
        if protocols and self._required_protocols(protocols):
            attributes.extend(self.parse_protocols(protocols, 'pattern'))
            return self.parse_network_connection_pattern(indicator, attributes, references)
        attributes.extend(self._parse_network_pattern_references(references, 'ip_port_references_mapping'))
        self.handle_import_case(indicator, attributes, 'ip-port')

    def parse_process_pattern(self, indicator, separator):
        attributes = []
        parent = {}
        child = defaultdict(set)
        for pattern_part in self._handle_pattern(indicator.pattern).split(separator):
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            if 'parent_' in pattern_type:
                child[pattern_type.split('.')[-1]].add(pattern_value)
            elif 'child_' in pattern_type:
                parent[pattern_type.split('.')[-1]] = pattern_value
            else:
                try:
                    attribute = deepcopy(stix2misp_mapping.process_mapping[pattern_type])
                except KeyError:
                    print(f'Pattern type not supported at the moment: {pattern_type}', file=sys.stderr)
                    continue
                attribute['value'] = pattern_value
                attributes.append(attribute)
        if parent:
            for key, value in parent.items():
                if key not in stix2misp_mapping.parent_process_reference_mapping:
                    print(f'Parent process key from pattern not supported at the moment: {key}', file=sys.stderr)
                    continue
                attribute = {'value': value}
                attribute.update(stix2misp_mapping.parent_process_reference_mapping[key])
                attributes.append(attribute)
        if child:
            for key, values in child.items():
                if key not in stix2misp_mapping.child_process_reference_mapping:
                    print(f'Child process key from pattern not supported at the moment: {key}', file=sys.stderr)
                    continue
                for value in values:
                    attribute = {'value': value}
                    attribute.update(stix2misp_mapping.child_process_reference_mapping[key])
                    attributes.append(attribute)
        self.handle_import_case(indicator, attributes, 'process', _force_object=True)

    def parse_regkey_pattern(self, indicator, separator):
        attributes = self.get_attributes_from_pattern(indicator.pattern, 'regkey_mapping', separator)
        self.handle_import_case(indicator, attributes, 'registry-key')

    def parse_url_pattern(self, indicator, separator):
        attributes = self.get_attributes_from_pattern(indicator.pattern, 'url_mapping', separator)
        self.handle_import_case(indicator, attributes, 'url')

    def parse_user_account_pattern(self, indicator, separator):
        attributes = []
        pattern = self._handle_pattern(indicator.pattern).split(separator)
        object_name, mapping = self._fetch_user_account_type_pattern(pattern)
        for pattern_part in pattern:
            pattern_type, pattern_value = self.get_type_and_value_from_pattern(pattern_part)
            pattern_type = pattern_type.split(':')[1]
            if pattern_type.startswith('extensions.'):
                pattern_type = pattern_type.split('.')[-1]
                if '[' in pattern_type:
                    pattern_type = pattern_type.split('[')[0]
                if pattern_type in ('group', 'groups'):
                    attributes.append({'type': 'text', 'object_relation': 'group', 'value': pattern_value})
                    continue
            if pattern_type in getattr(stix2misp_mapping, mapping):
                attribute = deepcopy(getattr(stix2misp_mapping, mapping)[pattern_type])
                attribute['value'] = pattern_value
                attributes.append(attribute)
        self.handle_import_case(indicator, attributes, object_name)

    def parse_x509_pattern(self, indicator, separator):
        attributes = self.get_attributes_from_pattern(indicator.pattern, 'x509_mapping', separator)
        self.handle_import_case(indicator, attributes, 'x509')

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    def add_attributes_from_indicator(self, indicator, attribute_type, separator):
        patterns = self._handle_pattern(indicator.pattern).split(separator)
        if len(patterns) == 1:
            _, value = self.get_type_and_value_from_pattern(patterns[0])
            attribute = MISPAttribute()
            attribute.from_dict(**{
                'uuid': indicator.id.split('--')[1],
                'type': attribute_type,
                'value': value,
                'to_ids': True
            })
            attribute.update(self.parse_timeline(indicator))
            self.misp_event.add_attribute(**attribute)
        else:
            tmp_attribute = self.parse_timeline(indicator)
            for pattern in patterns:
                _, value = self.get_type_and_value_from_pattern(pattern)
                attribute = MISPAttribute()
                attribute.from_dict(**{
                    'type': attribute_type,
                    'value': value,
                    'to_ids': True
                })
                attribute.update(tmp_attribute)
                self.misp_event.add_attribute(**attribute)

    def add_attributes_from_observable(self, observable, attribute_type, feature):
        if len(observable.objects) == 1:
            attribute = MISPAttribute()
            attribute.from_dict(**{
                'uuid': observable.id.split('--')[1],
                'type': attribute_type,
                'value': getattr(observable.objects['0'], feature),
                'to_ids': False
            })
            attribute.update(self.parse_timeline(observable))
            self.misp_event.add_attribute(**attribute)
        else:
            tmp_attribute = self.parse_timeline(observable)
            for observable_object in observable.objects.values():
                attribute = MISPAttribute()
                attribute.from_dict(**{
                    'type': attribute_type,
                    'value': getattr(observable_object, feature),
                    'to_ids': False
                })
                attribute.update(tmp_attribute)
                self.misp_event.add_attribute(**attribute)

    def _check_existing_galaxy_name(self, galaxy_name):
        if galaxy_name in self._synonyms_to_tag_names:
            return self._synonyms_to_tag_names[galaxy_name]
        for name, tag_names in self._synonyms_to_tag_names.items():
            if galaxy_name in name:
                return tag_names
        return None

    def create_misp_object(self, stix_object, name=None):
        misp_object = MISPObject(name if name is not None else stix_object.type,
                                 misp_objects_path_custom=_misp_objects_path)
        misp_object.uuid = stix_object.id.split('--')[1]
        if hasattr(stix_object, 'description') and stix_object.description:
            misp_object.comment = stix_object.description
        misp_object.update(self.parse_timeline(stix_object))
        return misp_object

    @staticmethod
    def _get_sections(pe_extension):
        sections = [feature for feature in pe_extension.keys() if feature.startswith('section_')]
        return (pe_extension.pop(feature) for feature in sections)

    @staticmethod
    def get_type_and_value_from_pattern(pattern):
        pattern = pattern.strip('[]')
        try:
            pattern_type, pattern_value = pattern.split(' = \'')
        except ValueError:
            pattern_type, pattern_value = pattern.split('=')
        return pattern_type.strip(), pattern_value.strip("'")

    def handle_import_case(self, stix_object, attributes, name, _force_object=False):
        try:
            if len(attributes) > 1 or (_force_object and self._handle_object_forcing(_force_object, attributes[0])):
                misp_object = self.create_misp_object(stix_object, name)
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
                self.misp_event.add_object(**misp_object)
            else:
                attribute = {field: attributes[0][field] for field in stix2misp_mapping.single_attribute_fields if attributes[0].get(field) is not None}
                attribute['uuid'] = stix_object.id.split('--')[1]
                attribute.update(self.parse_timeline(stix_object))
                if isinstance(stix_object, stix2.v20.Indicator):
                    attribute['to_ids'] = True
                if hasattr(stix_object, 'object_marking_refs'):
                    self.update_marking_refs(attribute['uuid'], stix_object.object_marking_refs)
                self.misp_event.add_attribute(**attribute)
        except IndexError:
            object_type = 'indicator' if isinstance(stix_object, stix2.Indicator) else 'observable objects'
            print(f'No attribute or object could be imported from the following {object_type}: {stix_object}', file=sys.stderr)

    @staticmethod
    def _handle_object_forcing(_force_object, attribute):
        if isinstance(_force_object, (list, tuple)):
            return attribute['object_relation'] in _force_object
        return _force_object

    @staticmethod
    def _handle_pattern(pattern):
        return pattern.strip().strip('[]')

    @staticmethod
    def _parse_observable_types(observable_objects):
        types = {observable_object._type for observable_object in observable_objects.values()}
        return tuple(sorted(types))

    @staticmethod
    def _parse_pattern_types(pattern):
        types = {part.split('=')[0].split(':')[0].strip('[') for part in pattern}
        return tuple(sorted(types))

    @staticmethod
    def _required_protocols(protocols):
        protocols = tuple(protocol.upper() for protocol in protocols)
        if any(protocol not in ('TCP', 'IP') for protocol in protocols):
            return True
        return False


def from_misp(stix_objects):
    for stix_object in stix_objects:
        if stix_object['type'] == "report" and 'misp:tool="misp2stix2"' in stix_object.get('labels', []):
            return True
    return False


def main(args):
    filename = args[1] if args[1][0] == '/' else Path(os.path.dirname(args[0]), args[1])
    with open(filename, 'rt', encoding='utf-8') as f:
        event = stix2.parse(f.read(), allow_custom=True, interoperability=True)
    stix_parser = StixFromMISPParser() if from_misp(event.objects) else ExternalStixParser()
    stix_parser.handler(event, filename, args[2:])
    stix_parser.save_file()
    print(1)


if __name__ == '__main__':
    main(sys.argv)
