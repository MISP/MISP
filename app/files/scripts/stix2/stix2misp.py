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
import uuid
import io
import stix2
from base64 import b64encode
from pymisp import MISPEvent, MISPObject, __path__
from stix2misp_mapping import *
from collections import defaultdict

galaxy_types = {'attack-pattern': 'Attack Pattern', 'intrusion-set': 'Intrusion Set',
                'malware': 'Malware', 'threat-actor': 'Threat Actor', 'tool': 'Tool'}
with open(os.path.join(__path__[0], 'data/describeTypes.json'), 'r') as f:
    misp_types = json.loads(f.read())['result'].get('types')

class StixParser():
    def __init__(self):
        super(StixParser, self).__init__()
        self.misp_event = MISPEvent()
        self.misp_event['Galaxy'] = []

    def load_data(self, filename, version, event, args):
        self.filename = filename
        self.stix_version = version
        self.event = event
        if args and args[0] is not None:
            self.add_original_file(args[0])
        try:
            event_distribution = args[1]
            if not isinstance(event_distribution, int):
                event_distribution = int(event_distribution) if event_distribution.isdigit() else 5
        except IndexError:
            event_distribution = 5
        try:
            attribute_distribution = args[2]
            if attribute_distribution != 'event' and not isinstance(attribute_distribution, int):
                attribute_distribution = int(attribute_distribution) if attribute_distribution.isdigit() else 5
        except IndexError:
            attribute_distribution = 5
        self.misp_event.distribution = event_distribution
        self._attribute_distribution = event_distribution if attribute_distribution == 'event' else attribute_distribution

    def add_original_file(self, original_filename):
        with open(self.filename, 'rb') as f:
            sample = b64encode(f.read()).decode('utf-8')
        original_file = MISPObject('original-imported-file')
        original_file.add_attribute(**{'type': 'attachment', 'value': original_filename,
                                       'object_relation': 'imported-sample', 'data': sample})
        original_file.add_attribute(**{'type': 'text', 'object_relation': 'format',
                                       'value': self.stix_version})
        self.misp_event.add_object(**original_file)

    def general_handler(self):
        self.outputname = '{}.stix2'.format(self.filename)
        self.buildMISPDict()
        self.set_distribution()

    def buildMISPDict(self):
        report_attributes = defaultdict(set)
        for _, report in self.event['report'].items():
            report_attributes['orgs'].add(report['created_by_ref'].split('--')[1])
            report_attributes['name'].add(report['name'])
            if report.get('published'):
                report_attributes['published'].add(report['published'])
            if 'labels' in report:
                report_attributes['labels'].update([l for l in report['labels']])
            if 'external_references' in report:
                self.add_links(report['external_references'])
            for ref in report['object_refs']:
                if 'relationship' not in ref:
                    object_type, uuid = ref.split('--')
                    object2parse = self.event[object_type][uuid]
                    self.parsing_process(object2parse, object_type)
        if len(report_attributes['orgs']) == 1:
            identity = self.event['identity'][report_attributes['orgs'].pop()]
            self.misp_event['Org'] = {'name': identity['name']}
        if len(report_attributes['published']) == 1:
            self.misp_event.publish_timestamp = self.getTimestampfromDate(report_attributes['published'].pop())
        if len(report_attributes['name']) == 1:
            self.misp_event.info = report_attributes['name'].pop()
        else:
            self.misp_event.info = "Imported with MISP import script for {}.".format(self.stix_version)
        for l in report_attributes['labels']:
            self.misp_event.add_tag(l)

    def set_distribution(self):
        for attribute in self.misp_event.attributes:
            attribute.distribution = self._attribute_distribution
        for misp_object in self.misp_event.objects:
            misp_object.distribution = self._attribute_distribution
            for attribute in misp_object.attributes:
                attribute.distribution = self._attribute_distribution

    def saveFile(self):
        eventDict = self.misp_event.to_json()
        outputfile = '{}.stix2'.format(self.filename)
        with open(outputfile, 'w') as f:
            f.write(eventDict)

    def add_links(self, refs):
        for e in refs:
            link = {"type": "link"}
            comment = e.get('source_name')
            try:
                comment = comment.split('url - ')[1]
            except IndexError:
                pass
            if comment:
                link['comment'] = comment
            link['value'] = e.get('url')
            self.misp_event.add_attribute(**link)

    @staticmethod
    def getTimestampfromDate(stix_date):
        try:
            return int(stix_date.timestamp())
        except AttributeError:
            return int(time.mktime(time.strptime(stix_date.split('+')[0], "%Y-%m-%d %H:%M:%S")))

    @staticmethod
    def get_misp_type(labels):
        return labels[0].split('=')[1][1:-1]

    @staticmethod
    def get_misp_category(labels):
        return labels[1].split('=')[1][1:-1]

    def parse_course_of_action(self, o):
        misp_object = MISPObject('course-of-action')
        if 'name' in o:
            attribute = {'type': 'text', 'object_relation': 'name', 'value': o.get('name')}
            misp_object.add_attribute(**attribute)
        else:
            return
        if 'description' in o:
            attribute = {'type': 'text', 'object_relation': 'description', 'value': o.get('description')}
            misp_object.add_attribute(**attribute)
        self.misp_event.add_object(**misp_object)

    @staticmethod
    def parse_observable(observable, attribute_type):
        return misp_types_mapping[attribute_type](observable, attribute_type)

    @staticmethod
    def parse_pattern(pattern):
        if ' AND ' in pattern:
            pattern_parts = pattern.split(' AND ')
            if len(pattern_parts) == 3:
                _, value1 = pattern_parts[2].split(' = ')
                _, value2 = pattern_parts[0].split(' = ')
                return '{}|{}'.format(value1[1:-2], value2[1:-1])
            else:
                _, value1 = pattern_parts[0].split(' = ')
                _, value2 = pattern_parts[1].split(' = ')
                if value1 in ("'ipv4-addr'", "'ipv6-addr'"):
                    return value2[1:-2]
                return '{}|{}'.format(value1[1:-1], value2[1:-2])
        else:
            return pattern.split(' = ')[1][1:-2]

    def parse_pattern_with_data(self, pattern):
        if 'artifact:payload_bin' not in pattern:
            return self.parse_pattern(pattern)
        pattern_parts = pattern.split(' AND ')
        if len(pattern_parts) == 3:
            filename = pattern_parts[0].split(' = ')[1]
            md5 = pattern_parts[1].split(' = ')[1]
            return "{}|{}".format(filename[1:-1], md5[1:-1]), pattern_parts[2].split(' = ')[1][1:-2]
        return pattern_parts[0].split(' = ')[1][1:-1], pattern_parts[1].split(' = ')[1][1:-2]


class StixFromMISPParser(StixParser):
    def __init__(self):
        super(StixFromMISPParser, self).__init__()
        self.objects_mapping = {'asn': {'observable': observable_asn, 'pattern': pattern_asn},
                                'domain-ip': {'observable': observable_domain_ip, 'pattern': pattern_domain_ip},
                                'email': {'observable': self.observable_email, 'pattern': self.pattern_email},
                                'file': {'observable': observable_file, 'pattern': self.pattern_file},
                                'ip-port': {'observable': observable_ip_port, 'pattern': pattern_ip_port},
                                'network-socket': {'observable': observable_socket, 'pattern': pattern_socket},
                                'process': {'observable': observable_process, 'pattern': pattern_process},
                                'registry-key': {'observable': observable_regkey, 'pattern': pattern_regkey},
                                'url': {'observable': observable_url, 'pattern': pattern_url},
                                'WindowsPEBinaryFile': {'observable': self.observable_pe, 'pattern': self.pattern_pe},
                                'x509': {'observable': observable_x509, 'pattern': pattern_x509}}
        self.object_from_refs = {'course-of-action': self.parse_MISP_course_of_action, 'vulnerability': self.parse_vulnerability,
                                 'x-misp-object': self.parse_custom}
        self.object_from_refs.update(dict.fromkeys(list(galaxy_types.keys()), self.parse_galaxy))
        self.object_from_refs.update(dict.fromkeys(['indicator', 'observed-data'], self.parse_usual_object))

    def handler(self):
        self.general_handler()

    def parsing_process(self, object2parse, object_type):
        labels = object2parse.get('labels')
        self.object_from_refs[object_type](object2parse, labels)

    def parse_usual_object(self, o, labels):
        if 'from_object' in labels:
            self.parse_object(o, labels)
        else:
            self.parse_attribute(o, labels)

    def parse_galaxy(self, o, labels):
        name = self.get_misp_type(labels)
        tag = labels[1]
        galaxy_type, value = tag.split(':')[1].split('=')
        galaxy_description, cluster_description = o.get('description').split('|')
        _, uuid = o.get('id').split('--')
        galaxy = {'type': galaxy_type, 'name': name, 'description': galaxy_description,
                  'GalaxyCluster': [{'type': galaxy_type, 'value':value, 'tag_name': tag,
                                     'description': cluster_description, 'uuid': uuid}]}
        self.misp_event['Galaxy'].append(galaxy)

    def parse_MISP_course_of_action(self, o, _):
        self.parse_course_of_action(o)

    def parse_custom(self, o, labels):
        if 'from_object' in labels:
            self.parse_custom_object(o, labels)
        else:
            self.parse_custom_attribute(o, labels)

    def parse_custom_object(self, o, labels):
        name = o['type'].split('x-misp-object-')[1]
        timestamp = self.getTimestampfromDate(o['x_misp_timestamp'])
        try:
            category = o['category']
        except KeyError:
            category = self.get_misp_category(labels)
        attributes = []
        for key, value in o['x_misp_values'].items():
            attribute_type, object_relation = key.split('_')
            attributes.append({'type': attribute_type, 'value': value, 'object_relation': object_relation})
        misp_object = {'name': name, 'timestamp': timestamp, 'meta-category': category, 'Attribute': attributes}
        self.misp_event.add_object(**misp_object)

    def parse_custom_attribute(self, o, labels):
        attribute_type = o['type'].split('x-misp-object-')[1]
        if attribute_type not in misp_types:
            attribute_type = attribute_type.replace('-', '|')
        timestamp = self.getTimestampfromDate(o['x_misp_timestamp'])
        to_ids = bool(labels[1].split('=')[1])
        value = o['x_misp_value']
        category = self.get_misp_category(labels)
        attribute = {'type': attribute_type, 'timestamp': timestamp, 'to_ids': to_ids,
                     'value': value, 'category': category}
        self.misp_event.add_attribute(**attribute)

    def parse_object(self, o, labels):
        object_type = self.get_misp_type(labels)
        name = 'file' if object_type == 'WindowsPEBinaryFile' else object_type
        object_category = self.get_misp_category(labels)
        stix_type = o._type
        misp_object = MISPObject(name)
        misp_object['meta-category'] = object_category
        if stix_type == 'indicator':
            pattern = o.pattern.replace('\\\\', '\\').split(' AND ')
            pattern[0] = pattern[0][1:]
            pattern[-1] = pattern[-1][:-1]
            attributes = self.objects_mapping[object_type]['pattern'](pattern)
        if stix_type == 'observed-data':
            observable = o.objects
            attributes = self.objects_mapping[object_type]['observable'](observable)
        if isinstance(attributes, tuple):
            attributes, pe_uuid = attributes
            misp_object.add_reference(pe_uuid, 'included-in')
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        misp_object.to_ids = bool(labels[1].split('=')[1])
        self.misp_event.add_object(**misp_object)

    def parse_attribute(self, o, labels):
        attribute_uuid = o['id'].split('--')[1]
        attribute_type = self.get_misp_type(labels)
        attribute_category = self.get_misp_category(labels)
        attribute = {'uuid': attribute_uuid, 'type': attribute_type, 'category': attribute_category}
        tags = [{'name': label} for label in labels[3:]]
        if tags:
            attribute['Tag'] = tags
        stix_type = o._type
        if stix_type == 'vulnerability':
            value = o.get('name')
        else:
            if stix_type == 'indicator':
                if hasattr(o, 'valid_until'):
                    org_uuid = o['created_by_ref'].split('--')[1]
                    attribute['Sighting'] = [{'type': '2', 'date_sighting': str(self.getTimestampfromDate(o['valid_until'])),
                                             'Organisation': {'uuid': org_uuid, 'name': self.event['identity'][org_uuid]['name']}}]
                pattern = o.pattern.replace('\\\\', '\\')
                value = self.parse_pattern_with_data(pattern) if attribute_type in ('malware-sample', 'attachment') else self.parse_pattern(pattern)
                attribute['to_ids'] = True
            else:
                attribute['timestamp'] = self.getTimestampfromDate(o.get('last_observed'))
                observable = o.objects
                try:
                    value = self.parse_observable(observable, attribute_type)
                except Exception:
                    print('Error with attribute type {}:\n{}'.format(attribute_type, observable), file=sys.stderr)
                attribute['to_ids'] = False
        if 'description' in o:
            attribute['comment'] = o.get('description')
        if isinstance(value, tuple):
            value, data = value
            attribute['data'] = io.BytesIO(data.encode())
        attribute['value'] = value
        self.misp_event.add_attribute(**attribute)

    def parse_vulnerability(self, o, labels):
        if len(labels) > 2:
            self.parse_usual_object(o, labels)
        else:
            self.parse_galaxy(o, labels)

    def observable_email(self, observable):
        attributes = []
        addresses, files, message = self.parse_observable_email(observable)
        attributes.append({'type': 'email-src', 'object_relation': 'from',
                           'value': addresses[message.pop('from_ref')], 'to_ids': False})
        for ref in ('to_refs', 'cc_refs'):
            attributes.extend([self.append_email_attribute(ref, addresses[item], False) for item in message.pop(ref) if ref in message])
        body_multipart = 'body_multipart'
        attributes.extend([self.append_email_attribute(body_multipart, files[f.get('body_raw_ref')], False) for f in message.pop(body_multipart) if body_multipart in message])
        for m_key, m_value in message.items():
            if m_key == 'additional_header_fields':
                for field_key, field_value in m_value.items():
                    if field_key == 'Reply-To':
                        attributes.extend([self.append_email_attribute(field_key, rt, False) for rt in field_value])
                    else:
                        attributes.append(self.append_email_attribute(field_key, field_value, False))
            else:
                try:
                    attributes.append(self.append_email_attribute(m_key, m_value, False))
                except KeyError:
                    if m_key.startswith("x_misp_attachment_"):
                        attribute_type, relation = m_key.split("x_misp_")[1].split("_")
                        attributes.append({'type': attribute_type, 'object_relation': relation, 'to_ids': False,
                                           'value': m_value['value'], 'data': io.BytesIO(m_value['data'].encode())})
                    elif "x_misp_" in m_key:
                        attribute_type, relation = m_key.split("x_misp_")[1].split("_")
                        attributes.append({'type': attribute_type, 'object_relation': relation,
                                           'value': m_value, 'to_ids': False})
        return attributes

    @staticmethod
    def parse_observable_email(observable):
        addresses = {}
        files = {}
        for o_key, o_dict in observable.items():
            part_type = o_dict._type
            if part_type == 'email-addr':
                addresses[o_key] = o_dict.get('value')
            elif part_type == 'file':
                files[o_key] = o_dict.get('name')
            else:
                message = dict(o_dict)
        return addresses, files, message

    def pattern_email(self, pattern):
        attributes = []
        attachments = defaultdict(dict)
        for p in pattern:
            p_type, p_value = p.split(' = ')
            try:
                attributes.append(self.append_email_attribute(p_type, p_value[1:-1], True))
            except KeyError:
                if p_type.startswith("email-message:'x_misp_attachment_"):
                    relation, field = p_type.split('.')
                    relation = relation.split(':')[1][1:-1]
                    attachments[relation][field] = p_value[1:-1]
                elif "x_misp_" in p_type:
                    attribute_type, relation = p_type.split("x_misp_")[1][:-1].split("_")
                    attributes.append({'type': attribute_type, 'object_relation': relation,
                                       'value': p_value[1:-1], 'to_ids': True})
        for a_key, a_dict in attachments.items():
            _, _, attribute_type, relation = a_key.split('_')
            attributes.append({'type': attribute_type, 'object_relation': relation, 'to_ids': True,
                               'value': a_dict['value'], 'data': io.BytesIO(a_dict['data'].encode())})
        return attributes

    @staticmethod
    def append_email_attribute(_type, value, to_ids):
        mapping = email_mapping[_type]
        return {'type': mapping['type'], 'object_relation': mapping['relation'], 'value': value, 'to_ids': to_ids}

    @staticmethod
    def pattern_file(pattern):
        attributes = []
        malware_sample = {}
        for p in pattern:
            p_type, p_value = p.split(' = ')
            if p_type == 'artifact:payload_bin':
                malware_sample['data'] = p_value
            elif p_type in ("file:name", "file:hashes.'md5'"):
                try:
                    mapping = file_mapping[p_type]
                    attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                       'value': p_value[1:-1], 'to_ids': True})
                    malware_sample['filename'] = p_value[1:-1]
                except KeyError:
                    attributes.append({'type': 'md5', 'object_relation': 'md5',
                                       'value': p_value[1:-1], 'to_ids': True})
                    malware_sample['md5'] = p_value[1:-1]
            elif 'file:hashes.' in p_type:
                _, h = p_type.split('.')
                h = h[1:-1]
                attributes.append({'type': h, 'object_relation': h, 'value': p_value[1:-1]})
            else:
                try:
                    mapping = file_mapping[p_type]
                    attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                       'value': p_value[1:-1], 'to_ids': True})
                except KeyError:
                    if "x_misp_" in  p_type:
                        attribute_type, relation = p_type.split("x_misp_")[1][:-1].split("_")
                        attributes.append({'type': attribute_type, 'object_relation': relation,
                                           'value': p_value[1:-1], 'to_ids': True})
        if 'data' in malware_sample:
            value = "{}|{}".format(malware_sample['filename'], malware_sample['md5'])
            attributes.append({'type': 'malware-sample', 'object_relation': 'malware-sample',
                               'value': value, 'to_ids': True, 'data': io.BytesIO(malware_sample['data'].encode())})
        return attributes

    def observable_pe(self, observable):
        extension = observable['1']['extensions']['windows-pebinary-ext']
        sections = extension['sections']
        pe = MISPObject('pe')
        pe_uuid = str(uuid.uuid4())
        pe.uuid = pe_uuid
        self.fill_object_attributes_observable(pe, pe_mapping, extension)
        for section in sections:
            pe_section = MISPObject('pe-section')
            if 'hashes' in section:
                for h_type, h_value in section['hashes'].items():
                    h_type = h_type.lower().replace('-', '')
                    pe_section.add_attribute(**{'type': h_type, 'object_relation': h_type,
                                                'value': h_value, 'to_ids': False})
            self.fill_object_attributes_observable(pe_section, pe_section_mapping, section)
            section_uuid = str(uuid.uuid4())
            pe_section.uuid = section_uuid
            pe.add_reference(section_uuid, 'included-in')
            self.misp_event.add_object(**pe_section)
        self.misp_event.add_object(**pe)
        return observable_file(observable), pe_uuid

    @staticmethod
    def fill_object_attributes_observable(misp_object, mapping_dict, stix_object):
        for stix_type, value in stix_object.items():
            try:
                mapping = mapping_dict[stix_type]
                misp_object.add_attribute(**{'type': mapping['type'], 'object_relation': mapping['relation'],
                                             'value': value, 'to_ids': False})
            except KeyError:
                if stix_type.startswith("x_misp_"):
                    attribute_type, relation = parse_custom_property(stix_type)
                    misp_object.add_attribute(**{'type': attribute_type, 'object_relation': relation[:-1],
                                                 'value': value, 'to_ids': False})

    def pattern_pe(self, pattern):
        attributes = []
        sections = defaultdict(dict)
        pe = MISPObject('pe')
        pe_uuid = str(uuid.uuid4())
        pe.uuid = pe_uuid
        for p in pattern:
            p_type, p_value = p.split(' = ')
            p_value = p_value[1:-1]
            if ':extensions.' in p_type:
                if '.sections[' in p_type:
                    p_type_list = p_type.split('.')
                    stix_type = "hashes.{}".format(p_type_list[4][1:-1]) if '.hashes.' in p_type else p_type_list[3]
                    sections[p_type_list[2]][stix_type] = p_value
                else:
                    stix_type = p_type.split('.')[-1]
                    try:
                        mapping = pe_mapping[stix_type]
                        pe.add_attribute(**{'type': mapping['type'], 'object_relation': mapping['relation'],
                                            'value': p_value, 'to_ids': True})
                    except KeyError:
                        if stix_type.startswith("x_misp_"):
                            attribute_type, relation = parse_custom_property(stix_type)
                            pe.add_attribute(**{'type': attribute_type, 'object_relation': relation[:-2],
                                                'value': p_value, 'to_ids': False})
            else:
                if 'file:hashes.' in p_type :
                    _, h = p_type.split('.')
                    h = h[1:-1]
                    attributes.append({'type': h, 'object_relation': h, 'value': p_value, 'to_ids': True})
                else:
                    try:
                        mapping = file_mapping[p_type]
                        attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                           'value': p_value, 'to_ids': True})
                    except KeyError:
                        if "x_misp_" in  p_type:
                            attribute_type, relation = p_type.split("x_misp_")[1][:-1].split("_")
                            attributes.append({'type': attribute_type, 'object_relation': relation,
                                               'value': p_value, 'to_ids': True})
        for _, section in sections.items():
            pe_section = MISPObject('pe-section')
            for stix_type, value in section.items():
                if 'hashes.' in stix_type:
                    h_type = stix_type.split('.')[1]
                    pe_section.add_attribute(**{'type': h_type, 'object_relation': h_type,
                                                'value': value, 'to_ids': True})
                else:
                    try:
                        mapping = pe_section_mapping[stix_type]
                        pe_section.add_attribute(**{'type': mapping['type'], 'object_relation': mapping['relation'],
                                                    'value': value, 'to_ids': True})
                    except KeyError:
                        if "x_misp_" in  stix_type:
                            attribute_type, relation = stix_type.split("x_misp_")[1][:-1].split("_")
                            attributes.append({'type': attribute_type, 'object_relation': relation,
                                               'value': value, 'to_ids': True})
            section_uuid = str(uuid.uuid4())
            pe_section.uuid = pe_uuid
            pe.add_reference(section_uuid, 'included-in')
            self.misp_event.add_object(**pe_section)
        self.misp_event.add_object(**pe)
        return attributes, pe_uuid


class ExternalStixParser(StixParser):
    def __init__(self):
        super(ExternalStixParser, self).__init__()
        self.object_from_refs = {'course-of-action': self.parse_course_of_action, 'vulnerability': self.parse_external_vulnerability,
                                 'indicator': self.parse_external_indicator, 'observed-data': self.parse_external_observable}
        self.object_from_refs.update(dict.fromkeys(list(galaxy_types.keys()), self.parse_external_galaxy))

    def handler(self):
        self.version_attribute = {'type': 'text', 'object_relation': 'version', 'value': self.stix_version}
        self.general_handler()

    def parsing_process(self, object2parse, object_type):
        self.object_from_refs[object_type](object2parse)

    def parse_external_galaxy(self, o):
        galaxy = {'name': galaxy_types[o._type].replace('-', ' ').title()}
        cluster = defaultdict(dict)
        cluster['value'] = o.get('name')
        cluster['description'] = o.get('description')
        if 'kill_chain_phases' in o:
            galaxy_type = o['kill_chain_phases'][0].get('phase_name')
            galaxy['type'] = galaxy_type
            cluster['type'] = galaxy_type
        if 'aliases' in o:
            aliases = []
            for a in o.get('aliases'):
                aliases.append(a)
            cluster['meta']['synonyms'] = aliases
        galaxy['GalaxyCluster'] = [cluster]
        self.misp_event['Galaxy'].append(galaxy)

    def parse_external_indicator(self, o):
        pattern = o.get('pattern')
        self.parse_external_pattern(pattern)
        attribute = {'type': 'stix2-pattern', 'object_relation': 'stix2-pattern', 'value': pattern}
        misp_object = {'name': 'stix2-pattern', 'meta-category': 'stix2-pattern',
                       'Attribute': [self.version_attribute, attribute]}
        self.misp_event.add_object(**misp_object)

    def parse_external_observable(self, o):
        observable = o.get('objects')
        # deeper analyse to come, as well as for indicators

    def parse_external_pattern(self, pattern):
        if ' OR ' in pattern and ' AND ' not in pattern:
            pattern = pattern.split('OR')
            for p in pattern:
                attribute = self.attribute_from_external_pattern(p)
                self.misp_event.add_attribute(**attribute)
        elif ' OR ' not in pattern and ' LIKE ' not in pattern:
            pattern = pattern.split('AND')
            if len(pattern) == 1:
                attribute = self.attribute_from_external_pattern(pattern[0])
                self.misp_event.add_attribute(**attribute)

    def parse_external_vulnerability(self, o):
        attribute = {'type': 'vulnerability', 'value': o.get('name')}
        if 'description' in o:
            attribute['comment'] = o.get('description')
        self.misp_event.add_attribute(**attribute)

    @staticmethod
    def attribute_from_external_pattern(pattern):
        pattern_type, pattern_value = pattern.split(' = ')
        pattern_type, pattern_value = pattern_type[1:].strip(), pattern_value[1:-2].strip()
        stix_type, value_type = pattern_type.split(':')
        if 'hashes' in value_type and 'x509' not in stix_type:
            h_type = value_type.split('.')[1]
            return {'type': h_type, 'value': pattern_value}
        # Might cause some issues, need more examples to test
        return {'type': external_pattern_mapping[stix_type][value_type].get('type'), 'value': pattern_value}

def from_misp(reports):
    for _, o in reports.items():
        if 'misp:tool="misp2stix2"' in o.get('labels'):
            return True
    return False

def main(args):
    stix_event = defaultdict(dict)
    filename = os.path.join(os.path.dirname(args[0]), args[1])
    with open(filename, 'rb') as f:
        event = stix2.parse(f.read().decode('utf-8'), allow_custom=True)
    for parsed_object in event.objects:
        try:
            object_type = parsed_object._type
        except AttributeError:
            object_type = parsed_object['type']
        object_uuid = parsed_object['id'].split('--')[1]
        if object_type.startswith('x-misp-object'):
            object_type = 'x-misp-object'
        stix_event[object_type][object_uuid] = parsed_object
    if not stix_event:
        print(json.dumps({'success': 0, 'message': 'There is no valid STIX object to import'}))
        sys.exit(1)
    stix_version = 'STIX {}'.format(event.get('spec_version'))
    stix_parser = StixFromMISPParser() if from_misp(stix_event['report']) else ExternalStixParser()
    stix_parser.load_data(filename, stix_version, stix_event, args[2:])
    stix_parser.handler()
    stix_parser.saveFile()
    print(1)

if __name__ == "__main__":
    main(sys.argv)
