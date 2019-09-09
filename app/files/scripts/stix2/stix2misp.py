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
from stix2misp_mapping import *
from collections import defaultdict

_MISP_dir = "/".join([p for p in os.path.dirname(os.path.realpath(__file__)).split('/')[:-4]])
_PyMISP_dir = '{_MISP_dir}/PyMISP'.format(_MISP_dir=_MISP_dir)
_MISP_objects_path = '{_MISP_dir}/app/files/misp-objects/objects'.format(_MISP_dir=_MISP_dir)
sys.path.append(_PyMISP_dir)
from pymisp.mispevent import MISPEvent, MISPObject, MISPAttribute
from pymisp.exceptions import PyMISPInvalidFormat
TAG_REGEX = re.compile(r"\(.+\) .+ = .+")
special_parsing = ('relationship', 'report', 'galaxy', 'marking-definition')
galaxy_types = {'attack-pattern': 'Attack Pattern', 'intrusion-set': 'Intrusion Set',
                'malware': 'Malware', 'threat-actor': 'Threat Actor', 'tool': 'Tool'}
with open('{_PyMISP_dir}/pymisp/data/describeTypes.json'.format(_PyMISP_dir=_PyMISP_dir), 'r') as f:
    misp_types = json.loads(f.read())['result'].get('types')

class StixParser():
    def __init__(self):
        super(StixParser, self).__init__()
        self.misp_event = MISPEvent()
        self.misp_event['Galaxy'] = []

    def load_data(self, filename, version, event, args):
        self.filename = filename
        self.stix_version = version
        for object_type in special_parsing:
            setattr(self, object_type.replace('-', '_'), event.pop(object_type) if object_type in event else {})
        self.event = event
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
        self.misp_event.distribution = event_distribution
        self._attribute_distribution = attribute_distribution

    def general_handler(self):
        self.outputname = '{}.stix2'.format(self.filename)
        self.build_from_STIX_with_report() if self.report else self.build_from_STIX_without_report()
        self.set_distribution()
        for galaxy in self.galaxy.values():
            if galaxy['used'] == False:
                self.misp_event['Galaxy'].append(self.parse_galaxies(galaxy['object']))
        for marking in self.marking_definition.values():
            if marking['used'] == False:
                try:
                    self.misp_event.add_tag(self.parse_marking(marking['object']))
                except PyMISPInvalidFormat:
                    continue

    def build_from_STIX_with_report(self):
        report_attributes = defaultdict(set)
        for report in self.report.values():
            try:
                report_attributes['orgs'].add(report.created_by_ref.split('--')[1])
            except AttributeError:
                pass
            report_attributes['name'].add(report.name)
            if report.get('published'):
                report_attributes['published'].add(report.published)
            if 'labels' in report:
                report_attributes['labels'].update([l for l in report.labels])
            if 'external_references' in report:
                self.add_links(report.external_references)
            for ref in report.object_refs:
                object_type, uuid = ref.split('--')
                if object_type not in special_parsing and object_type not in galaxy_types:
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

    def build_from_STIX_without_report(self):
        for object_type, objects in self.event.items():
            for _, _object in objects.items():
                self.parsing_process(_object, object_type)
        self.misp_event.info = "Imported with MISP import script for {}.".format(self.stix_version)

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

    ################################################################################
    ##                 PARSING FUNCTIONS USED BY BOTH SUBCLASSES.                 ##
    ################################################################################

    def add_tag_in_attribute(self, attribute, marking_refs):
        attribute = self.pyMISPify(attribute)
        for marking in marking_refs:
            marking_uuid = marking.split('--')[1]
            marking = self.marking_definition[marking_uuid]
            tag = self.parse_marking(marking['object'])
            if tag is not None:
                attribute.add_tag(self.parse_marking(marking['object']))
            marking['used'] = True
        return attribute

    @staticmethod
    def append_email_attribute(_type, value, to_ids):
        mapping = email_mapping[_type]
        return {'type': mapping['type'], 'object_relation': mapping['relation'], 'value': value, 'to_ids': to_ids}

    def attributes_from_asn_observable(self, objects):
        attributes = []
        for _object in objects.values():
            attributes.extend(self.fill_observable_attributes(_object, asn_mapping))
        return attributes

    def attributes_from_domain_ip_observable(self, objects):
        attributes = []
        for _object in objects.values():
            mapping = domain_ip_mapping[_object.type]
            attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                               'value': _object.value, 'to_ids': False})
        return attributes

    def attributes_from_file_observable(self, _object, data=None):
        attributes = []
        md5 = None
        if hasattr(_object, 'hashes'):
            if 'MD5' in _object.hashes:
                md5 = _object.hashes['MD5']
            for h_type, h_value in _object.hashes.items():
                h_type = h_type.lower().replace('-', '')
                attributes.append({'type': h_type, 'object_relation': h_type,
                                   'value': h_value, 'to_ids': False})
        attributes.extend(self.fill_observable_attributes(_object, file_mapping))
        if data is not None and md5 and hasattr(_object, 'name'):
            attributes.append({'type': 'malware-sample', 'object_relation': 'malware-sample',
                               'value': '{}|{}'.format(_object.name, md5), 'data': data})
        return attributes

    @staticmethod
    def attributes_from_file_pattern(types, values):
        attributes = []
        for type_, value in zip(types, values):
            if 'hashes' in type_:
                hash_type = type_.split('.')[1].strip("'").replace('-', '').lower()
                attributes.append({'type': hash_type, 'value': value,
                                   'object_relation': hash_type, 'to_ids': True})
            else:
                try:
                    mapping = file_mapping[type_]
                    attributes.append({'type': mapping['type'], 'value': value,
                                       'object_relation': mapping['relation'], 'to_ids': True})
                except KeyError:
                    continue
        return attributes

    def attributes_from_network_traffic(self, objects, name=None):
        network_traffic, references = self.fetch_network_traffic_objects_and_references(objects)
        attributes = self.fill_observable_attributes(network_traffic, network_traffic_mapping)
        if name is not None:
            mapping = network_socket_types
            for protocol in network_traffic.protocols:
                try:
                    layer = connection_protocols[protocol]
                    attributes.append({'type': 'text', 'value': protocol, 'to_ids': False,
                                       'object_relation': 'layer{}-protocol'.format(layer)})
                except KeyError:
                    continue
        elif hasattr(network_traffic, 'extensions') and network_traffic.extensions:
            extension_type, extension_value = list(network_traffic.extensions.items())[0]
            name = network_traffic_extensions[extension_type]
            attributes.extend(self.parse_socket_extension(extension_value))
            mapping = network_traffic_references_mapping['with_extensions']
        else:
            name = 'ip-port'
            mapping = network_traffic_references_mapping['without_extensions']
        attributes.extend(self.parse_network_traffic_references(references, network_traffic, mapping))
        if references:
            attributes.extend(self.parse_remaining_references(references, mapping))
        return attributes, name

    def attributes_from_process_observable(self, objects):
        main_process = None
        for _object in objects.values():
            if hasattr(_object, 'parent_ref') or hasattr(_object, 'child_refs'):
                main_process = _object
                break
        if main_process:
            attributes = self.fill_observable_attributes(main_process, process_mapping)
            for refs in ('parent_ref', 'child_refs'):
                if hasattr(main_process, refs):
                    attributes.extend([self.parse_reference_process(objects[ref], refs) for ref in getattr(main_process, refs)])
            return attributes
        return [result for _object in objects.values() for result in self.fill_observable_attributes(_object, process_mapping)]

    @staticmethod
    def parse_reference_process(process, ref_type):
        field = 'pid'
        mapping = process_mapping[field]
        relation = '{}-{}'.format(ref_type.split('_')[0], mapping['relation'])
        return {'type': mapping['type'], 'object_relation': relation, 'value': getattr(process, field), 'to_ids': False}

    def attributes_from_regkey_observable(self, _object):
        attributes = []
        for key, value in _object.items():
            if key in regkey_mapping:
                mapping = regkey_mapping[key]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': value.replace('\\\\', '\\'), 'to_ids': False})
        if 'values' in _object:
            attributes.extend(self.fill_observable_attributes(_object.values[0], regkey_mapping))
        return attributes

    @staticmethod
    def attributes_from_url_observable(objects):
        attributes = []
        for value in objects.values():
            if isinstance(value, (stix2.URL, stix2.DomainName)):
                mapping = url_mapping[value._type]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': value.value, 'to_ids': False})
            elif isinstance(value, stix2.NetworkTraffic):
                mapping = url_mapping[value._type]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': value.dst_port, 'to_ids': False})
        return attributes

    def attributes_from_user_account_observable(self, observable):
        observable = observable['0']
        attributes = self.fill_user_account_observable_attributes(observable)
        if 'extensions' in observable and 'unix-account-ext' in observable['extensions']:
            extension = observable['extensions']['unix-account-ext']
            if 'groups' in extension:
                for group in extension['groups']:
                    attributes.append({'type': 'text', 'object_relation': 'group',
                                       'to_ids': False, 'disable_correlation': True,
                                       'value': group})
        attributes.extend(self.fill_user_account_observable_attributes(extension))
        return attributes

    def attributes_from_user_account_pattern(self, pattern):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            p_value = p_value[1:-1]
            if "extensions.'unix-account-ext'" in p_type:
                relation = p_type.split('.')[-1]
                if 'groups' in relation:
                    attributes.append({'type': 'text', 'object_relation': 'group',
                                       'disable_correlation': True, 'value': p_value})
                    continue
            else:
                relation = p_type.split(':')[1]
            if relation in user_account_mapping:
                attribute = {'value': p_value}
                attribute.update(user_account_mapping[relation])
                attributes.append(attribute)
        return attributes

    def attributes_from_x509_observable(self, objects):
        _object = objects['0']
        attributes = self.fill_observable_attributes(_object.hashes, x509_mapping) if (hasattr(_object, 'hashes') and _object.hashes) else []
        attributes.extend(self.fill_observable_attributes(_object, x509_mapping))
        return attributes

    @staticmethod
    def extract_data_from_file(objects):
        data = None
        for value in objects.values():
            if isinstance(value, stix2.Artifact):
                data = value.payload_bin
            elif isinstance(value, stix2.File):
                file = value
        return file, data

    @staticmethod
    def fetch_network_traffic_objects_and_references(objects):
        references = {}
        for key, value in objects.items():
            if isinstance(value, (stix2.DomainName, stix2.IPv4Address, stix2.IPv6Address)):
                references[key] = value
            elif isinstance(value, stix2.NetworkTraffic):
                network_traffic = value
        return network_traffic, references

    @staticmethod
    def fill_user_account_observable_attributes(observable):
        attributes = []
        for key, value in observable.items():
            if key in user_account_mapping:
                attribute = {'to_ids': False, 'value': value}
                attribute.update(user_account_mapping[key])
                attributes.append(attribute)
        return attributes

    def handle_object_relationship(self, misp_object, uuid):
        for reference in self.relationship[uuid]:
            target = reference.target_ref.split('--')[1]
            if target not in self.galaxy:
                misp_object.add_reference(target, reference.relationship_type)

    def handle_single_attribute(self, attribute, uuid=None):
        if uuid is not None:
            if uuid in self.relationship:
                galaxies = []
                for reference in self.relationship[uuid]:
                    target = reference.target_ref.split('--')[1]
                    if target in self.galaxy:
                        galaxy = self.galaxy[target]
                        galaxies.append(self.parse_external_galaxy(galaxy['object']))
                        galaxy['used'] = True
                if galaxies:
                    attribute['Galaxy'] = galaxies
        self.misp_event.add_attribute(**attribute)

    def parse_complex_fields_observable_email(self, objects, to_ids):
        attributes = []
        addresses, files, message = self.split_observable_email_parts(objects)
        if 'from_ref' in message:
            from_ref = 'from_ref'
            attributes.append(self.append_email_attribute(from_ref, addresses[message.pop(from_ref)], to_ids))
        for ref in ('to_refs', 'cc_refs'):
            if ref in message:
                attributes.extend([self.append_email_attribute(ref, addresses[item], to_ids) for item in message.pop(ref)])
        if 'body_multipart' in message:
            brr = 'body_raw_ref'
            attributes.extend([self.append_email_attribute('body_multipart', files[f[brr]], to_ids) for f in message.pop('body_multipart') if brr in f])
        if 'additional_header_fields' in message:
            for field_key, field_value in message.pop('additional_header_fields').items():
                if field_key == 'Reply-To':
                    attributes.extend([self.append_email_attribute(field_key, reply_to, to_ids) for reply_to in field_value])
                else:
                    attributes.append(self.append_email_attribute(field_key, field_value, to_ids))
        return attributes, message

    def parse_course_of_action(self, o):
        misp_object = MISPObject('course-of-action', misp_objects_path_custom=_MISP_objects_path)
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
    def __parse_network_traffic_reference(ref_object, ref, mapping):
        origin = ref.split('_')[0]
        misp_type, relation = mapping[ref_object._type]
        return {'type': misp_type.format(origin), 'object_relation': relation.format(origin),
                'to_ids': False, 'value': ref_object.value}

    def parse_network_traffic_references(self, objects, network_traffic, mapping):
        attributes= []
        for ref in ('src_ref', 'dst_ref'):
            if hasattr(network_traffic, ref):
                ref_object = objects.pop(getattr(network_traffic, ref))
                attributes.append(self.__parse_network_traffic_reference(ref_object, ref, mapping))
        for refs in ('src_refs', 'dst_refs'):
            if hasattr(network_traffic, refs):
                for ref in getattr(network_traffic, refs):
                    ref_object = objects.pop(ref)
                    attributes.append(self.__parse_network_traffic_reference(ref_object, refs, mapping))
        return attributes

    def parse_pe(self, extension):
        pe = MISPObject('pe', misp_objects_path_custom=_MISP_objects_path)
        self.fill_object_attributes_observable(pe, pe_mapping, extension)
        for section in extension['sections']:
            pe_section = MISPObject('pe-section', misp_objects_path_custom=_MISP_objects_path)
            if 'hashes' in section:
                for h_type, h_value in section['hashes'].items():
                    h_type = h_type.lower().replace('-', '')
                    pe_section.add_attribute(**{'type': h_type, 'object_relation': h_type,
                                                'value': h_value, 'to_ids': False})
            self.fill_object_attributes_observable(pe_section, pe_section_mapping, section)
            pe.add_reference(pe_section.uuid, 'includes')
            self.misp_event.add_object(**pe_section)
        self.misp_event.add_object(**pe)
        return pe.uuid

    @staticmethod
    def parse_remaining_references(references, mapping):
        attributes = []
        for reference in references.values():
            misp_type, relation = mapping[reference._type]
            attributes.append({'type': misp_type, 'object_relation': relation,
                               'to_ids': False, 'value': reference.value})
        return attributes

    @staticmethod
    def parse_socket_extension(extension):
        attributes = []
        for element in extension:
            try:
                mapping = network_traffic_mapping[element]
            except KeyError:
                continue
            if element in ('is_listening', 'is_blocking'):
                attribute_value = element.split('_')[1]
            else:
                attribute_value = extension[element]
            attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                               'value': attribute_value})
        return attributes

    @staticmethod
    def pyMISPify(attribute_dict):
        attribute = MISPAttribute()
        attribute.from_dict(**attribute_dict)
        return attribute

    @staticmethod
    def split_observable_email_parts(observable):
        addresses = {}
        files = {}
        message = None
        for o_key, o_dict in observable.items():
            if isinstance(o_dict, stix2.EmailAddress):
                addresses[o_key] = o_dict.value
            elif isinstance(o_dict, stix2.EmailMessage):
                message = dict(o_dict)
            elif isinstance(o_dict, stix2.File):
                files[o_key] = o_dict.name
        return addresses, files, message


class StixFromMISPParser(StixParser):
    def __init__(self):
        super(StixFromMISPParser, self).__init__()
        self.objects_mapping = {'asn': {'observable': self.attributes_from_asn_observable, 'pattern': self.pattern_asn},
                                'credential': {'observable': self.observable_credential, 'pattern': self.pattern_credential},
                                'domain-ip': {'observable': self.attributes_from_domain_ip_observable, 'pattern': self.pattern_domain_ip},
                                'email': {'observable': self.observable_email, 'pattern': self.pattern_email},
                                'file': {'observable': self.observable_file, 'pattern': self.pattern_file},
                                'ip-port': {'observable': self.observable_ip_port, 'pattern': self.pattern_ip_port},
                                'network-connection': {'observable': self.observable_connection, 'pattern': self.pattern_connection},
                                'network-socket': {'observable': self.observable_socket, 'pattern': self.pattern_socket},
                                'process': {'observable': self.attributes_from_process_observable, 'pattern': self.pattern_process},
                                'registry-key': {'observable': self.attributes_from_regkey_observable, 'pattern': self.pattern_regkey},
                                'url': {'observable': self.attributes_from_url_observable, 'pattern': self.pattern_url},
                                'user-account': {'observable': self.attributes_from_user_account_observable,
                                                 'pattern': self.attributes_from_user_account_pattern},
                                'WindowsPEBinaryFile': {'observable': self.observable_pe, 'pattern': self.pattern_pe},
                                'x509': {'observable': self.attributes_from_x509_observable, 'pattern': self.pattern_x509}}
        self.object_from_refs = {'course-of-action': self.parse_MISP_course_of_action, 'vulnerability': self.parse_vulnerability,
                                 'x-misp-object': self.parse_custom}
        self.object_from_refs.update(dict.fromkeys(['indicator', 'observed-data'], self.parse_usual_object))

    def handler(self):
        self.general_handler()

    def parsing_process(self, object2parse, object_type):
        labels = object2parse.get('labels')
        self.object_from_refs[object_type](object2parse, labels)

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################

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
                                     'description': cluster_description, 'collection_uuid': uuid}]}
        return galaxy

    def parse_MISP_course_of_action(self, o, _):
        self.parse_course_of_action(o)

    def parse_custom(self, o, labels):
        if 'from_object' in labels:
            self.parse_custom_object(o, labels)
        else:
            self.parse_custom_attribute(o, labels)

    def parse_custom_object(self, o, labels):
        name = o['type'].split('x-misp-object-')[1]
        misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
        misp_object.timestamp = self.getTimestampfromDate(o['x_misp_timestamp'])
        misp_object.uuid = o['id'].split('--')[1]
        try:
            misp_object.category = o['category']
        except KeyError:
            misp_object.category = self.get_misp_category(labels)
        attributes = []
        for key, value in o['x_misp_values'].items():
            attribute_type, object_relation = key.split('_')
            misp_object.add_attribute(**{'type': attribute_type, 'value': value, 'object_relation': object_relation})
        self.misp_event.add_object(**misp_object)

    def parse_custom_attribute(self, o, labels):
        attribute_type = o['type'].split('x-misp-object-')[1]
        if attribute_type not in misp_types:
            replacement = ' ' if attribute_type == 'named-pipe' else '|'
            attribute_type = attribute_type.replace('-', replacement)
        attribute = {'type': attribute_type,
                     'timestamp': self.getTimestampfromDate(o['x_misp_timestamp']),
                     'to_ids': bool(labels[1].split('=')[1]),
                     'value': o['x_misp_value'],
                     'category': self.get_misp_category(labels),
                     'uuid': o['id'].split('--')[1]}
        if o.get('object_marking_refs'):
            attribute = self.add_tag_in_attribute(attribute, o['object_marking_refs'])
        self.misp_event.add_attribute(**attribute)

    def parse_object(self, o, labels):
        object_type = self.get_misp_type(labels)
        name = 'file' if object_type == 'WindowsPEBinaryFile' else object_type
        object_category = self.get_misp_category(labels)
        stix_type = o._type
        misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
        uuid = o.id.split('--')[1]
        misp_object.uuid = uuid
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
            misp_object.add_reference(pe_uuid, 'includes')
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        misp_object.to_ids = (labels[2].split('=')[1][1:-1].lower() == 'true')
        if uuid in self.relationship:
            self.handle_object_relationship(misp_object, uuid)
        self.misp_event.add_object(**misp_object)

    def parse_attribute(self, o, labels):
        attribute_uuid = o.id.split('--')[1]
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
                    org_uuid = o.created_by_ref.split('--')[1]
                    attribute['Sighting'] = [{'type': '2', 'date_sighting': str(self.getTimestampfromDate(o.valid_until)),
                                             'Organisation': {'uuid': org_uuid, 'name': self.event['identity'][org_uuid]['name']}}]
                pattern = o.pattern.replace('\\\\', '\\')
                value = self.parse_pattern_with_data(pattern) if attribute_type in ('malware-sample', 'attachment') else self.parse_pattern(pattern)
                attribute['to_ids'] = True
            else:
                attribute['timestamp'] = self.getTimestampfromDate(o.get('last_observed'))
                observable = o.objects
                try:
                    value = misp_types_mapping[attribute_type](observable, attribute_type)
                except Exception:
                    print('Error with attribute type {}:\n{}'.format(attribute_type, observable), file=sys.stderr)
                attribute['to_ids'] = False
        if hasattr(o, 'description'):
            attribute['comment'] = o.description
        if isinstance(value, tuple):
            value, data = value
            attribute['data'] = io.BytesIO(data.encode())
        attribute['value'] = value
        if hasattr(o, 'object_marking_refs'):
            attribute = self.add_tag_in_attribute(attribute, o.object_marking_refs)
        self.handle_single_attribute(attribute, uuid=attribute_uuid)

    def parse_vulnerability(self, o, labels):
        if len(labels) > 2:
            self.parse_usual_object(o, labels)
        else:
            self.misp_event['Galaxy'].append(self.parse_galaxy(o, labels))

    def observable_connection(self, observable):
        attributes, _ = self.attributes_from_network_traffic(observable, 'network-connection')
        return attributes

    def pattern_connection(self, pattern):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            p_value = p_value[1:-1]
            try:
                mapping = network_traffic_mapping[p_type]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': p_value})
            except KeyError:
                if not p_type.startswith('network-traffic:protocols['):
                    continue
                attributes.append({'type': 'text', 'value': p_value,
                                   'object_relation': 'layer{}-protocol'.format(connection_protocols[p_value])})
        return attributes

    def observable_credential(self, observable):
        return self.fill_observable_attributes(observable['0'], credential_mapping)

    def pattern_credential(self, pattern):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            p_type = p_type.split(':')[1]
            p_value = p_value[1:-1]
            try:
                mapping = credential_mapping[p_type]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': p_value})
            except KeyError:
                if not p_type.startswith('x_misp_'):
                    continue
                attribute_type, relation = p_type.strip('x_misp_').split('_')
                attributes.append({'type': attribute_type, 'object_relation': relation,
                                   'value': p_value})
        return attributes

    def observable_email(self, observable):
        to_ids = False
        attributes, message = self.parse_complex_fields_observable_email(observable, to_ids)
        for m_key, m_value in message.items():
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

    def observable_file(self, observable):
        if len(observable) > 1:
            file, data = self.extract_data_from_file(observable)
            if data is not None:
                return self.attributes_from_file_observable(file, data)
        return self.attributes_from_file_observable(observable['0'])

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
        pe_uuid = self.parse_pe(extension)
        return self.observable_file(observable), pe_uuid

    def pattern_pe(self, pattern):
        attributes = []
        sections = defaultdict(dict)
        pe = MISPObject('pe', misp_objects_path_custom=_MISP_objects_path)
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
                            attribute_type, relation = self.parse_custom_property(stix_type)
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
            pe_section = MISPObject('pe-section', misp_objects_path_custom=_MISP_objects_path)
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
            pe.add_reference(pe_section.uuid, 'includes')
            self.misp_event.add_object(**pe_section)
        self.misp_event.add_object(**pe)
        return attributes, pe.uuid

    def pattern_asn(self, pattern):
        return self.fill_pattern_attributes(pattern, asn_mapping)

    def pattern_domain_ip(self, pattern):
        return self.fill_pattern_attributes(pattern, domain_ip_mapping)

    def observable_ip_port(self, observable):
        attributes, _ = self.attributes_from_network_traffic(observable)
        return attributes

    def pattern_ip_port(self, pattern):
        return self.fill_pattern_attributes(pattern, network_traffic_mapping)

    @staticmethod
    def pattern_process(pattern):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            try:
                mapping = process_mapping[p_type]
            except KeyError:
                continue
            if p_type == 'process:child_refs':
                for value in p_value[1:-1].split(','):
                    attribute.append({'type': mapping['type'], 'value': value.strip(),
                                     'object_relation': mapping['relation']})
            else:
                attributes.append({'type': mapping['type'], 'value': p_value,
                                   'object_relation': mapping['relation']})
        return attributes

    @staticmethod
    def pattern_regkey(pattern):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            try:
                mapping = regkey_mapping[p_type]
            except KeyError:
                continue
            attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                               'value': p_value.replace('\\\\', '\\')[1:-1]})
        return attributes

    def observable_socket(self, observable):
        attributes, _ = self.attributes_from_network_traffic(observable)
        return attributes

    @staticmethod
    def pattern_socket(pattern):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            p_value = p_value[1:-1]
            try:
                mapping = network_traffic_mapping[p_type]
            except KeyError:
                continue
            if "network-traffic:extensions.'socket-ext'.is_" in p_type:
                p_value = p_type.split('_')[1]
            attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                               'value': p_value})
        return attributes

    def pattern_url(self, pattern):
        return self.fill_pattern_attributes(pattern, url_mapping)

    def pattern_x509(self, pattern):
        return self.fill_pattern_attributes(pattern, x509_mapping)

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    def fill_observable_attributes(self, stix_object, object_mapping):
        attributes = []
        for o_key, o_value in stix_object.items():
            try:
                mapping = object_mapping[o_key]
                attributes.append({'type': mapping.get('type'), 'object_relation': mapping.get('relation'),
                                   'value': o_value, 'to_ids': False})
            except KeyError:
                if "x_misp_" in o_key:
                    attribute_type, relation = self.parse_custom_property(o_key)
                    if isinstance(o_value, list):
                        for v in o_value:
                            attributes.append({'type': attribute_type, 'object_relation': relation[:-1],
                                               'value': v, 'to_ids': False})
                    else:
                        attributes.append({'type': attribute_type, 'object_relation': relation[:-1],
                                           'value': o_value, 'to_ids': False})
        return attributes

    def fill_object_attributes_observable(self, misp_object, mapping_dict, stix_object):
        for stix_type, value in stix_object.items():
            try:
                mapping = mapping_dict[stix_type]
                misp_object.add_attribute(**{'type': mapping['type'], 'object_relation': mapping['relation'],
                                             'value': value, 'to_ids': False})
            except KeyError:
                if stix_type.startswith("x_misp_"):
                    attribute_type, relation = self.parse_custom_property(stix_type)
                    misp_object.add_attribute(**{'type': attribute_type, 'object_relation': relation[:-1],
                                                 'value': value, 'to_ids': False})

    def fill_pattern_attributes(self, pattern, object_mapping):
        attributes = []
        for p in pattern:
            p_type, p_value = p.split(' = ')
            try:
                mapping = object_mapping[p_type]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': p_value[1:-1], 'to_ids': True})
            except KeyError:
                if "x_misp_" in p_type:
                    attribute_type, relation = self.parse_custom_property(p_type)
                    attributes.append({'type': attribute_type, 'object_relation': relation[:-2],
                                       'value': p_value[1:-1], 'to_ids': True})
        return attributes

    @staticmethod
    def parse_custom_property(p_type):
        d_type = p_type.split("_")
        attribute_type = d_type[2]
        relation = "".join("{}-".format(t) for t in d_type[3:])
        return attribute_type, relation

    @staticmethod
    def parse_marking(marking):
        marking_type = marking.definition_type
        tag = getattr(marking.definition, marking_type)
        return "{}:{}".format(marking_type, tag)

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

    def parse_galaxies(self, galaxy_object):
        return self.parse_galaxy(galaxy_object, galaxy_object.get('labels'))


class ExternalStixParser(StixParser):
    def __init__(self):
        super(ExternalStixParser, self).__init__()
        self.object_from_refs = {'course-of-action': self.parse_course_of_action, 'vulnerability': self.parse_external_vulnerability,
                                 'indicator': self.parse_external_indicator, 'observed-data': self.parse_external_observable}
        self.observable_mapping = {('artifact', 'file'): self.parse_file_object_observable,
                                   ('autonomous-system',): self.parse_asn_observable,
                                   ('autonomous-system', 'ipv4-addr'): self.parse_asn_observable,
                                   ('autonomous-system', 'ipv6-addr'): self.parse_asn_observable,
                                   ('autonomous-system', 'ipv4-addr', 'ipv6-addr'): self.parse_asn_observable,
                                   ('domain-name',): self.parse_domain_ip_observable,
                                   ('domain-name', 'ipv4-addr'): self.parse_domain_ip_observable,
                                   ('domain-name', 'ipv6-addr'): self.parse_domain_ip_observable,
                                   ('domain-name', 'ipv4-addr', 'network-traffic'): self.parse_ip_port_or_network_socket_observable,
                                   ('domain-name', 'ipv6-addr', 'network-traffic'): self.parse_ip_port_or_network_socket_observable,
                                   ('domain-name', 'ipv4-addr', 'ipv6-addr', 'network-traffic'): self.parse_ip_port_or_network_socket_observable,
                                   ('domain-name', 'network-traffic'): self.parse_network_socket_observable,
                                   ('domain-name', 'network-traffic', 'url'): self.parse_url_object_observable,
                                   ('email-addr', 'email-message'): self.parse_email_observable,
                                   ('email-addr', 'email-message', 'file'): self.parse_email_observable,
                                   ('email-message',): self.parse_email_observable,
                                   ('file',): self.parse_file_observable,
                                   ('ipv4-addr',): self.parse_ip_address_observable,
                                   ('ipv6-addr',): self.parse_ip_address_observable,
                                   ('ipv4-addr', 'network-traffic'): self.parse_ip_network_traffic_observable,
                                   ('ipv6-addr', 'network-traffic'): self.parse_ip_network_traffic_observable,
                                   ('mac-addr',): self.parse_mac_address_observable,
                                   ('mutex',): self.parse_mutex_observable,
                                   ('process',): self.parse_process_observable,
                                   ('x509-certificate',): self.parse_x509_observable,
                                   ('url',): self.parse_url_observable,
                                   ('user-account',): self.parse_user_account_observable,
                                   ('windows-registry-key',): self.parse_regkey_observable}
        self.pattern_mapping = {('domain-name',): self.parse_domain_ip_port_pattern,
                                ('domain-name', 'ipv4-addr', 'url'): self.parse_domain_ip_port_pattern,
                                ('domain-name', 'ipv6-addr', 'url'): self.parse_domain_ip_port_pattern,
                                ('file',): self.parse_file_pattern,
                                ('ipv4-addr',): self.parse_ip_address_pattern,
                                ('ipv6-addr',): self.parse_ip_address_pattern,
                                ('network-traffic',): self.parse_network_traffic_pattern,
                                ('process',): self.parse_process_pattern,
                                ('url',): self.parse_url_pattern,
                                ('user-account',): self.parse_user_account_pattern,
                                ('windows-registry-key',): self.parse_regkey_pattern,
                                ('x509-certificate',): self.parse_x509_pattern}
        self.pattern_forbidden_relations = (' LIKE ', ' FOLLOWEDBY ', ' MATCHES ', ' ISSUBSET ', ' ISSUPERSET ', ' REPEATS ')

    def handler(self):
        self.version_attribute = {'type': 'text', 'object_relation': 'version', 'value': self.stix_version}
        self.general_handler()

    def parsing_process(self, object2parse, object_type):
        try:
            self.object_from_refs[object_type](object2parse)
        except KeyError:
            print("Unknown {} type: {}".format(self.stix_version, object_type), file=sys.stderr)

    def parse_external_galaxy(self, o):
        galaxy = {'name': galaxy_types[o._type].replace('-', ' ').title()}
        cluster = defaultdict(dict)
        cluster['value'] = o.name
        if  hasattr(o, 'description'):
            cluster['description'] = o.description
        if hasattr(o, 'kill_chain_name'):
            galaxy_type = o.kill_chain_phases[0].get('phase_name')
            galaxy['type'] = galaxy_type
            cluster['type'] = galaxy_type
        if hasattr(o, 'aliases'):
            aliases = []
            for a in o.get('aliases'):
                aliases.append(a)
            cluster['meta']['synonyms'] = aliases
        galaxy['GalaxyCluster'] = [cluster]
        return galaxy

    def parse_external_indicator(self, indicator):
        pattern = indicator.pattern
        # Deeper analyse of patterns coming when we get examples
        attribute = {'type': 'stix2-pattern', 'object_relation': 'stix2-pattern', 'value': pattern}
        misp_object = {'name': 'stix2-pattern', 'meta-category': 'stix2-pattern',
                       'Attribute': [self.version_attribute, attribute]}
        self.misp_event.add_object(**misp_object)
        indicator_id = indicator.id.split('--')[1]
        if hasattr(indicator, 'object_marking_refs'):
            self.parse_external_pattern(pattern, indicator_id, marking=indicator.object_marking_refs)
        else:
            self.parse_external_pattern(pattern, indicator_id)

    def parse_external_observable(self, observable):
        objects = observable.objects
        types = self.parse_external_observable_object(objects)
        try:
            to_call = self.observable_mapping[types]
            observable_id = observable.id.split('--')[1]
            if hasattr(observable, 'object_marking_refs'):
                to_call(objects, observable_id, marking=observable.object_marking_refs)
            else:
                to_call(objects, observable_id)
        except KeyError:
            print('{} not parsed at the moment'.format(types), file=sys.stderr)
        # deeper analyse to come, as well as for indicators

    @staticmethod
    def parse_external_observable_object(observable_objects):
        types = set()
        for _object in observable_objects.values():
            types.add(_object._type)
        return tuple(sorted(types))

    def parse_external_pattern(self, pattern, uuid, marking=None):
        if not any(relation in pattern for relation in self.pattern_forbidden_relations):
            pattern = pattern[1:-1]
            if ' OR ' in pattern and ' AND ' in pattern:
                return
            if ' OR ' in pattern:
                pattern = pattern.split(' OR ')
                for p in pattern:
                    type_ = tuple([p.split(' = ')[0].split(':')[0]])
                    try:
                        self.pattern_mapping[type_]([p.strip()], marking)
                    except KeyError:
                        print('{} not parsed at the moment'.format(type_), file=sys.stderr)
            else:
                pattern = [p.strip() for p in pattern.split(' AND ')]
                types = self.parse_external_pattern_types(pattern)
                try:
                    self.pattern_mapping[types](pattern, marking, uuid=uuid)
                except KeyError:
                    print('{} not parsed at the moment'.format(types), file=sys.stderr)

    @staticmethod
    def parse_external_pattern_types(pattern):
        types = set()
        for p in pattern:
            types.add(p.split('=')[0].split(':')[0])
        return tuple(sorted(types))

    def parse_external_vulnerability(self, o):
        attribute = {'type': 'vulnerability', 'value': o.get('name')}
        if 'description' in o:
            attribute['comment'] = o.get('description')
        if 'object_marking_refs' in o:
            attribute = self.add_tag_in_attribute(attribute, o['object_marking_refs'])
        self.misp_event.add_attribute(**attribute)

    @staticmethod
    def attributes_from_external_pattern(pattern):
        types = self.parse_external_pattern_types()
        pattern_type, pattern_value = pattern.split(' = ')
        pattern_type, pattern_value = pattern_type[1:].strip(), pattern_value[1:-2].strip()
        stix_type, value_type = pattern_type.split(':')
        if 'hashes' in value_type and 'x509' not in stix_type:
            h_type = value_type.split('.')[1].replace("'", '')
            return {'type': h_type, 'value': pattern_value}
        # Might cause some issues, need more examples to test
        return {'type': external_pattern_mapping[stix_type][value_type].get('type'), 'value': pattern_value}

    ################################################################################
    ##                             PARSING FUNCTIONS.                             ##
    ################################################################################

    def add_attributes_from_observable(self, objects, attribute_type, identifier, marking, uuid):
        attribute = {'to_ids': False}
        if len(objects) == 1:
            attribute['uuid'] = uuid
        if marking:
            attribute['type'] = attribute_type
            for observable in objects.values():
                attribute['value'] = getattr(observable, identifier)
                attribute = self.add_tag_in_attribute(attribute, marking)
                self.misp_event.add_attribute(**attribute)
        else:
            for observable in objects.values():
                self.misp_event.add_attribute(attribute_type, getattr(observable, identifier), **attribute)

    def add_attributes_from_pattern(self, attribute_type, pattern, marking, uuid):
        _, pattern_values = self.get_types_and_values_from_pattern(pattern)
        attribute = {'to_ids': True}
        if len(pattern_values) == 1 and uuid is not None:
            attribute['uuid'] = uuid
            attribute['value'] = pattern_values[0]
            attribute['type'] = attribute_type
            if marking:
                attribute = self.add_tag_in_attribute(attribute, marking)
            self.handle_single_attribute(attribute, uuid=uuid)
        else:
            if marking:
                attribute['type'] = attribute_type
                for value in pattern_values:
                    attribute['value'] = value
                    attribute = self.add_tag_in_attribute(attribute, marking)
                    self.misp_event.add_attribute(**attribute)
            else:
                for value in pattern_values:
                    self.misp_event.add_attribute(attribute_type, value, **attribute)

    @staticmethod
    def  attributes_from_dict(values, mapping_dict, to_ids):
        attributes = []
        for type_, value in values.items():
            try:
                mapping = mapping_dict[type_]
            except KeyError:
                continue
            attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                               'value': value, 'to_ids': to_ids})
        return attributes

    def handle_pe_case(self, extension, attributes, uuid):
        pe_uuid = self.parse_pe(extension)
        file_object = self.create_misp_object(attributes, 'file', uuid)
        file_object.add_reference(pe_uuid, 'includes')
        self.misp_event.add_object(**file_object)

    def parse_asn_observable(self, objects, marking, uuid):
        attributes = self.attributes_from_asn_observable(objects)
        self.handle_import_case(attributes, 'asn', marking, uuid)

    def parse_domain_ip_observable(self, objects, marking, uuid):
        attributes = self.attributes_from_domain_ip_observable(objects)
        self.handle_import_case(attributes, 'domain-ip', marking, uuid)

    def parse_domain_ip_port_pattern(self, pattern, marking=None, uuid=None):
        values = {}
        for p in pattern:
            type_, value = p.split('=')
            values[type_.strip().split(':')[0]] = value.strip().strip('\'')
        attributes = self.attributes_from_dict(values, domain_ip_mapping, True)
        self.handle_import_case(attributes, 'domain-ip', marking, uuid)

    def parse_email_observable(self, objects, marking, uuid):
        to_ids = False
        attributes, message = self.parse_complex_fields_observable_email(objects, to_ids)
        for m_key, m_value in message.items():
            if m_key in email_mapping:
                attributes.append(self.append_email_attribute(m_key, m_value, to_ids))
        self.handle_import_case(attributes, 'email', marking, uuid)

    def parse_file_observable(self, objects, marking, uuid):
        _object = objects['0']
        attributes = self.attributes_from_file_observable(_object)
        if hasattr(_object, 'extensions') and 'windows-pebinary-ext' in _object.extensions:
            self.handle_pe_case(_object.extensions['windows-pebinary-ext'], attributes, uuid)
        else:
            self.handle_import_case(attributes, _object._type, marking, uuid)

    def parse_file_pattern(self, pattern, marking=None, uuid=None):
        pattern_types, pattern_values = self.get_types_and_values_from_pattern(pattern)
        attributes = self.attributes_from_file_pattern(pattern_types, pattern_values)
        self.handle_import_case(attributes, 'file', marking, uuid)

    def parse_file_object_observable(self, objects, marking, uuid):
        file, data = self.extract_data_from_file(objects)
        attributes = self.attributes_from_file_observable(file, data)
        if hasattr(file, 'extensions') and 'windows-pebinary-ext' in file.extensions:
            self.handle_pe_case(file.extensions['windows-pebinary-ext'], attributes, uuid)
        else:
            self.handle_import_case(attributes, file._type, marking, uuid)

    def parse_ip_address_observable(self, objects, marking, uuid):
        self.add_attributes_from_observable(objects, 'ip-dst', 'value', marking, uuid)

    def parse_ip_address_pattern(self, pattern, marking=None, uuid=None):
        self.add_attributes_from_pattern('ip-dst', pattern, marking, uuid)

    def parse_ip_network_traffic_observable(self, objects, marking, uuid):
        attributes, name = self.attributes_from_network_traffic(objects)
        self.handle_import_case(attributes, name, marking, uuid)

    def parse_ip_port_or_network_socket_observable(self, objects, marking, uuid):
        attributes, name = self.attributes_from_network_traffic(objects)
        self.handle_import_case(attributes, name, marking, uuid)

    def parse_mac_address_observable(self, objects, marking, uuid):
        self.add_attributes_from_observable(objects, 'mac-address', 'value', marking, uuid)

    def parse_mutex_observable(self, objects, marking, uuid):
        self.add_attributes_from_observable(objects, 'mutex', 'name', marking, uuid)

    def parse_network_socket_observable(self, objects, marking, uuid):
        attributes, name = self.attributes_from_network_traffic(objects)
        self.handle_import_case(attributes, name, marking, uuid)

    def parse_network_traffic_pattern(self, pattern, marking=None, uuid=None):
        pattern_types, pattern_values = self.get_types_and_values_from_pattern(pattern)
        attributes = self.fill_pattern_attributes(pattern_types, pattern_values, network_traffic_mapping)
        self.handle_import_case(attributes, 'ip-port', marking, uuid)

    def parse_process_observable(self, objects, marking, uuid):
        attributes = self.attributes_from_process_observable(objects)
        self.handle_import_case(attributes, 'process', marking, uuid)

    def parse_process_pattern(self, pattern, marking=None, uuid=None):
        pattern_types, pattern_values = self.get_types_and_values_from_pattern(pattern)
        attributes = self.fill_pattern_attributes(pattern_types, pattern_values, process_mapping)
        self.handle_import_case(attributes, 'process', marking, uuid)

    def parse_regkey_observable(self, objects, marking, uuid):
        _object = objects['0']
        attributes = self.attributes_from_regkey_observable(_object)
        self.handle_import_case(attributes, 'registry-key', marking, uuid)

    def parse_regkey_pattern(self, pattern, marking=None, uuid=None):
        pattern_types, pattern_values = self.get_types_and_values_from_pattern(pattern)
        attributes = self.fill_pattern_attributes(pattern_types, pattern_values, regkey_mapping)
        self.handle_import_case(attributes, 'registry-key', marking, uuid)

    def parse_url_observable(self, objects, marking, uuid):
        self.add_attributes_from_observable(objects, 'url', 'value', marking, uuid)

    def parse_url_pattern(self, pattern, marking=None, uuid=None):
        self.add_attributes_from_pattern('url', pattern, marking, uuid)

    def parse_url_object_observable(self, objects, marking, uuid):
        attributes = self.attributes_from_url_observable(objects)
        self.handle_import_case(attributes, 'url', marking, uuid)

    def parse_user_account_observable(self, observable, marking, uuid):
        attributes = self.attributes_from_user_account_observable(observable)
        name = self.__define_user_account_name(attributes)
        self.handle_import_case(attributes, name, marking, uuid)

    def parse_user_account_pattern(self, pattern, marking, uuid):
        attributes = self.attributes_from_user_account_pattern(pattern)
        name = self.__define_user_account_name(attributes)
        self.handle_import_case(attributes, name, marking, uuid)

    def parse_x509_observable(self, objects, marking, uuid):
        attributes = self.attributes_from_x509_observable(objects)
        self.handle_import_case(attributes, 'x509', marking, uuid)

    def parse_x509_pattern(self, pattern, marking=None, uuid=None):
        pattern_types, attribute_types = self.get_types_and_values_from_pattern(pattern)
        attributes = self.fill_pattern_attributes(pattern_types, attribute_types, x509_mapping)
        self.handle_import_case(attributes, 'x509', marking, uuid)

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    @staticmethod
    def create_misp_object(attributes, name, uuid=None):
        misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
        if uuid is not None:
            misp_object.uuid = uuid
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return misp_object

    @staticmethod
    def __define_user_account_name(attributes):
        if len(attributes) == 2:
            relations = (attribute['type'] for attribute in attributes)
            if 'user_id' in relations and 'credential' in relations:
                return 'credential'
        return 'user-account'

    @staticmethod
    def fill_observable_attributes(stix_object, object_mapping):
        attributes = []
        for o_key, o_value in stix_object.items():
            if o_key in object_mapping:
                mapping = object_mapping[o_key]
                attributes.append({'type': mapping.get('type'), 'object_relation': mapping.get('relation'),
                                   'value': o_value, 'to_ids': False})
        return attributes

    def fill_object_attributes_observable(self, misp_object, mapping_dict, stix_object):
        for stix_type, value in stix_object.items():
            if stix_type in mapping_dict:
                mapping = mapping_dict[stix_type]
                misp_object.add_attribute(**{'type': mapping['type'], 'object_relation': mapping['relation'],
                                             'value': value, 'to_ids': False})

    @staticmethod
    def fill_pattern_attributes(types, values, object_mapping):
        attributes = []
        for type_, value in zip(types, values):
            try:
                mapping = object_mapping[type_]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'to_ids': True, 'value': value.replace('\\\\', '\\')})
            except KeyError:
                continue
        return attributes

    @staticmethod
    def get_types_and_values_from_pattern(pattern):
        types = []
        values = []
        for p in pattern:
            try:
                type_, value = p.split('=')
            except ValueError:
                type_, value = p.split(' = ')
            types.append(type_.strip())
            values.append(value.strip().strip('\''))
        return types, values

    def handle_import_case(self, attributes, name, marking=None, uuid=None):
        if len(attributes) == 1:
            attribute = attributes[0]
            attribute['uuid'] = uuid
            if marking:
                attribute = self.add_tag_in_attribute(attribute, marking)
            self.handle_single_attribute(attribute, uuid=uuid)
        else:
            self.object_case_import(attributes, name, uuid)

    def object_case_import(self, attributes, name, uuid):
        misp_object = self.create_misp_object(attributes, name, uuid)
        if uuid is not None and uuid in self.relationship:
            self.handle_object_relationship(misp_object, uuid)
        self.misp_event.add_object(**misp_object)

    def parse_galaxies(self, galaxy_object):
        return self.parse_external_galaxy(galaxy_object)

    @staticmethod
    def parse_marking(marking):
        marking_type = marking.definition_type
        if marking_type == 'tlp':
            return "{}:{}".format(marking_type, getattr(marking.definition, marking_type))


def from_misp(reports):
    for _, o in reports.items():
        if 'misp:tool="misp2stix2"' in o.get('labels'):
            return True
    return False

def main(args):
    stix_event = defaultdict(dict)
    stix_event['relationship'] = defaultdict(list)
    filename = os.path.join(os.path.dirname(args[0]), args[1])
    with open(filename, 'rt', encoding='utf-8') as f:
        event = stix2.parse(f.read(), allow_custom=True, interoperability=True)
    for parsed_object in event.objects:
        try:
            object_type = parsed_object._type
        except AttributeError:
            object_type = parsed_object['type']
        if object_type.startswith('x-misp-object'):
            object_type = 'x-misp-object'
        if object_type == 'relationship':
            stix_event[object_type][parsed_object.source_ref.split('--')[1]].append(parsed_object)
        else:
            uuid = parsed_object['id'].split('--')[1]
            if object_type in galaxy_types:
                parsed_object = {'object': parsed_object, 'used': False}
                object_type = 'galaxy'
            elif object_type == 'marking-definition':
                parsed_object = {'object': parsed_object, 'used': False}
                # object_type = object_type
            stix_event[object_type][uuid] = parsed_object
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
