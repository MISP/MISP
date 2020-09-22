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


import json
import os
import re
import sys
import uuid
import misp2stix2_mapping
from datetime import datetime
from stix2.base import STIXJSONEncoder
from stix2.exceptions import InvalidValueError, TLPMarkingDefinitionError, AtLeastOnePropertyError
from stix2.properties import DictionaryProperty, ListProperty, StringProperty, TimestampProperty
from stix2.v20.common import MarkingDefinition, TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from stix2.v20.observables import SocketExt, WindowsPESection, WindowsRegistryValueType
from stix2.v20.sdo import AttackPattern, CourseOfAction, CustomObject, Identity, Indicator, IntrusionSet, Malware, ObservedData, Report, ThreatActor, Tool, Vulnerability
from stix2.v20.sro import Relationship
from collections import defaultdict
from copy import deepcopy

_MISP_event_tags = ['Threat-Report', 'misp:tool="misp2stix2"']
_time_fields = {'indicator': ('valid_from', 'valid_until'),
                'observed-data': ('first_observed', 'last_observed')}

class StixBuilder():
    def __init__(self):
        self.orgs = []
        self.galaxies = []
        self.ids = {}
        self.custom_objects = {}

    def loadEvent(self, args):
        pathname = os.path.dirname(args[0])
        filename = os.path.join(pathname, args[1])
        with open(filename, 'rt', encoding='utf-8') as f:
            self.json_event = json.loads(f.read())
        self.filename = filename

    def buildEvent(self):
        try:
            stix_packages = [sdo for event in self.json_event['response'] for sdo in self.handler(event['Event'])] if self.json_event.get('response') else self.handler(self.json_event['Event'])
            outputfile = "{}.out".format(self.filename)
            with open(outputfile, 'wt', encoding='utf-8') as f:
                f.write(json.dumps(stix_packages, cls=STIXJSONEncoder))
            print(json.dumps({'success': 1}))
        except Exception as e:
            print(json.dumps({'error': e.__str__()}))

    def eventReport(self):
        if not self.object_refs and self.links:
            self.add_custom(self.links.pop(0))
        external_refs = [self.__parse_link(link) for link in self.links]
        report_args = {'type': 'report', 'id': self.report_id, 'name': self.misp_event['info'],
                       'created': datetime.strptime(self.misp_event['date'], '%Y-%m-%d'),
                       'published': self.get_datetime_from_timestamp(self.misp_event['publish_timestamp']),
                       'modified': self.get_datetime_from_timestamp(self.misp_event['timestamp']),
                       'created_by_ref': self.identity_id, 'interoperability': True}
        labels = [tag for tag in _MISP_event_tags]
        if self.misp_event.get('Tag'):
            markings = []
            for tag in self.misp_event['Tag']:
                name = tag['name']
                markings.append(name) if name.startswith('tlp:') else labels.append(name)
            if markings:
                report_args['object_marking_refs'] = self.handle_tags(markings)
        report_args['labels'] = labels
        if external_refs:
            report_args['external_references'] = external_refs
        self.add_all_markings()
        self.add_all_relationships()
        report_args['object_refs'] = self.object_refs
        return Report(**report_args)

    @staticmethod
    def __parse_link(link):
        url = link['value']
        source = "url"
        if link.get('comment'):
            source += " - {}".format(link['comment'])
        return {'source_name': source, 'url': url}

    def add_all_markings(self):
        for marking in self.markings.values():
            self.append_object(marking)

    def add_all_relationships(self):
        for source, targets in self.relationships['defined'].items():
            if source.startswith('report'):
                continue
            source_type,_ = source.split('--')
            for target in targets:
                target_type,_ = target.split('--')
                try:
                    relation = misp2stix2_mapping.relationshipsSpecifications[source_type][target_type]
                except KeyError:
                    # custom relationship (suggested by iglocska)
                    relation = "has"
                relationship = Relationship(source_ref=source, target_ref=target,
                                            relationship_type=relation, interoperability=True)
                self.append_object(relationship, id_mapping=False)
        for source_uuid, references in self.relationships['to_define'].items():
            for reference in references:
                target_uuid, relationship_type = reference
                try:
                    source = '{}--{}'.format(self.ids[source_uuid], source_uuid)
                    target = '{}--{}'.format(self.ids[target_uuid], target_uuid)
                except KeyError:
                    continue
                relationship = Relationship(source_ref=source, target_ref=target, interoperability=True,
                                            relationship_type=relationship_type.strip())
                self.append_object(relationship, id_mapping=False)

    def __set_identity(self):
        org = self.misp_event['Orgc']
        org_uuid = org['uuid']
        identity_id = 'identity--{}'.format(org_uuid)
        self.identity_id = identity_id
        if org_uuid not in self.orgs:
            identity = Identity(type="identity", id=identity_id, name=org["name"],
                                identity_class="organization", interoperability=True)
            self.SDOs.append(identity)
            self.orgs.append(org_uuid)
            return 1
        return 0

    def handler(self, event):
        self.misp_event = event
        self.report_id = "report--{}".format(self.misp_event['uuid'])
        self.SDOs = []
        self.object_refs = []
        self.links = []
        self.markings = {}
        self.relationships = {'defined': defaultdict(list),
                              'to_define': {}}
        i = self.__set_identity()
        if self.misp_event.get('Attribute'):
            for attribute in self.misp_event['Attribute']:
                a_type = attribute['type']
                to_call = self._get_function_to_call(a_type)
                getattr(self, to_call)(attribute)
        if self.misp_event.get('Object'):
            self.objects_to_parse = defaultdict(dict)
            for misp_object in self.misp_event['Object']:
                name = misp_object['name']
                if name == 'original-imported-file':
                    continue
                to_ids = self.fetch_ids_flag(misp_object['Attribute'])
                try:
                    getattr(self, misp2stix2_mapping.objectsMapping[name]['to_call'])(misp_object, to_ids)
                except KeyError:
                    self.add_object_custom(misp_object, to_ids)
                if misp_object.get('ObjectReference'):
                    self.relationships['to_define'][misp_object['uuid']] = tuple((r['referenced_uuid'], r['relationship_type']) for r in misp_object['ObjectReference'])
            if self.objects_to_parse:
                self.resolve_objects2parse()
        if self.misp_event.get('Galaxy'):
            for galaxy in self.misp_event['Galaxy']:
                self.parse_galaxy(galaxy, self.report_id)
        report = self.eventReport()
        self.SDOs.insert(i, report)
        return self.SDOs

    def get_object_by_uuid(self, uuid):
        for _object in self.misp_event['Object']:
            if _object.get('uuid') and _object['uuid'] == uuid:
                return _object
        raise Exception('Object with uuid {} does not exist in this event.'.format(uuid))

    def handle_person(self, attribute):
        if attribute['category'] == "Person":
            self.add_identity(attribute)
        else:
            self.add_custom(attribute)

    def handle_usual_type(self, attribute):
        try:
            if attribute['to_ids']:
                self.add_indicator(attribute)
            else:
                self.add_observed_data(attribute)
        except (AtLeastOnePropertyError, InvalidValueError):
            self.add_custom(attribute)

    def handle_usual_object_name(self, misp_object, to_ids):
        name = misp_object['name']
        if  name == 'file' and misp_object.get('ObjectReference'):
            for reference in misp_object['ObjectReference']:
                if reference['relationship_type'] in ('includes',  'included-in') and reference['Object']['name'] == "pe":
                    self.objects_to_parse[name][misp_object['uuid']] = to_ids, misp_object
                    return
        try:
            if to_ids or name == "stix2-pattern":
                self.add_object_indicator(misp_object)
            else:
                self.add_object_observable(misp_object)
        except Exception:
            self.add_object_custom(misp_object, to_ids)

    def handle_link(self, attribute):
        self.links.append(attribute)

    def populate_objects_to_parse(self, misp_object, to_ids):
        self.objects_to_parse[misp_object['name']][misp_object['uuid']] = to_ids, misp_object

    def resolve_objects2parse(self):
        for misp_object in self.objects_to_parse['file'].values():
            to_ids_file, file_object = misp_object
            file_id = "file--{}".format(file_object['uuid'])
            to_ids_list = [to_ids_file]
            for reference in file_object['ObjectReference']:
                if reference['relationship_type'] in ("includes", "included-in") and reference['Object']['name'] == "pe":
                    pe_uuid = reference['referenced_uuid']
                    break
            to_ids_pe, pe_object = self.objects_to_parse['pe'][pe_uuid]
            to_ids_list.append(to_ids_pe)
            sections = []
            for reference in pe_object['ObjectReference']:
                if reference['Object']['name'] == "pe-section" and reference['referenced_uuid'] in self.objects_to_parse['pe-section']:
                    to_ids_section, section_object = self.objects_to_parse['pe-section'][reference['referenced_uuid']]
                    to_ids_list.append(to_ids_section)
                    sections.append(section_object)
            if True in to_ids_list:
                patterns = self.resolve_file_pattern(file_object['Attribute'], file_id)
                patterns.extend(self.parse_pe_extensions_pattern(pe_object, sections))
                self.add_object_indicator(file_object, pattern_arg=f"[{' AND '.join(patterns)}]")
            else:
                observable = self.resolve_file_observable(file_object['Attribute'], file_id)
                key = '0' if len(observable) == 1 else self._fetch_file_observable(observable)
                pe_type = self._get_pe_type_from_filename(observable[key])
                observable[key]['extensions'] = self.parse_pe_extensions_observable(pe_object, sections, pe_type)
                self.add_object_observable(file_object, observable_arg=observable)

    @staticmethod
    def _create_pe_type_test(observable, extension):
        return [
            ('name' in observable and observable['name'].endswith(f'.{extension}')),
            ('mime_type' in observable and re.compile(".* .+{0}.+ .*|.* {0} .*".format(extension)).match(observable['mime_type'].lower()))]

    def _get_pe_type_from_filename(self, observable):
        for extension in ('exe', 'dll'):
            if any(self._create_pe_type_test(observable, extension)):
                return extension
        return 'sys'

    @staticmethod
    def _fetch_file_observable(observable_objects):
        for key, observable in observable_objects.items():
            if observable['type'] == 'file':
                return key
        return '0'

    def parse_pe_extensions_observable(self, pe_object, sections, pe_type):
        extension = defaultdict(list)
        extension['pe_type'] = pe_type
        for attribute in pe_object['Attribute']:
            try:
                extension[misp2stix2_mapping.peMapping[attribute['object_relation']]] = attribute['value']
            except KeyError:
                extension["x_misp_{}_{}".format(attribute['type'], attribute['object_relation'].replace('-', '_'))] = attribute['value']
        for section in sections:
            d_section = defaultdict(dict)
            for attribute in section['Attribute']:
                relation = attribute['object_relation']
                if relation in misp2stix2_mapping.misp_hash_types:
                    d_section['hashes'][relation] = attribute['value']
                else:
                    try:
                        d_section[misp2stix2_mapping.peSectionMapping[relation]] = attribute['value']
                    except KeyError:
                        continue
            if 'name' not in d_section:
                d_section['name'] = 'Section {}'.format(sections.index(section))
            extension['sections'].append(WindowsPESection(**d_section))
        if len(sections) != int(extension['number_of_sections']):
            extension['number_of_sections'] = str(len(sections))
        return {"windows-pebinary-ext": extension}

    def parse_pe_extensions_pattern(self, pe_object, sections):
        pattern = []
        mapping = misp2stix2_mapping.objectsMapping['file']['pattern']
        pe_mapping = "extensions.'windows-pebinary-ext'"
        for attribute in pe_object['Attribute']:
            try:
                stix_type = f"{pe_mapping}.{misp2stix2_mapping.peMapping[attribute['object_relation']]}"
            except KeyError:
                stix_type = f"{pe_mapping}.x_misp_{attribute['type']}_{attribute['object_relation'].replace('-', '_')}"
            pattern.append(mapping.format(stix_type, attribute['value']))
        n_section = 0
        for section in sections:
            section_mapping = f"{pe_mapping}.sections[{str(n_section)}]"
            for attribute in section['Attribute']:
                relation = attribute['object_relation']
                if relation in misp2stix2_mapping.misp_hash_types:
                    stix_type = "{}.hashes.'{}'".format(section_mapping, relation)
                    pattern.append(mapping.format(stix_type, attribute['value']))
                else:
                    try:
                        stix_type = "{}.{}".format(section_mapping, misp2stix2_mapping.peSectionMapping[relation])
                        pattern.append(mapping.format(stix_type, attribute['value']))
                    except KeyError:
                        continue
            n_section += 1
        return pattern

    def parse_galaxies(self, galaxies, source_id):
        for galaxy in galaxies:
            self.parse_galaxy(galaxy, source_id)

    def parse_galaxy(self, galaxy, source_id):
        galaxy_type = galaxy.get('type')
        galaxy_uuid = galaxy['GalaxyCluster'][0]['collection_uuid']
        try:
            stix_type, to_call = misp2stix2_mapping.galaxies_mapping[galaxy_type]
        except Exception:
            return
        if galaxy_uuid not in self.galaxies:
            getattr(self, to_call)(galaxy)
            self.galaxies.append(galaxy_uuid)
        self.relationships['defined'][source_id].append("{}--{}".format(stix_type, galaxy_uuid))

    def generate_galaxy_args(self, galaxy, b_killchain, b_alias, sdo_type):
        cluster = galaxy['GalaxyCluster'][0]
        try:
            cluster_uuid = cluster['collection_uuid']
        except KeyError:
            cluster_uuid = cluster['uuid']
        sdo_id = "{}--{}".format(sdo_type, cluster_uuid)
        description = "{} | {}".format(galaxy['description'], cluster['description'])
        labels = ['misp:name=\"{}\"'.format(galaxy['name'])]
        sdo_args = {
            'id': sdo_id,
            'type': sdo_type,
            'created': datetime.strptime(self.misp_event['date'], '%Y-%m-%d'),
            'modified': self.get_datetime_from_timestamp(self.misp_event['timestamp']),
            'name': cluster['value'],
            'description': description,
            'interoperability': True
        }
        if b_killchain:
            killchain = [{'kill_chain_name': 'misp-category',
                          'phase_name': galaxy['type']}]
            sdo_args['kill_chain_phases'] = killchain
        if cluster['tag_name']:
            labels.append(cluster.get('tag_name'))
        meta = cluster.get('meta')
        if 'synonyms' in meta and b_alias:
            aliases = []
            for a in meta['synonyms']:
                aliases.append(a)
            sdo_args['aliases'] = aliases
        sdo_args['labels'] = labels
        return sdo_args

    def add_attack_pattern(self, galaxy):
        a_p_args = self.generate_galaxy_args(galaxy, True, False, 'attack-pattern')
        a_p_args['created_by_ref'] = self.identity_id
        attack_pattern = AttackPattern(**a_p_args)
        self.append_object(attack_pattern)

    def add_attack_pattern_object(self, misp_object, to_ids):
        attack_pattern_args = {'id': f'attack-pattern--{misp_object["uuid"]}', 'type': 'attack-pattern',
                               'created_by_ref': self.identity_id, 'interoperability': True}
        attack_pattern_args.update(self.parse_attack_pattern_fields(misp_object['Attribute']))
        attack_pattern_args['labels'] = self.create_object_labels(misp_object['name'], misp_object['meta-category'], to_ids)
        attack_pattern = AttackPattern(**attack_pattern_args)
        self.append_object(attack_pattern)

    def add_course_of_action(self, misp_object):
        coa_args= self.generate_galaxy_args(misp_object, False, False, 'course-of-action')
        self.add_coa_stix_object(coa_args)

    def add_course_of_action_from_object(self, misp_object, to_ids):
        coa_id = 'course-of-action--{}'.format(misp_object['uuid'])
        coa_args = {'id': coa_id, 'type': 'course-of-action', 'created_by_ref': self.identity_id}
        coa_args['labels'] = self.create_object_labels(misp_object['name'], misp_object['meta-category'], to_ids)
        for attribute in misp_object['Attribute']:
            self.parse_galaxies(attribute['Galaxy'], coa_id)
            relation = attribute['object_relation']
            if relation in ('name', 'description'):
                coa_args[relation] = attribute['value']
            else:
                coa_args[f'x_misp_{attribute["type"]}_{relation}'] = attribute['value']
        if not 'name' in coa_args:
            return
        self.add_coa_stix_object(coa_args)

    def add_coa_stix_object(self, coa_args):
        coa_args['created_by_ref'] = self.identity_id
        course_of_action = CourseOfAction(**coa_args, allow_custom=True)
        self.append_object(course_of_action)

    def add_custom(self, attribute):
        attribute_type = attribute['type'].replace('|', '-').replace(' ', '-').lower()
        custom_object_id = "x-misp-object-{}--{}".format(attribute_type, attribute['uuid'])
        custom_object_type = "x-misp-object-{}".format(attribute_type)
        labels, markings = self.create_labels(attribute)
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(labels)
        stix_markings = ListProperty(StringProperty)
        timestamp = self.get_datetime_from_timestamp(attribute['timestamp'])
        custom_object_args = {'id': custom_object_id, 'x_misp_category': attribute['category'],
                              'created': timestamp, 'modified': timestamp, 'labels': labels,
                              'x_misp_value': attribute['value'], 'created_by_ref': self.identity_id}
        if attribute.get('comment'):
            custom_object_args['x_misp_comment'] = attribute['comment']
        if markings:
            markings = self.handle_tags(markings)
            custom_object_args['object_marking_refs'] = markings
            stix_markings.clean(markings)
        if custom_object_type not in self.custom_objects:
            @CustomObject(custom_object_type, [
                ('id', StringProperty(required=True)),
                ('labels', ListProperty(stix_labels, required=True)),
                ('x_misp_value', StringProperty(required=True)),
                ('created', TimestampProperty(required=True, precision='millisecond')),
                ('modified', TimestampProperty(required=True, precision='millisecond')),
                ('created_by_ref', StringProperty(required=True)),
                ('object_marking_refs', ListProperty(stix_markings)),
                ('x_misp_comment', StringProperty()),
                ('x_misp_category', StringProperty())
            ])
            class Custom(object):
                def __init__(self, **kwargs):
                    return
            self.custom_objects[custom_object_type] = Custom
        else:
            Custom = self.custom_objects[custom_object_type]
        custom_object = Custom(**custom_object_args)
        self.append_object(custom_object)

    def add_identity(self, attribute):
        identity_id = "identity--{}".format(attribute['uuid'])
        name = attribute['value']
        labels, markings = self.create_labels(attribute)
        identity_args = {'id': identity_id,  'type': 'identity', 'name': name, 'labels': labels,
                          'identity_class': 'individual', 'created_by_ref': self.identity_id,
                          'interoperability': True}
        if attribute.get('comment'):
            identity_args['description'] = attribute['comment']
        if markings:
            identity_args['object_marking_refs'] = self.handle_tags(markings)
        identity = Identity(**identity_args)
        self.append_object(identity)

    def add_indicator(self, attribute):
        indicator_id = "indicator--{}".format(attribute['uuid'])
        self.parse_galaxies(attribute['Galaxy'], indicator_id)
        category = attribute['category']
        killchain = self.create_killchain(category)
        labels, markings = self.create_labels(attribute)
        pattern = f'[{self.define_pattern(attribute)}]'
        timestamp = self.get_datetime_from_timestamp(attribute['timestamp'])
        indicator_args = {'id': indicator_id, 'type': 'indicator', 'labels': labels,
                          'kill_chain_phases': killchain, 'created_by_ref': self.identity_id,
                          'pattern': pattern, 'interoperability': True}
        indicator_args.update(self.handle_time_fields(attribute, timestamp, 'indicator'))
        if attribute.get('comment'):
            indicator_args['description'] = attribute['comment']
        if markings:
            indicator_args['object_marking_refs'] = self.handle_tags(markings)
        indicator = Indicator(**indicator_args)
        self.append_object(indicator)

    def add_intrusion_set(self, galaxy):
        i_s_args = self.generate_galaxy_args(galaxy, False, True, 'intrusion-set')
        i_s_args['created_by_ref'] = self.identity_id
        intrusion_set = IntrusionSet(**i_s_args)
        self.append_object(intrusion_set)

    def add_malware(self, galaxy):
        malware_args= self.generate_galaxy_args(galaxy, True, False, 'malware')
        malware_args['created_by_ref'] = self.identity_id
        malware = Malware(**malware_args)
        self.append_object(malware)

    def add_observed_data(self, attribute):
        observed_data_id = "observed-data--{}".format(attribute['uuid'])
        self.parse_galaxies(attribute['Galaxy'], observed_data_id)
        timestamp = self.get_datetime_from_timestamp(attribute['timestamp'])
        labels, markings = self.create_labels(attribute)
        observable = self.define_observable(attribute)
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data', 'number_observed': 1,
                              'objects': observable, 'created_by_ref': self.identity_id,
                              'labels': labels, 'interoperability': True}
        observed_data_args.update(self.handle_time_fields(attribute, timestamp, 'observed-data'))
        if markings:
            observed_data_args['object_marking_refs'] = self.handle_tags(markings)
        observed_data = ObservedData(**observed_data_args)
        self.append_object(observed_data)

    def add_threat_actor(self, galaxy):
        t_a_args = self.generate_galaxy_args(galaxy, False, True, 'threat-actor')
        t_a_args['created_by_ref'] = self.identity_id
        threat_actor = ThreatActor(**t_a_args)
        self.append_object(threat_actor)

    def add_tool(self, galaxy):
        tool_args = self.generate_galaxy_args(galaxy, True, False, 'tool')
        tool_args['created_by_ref'] = self.identity_id
        tool = Tool(**tool_args)
        self.append_object(tool)

    def add_vulnerability(self, attribute):
        vulnerability_id = "vulnerability--{}".format(attribute['uuid'])
        name = attribute['value']
        vulnerability_data = [self._get_vulnerability_data(name)]
        labels, markings = self.create_labels(attribute)
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'name': name, 'external_references': vulnerability_data,
                              'created_by_ref': self.identity_id, 'labels': labels,
                              'interoperability': True}
        if markings:
            vulnerability_args['object_marking_refs'] = self.handle_tags(markings)
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability)

    def add_vulnerability_from_galaxy(self, attribute):
        vulnerability_id = "vulnerability--{}".format(attribute['uuid'])
        cluster = attribute['GalaxyCluster'][0]
        name = cluster['value']
        vulnerability_names = [name]
        if cluster.get('meta') and cluster['meta'].get('aliases'):
            vulnerability_names.extend(cluster['meta']['aliases'])
        vulnerability_data = [self._get_vulnerability_data(name) for name in vulnerability_names]
        labels = ['misp:type=\"{}\"'.format(attribute.get('type'))]
        if cluster['tag_name']:
            labels.append(cluster['tag_name'])
        description = "{} | {}".format(attribute.get('description'), cluster.get('description'))
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'name': name, 'external_references': vulnerability_data,
                              'created_by_ref': self.identity_id, 'labels': labels,
                              'description': description, 'interoperability': True}
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability)

    def add_object_custom(self, misp_object, to_ids):
        name = misp_object['name'].replace('_', '-')
        custom_object_id = 'x-misp-object-{}--{}'.format(name, misp_object['uuid'])
        custom_object_type = 'x-misp-object-{}'.format(name)
        category = misp_object.get('meta-category')
        labels = [
            f'misp:type="{name}"',
            f'misp:category="{category}"',
            f'misp:to_ids="{to_ids}"',
            'from_object'
        ]
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(labels)
        values = self.fetch_custom_values(misp_object['Attribute'], custom_object_id)
        timestamp = self.get_datetime_from_timestamp(misp_object['timestamp'])
        custom_object_args = {'id': custom_object_id, 'x_misp_values': values,
                              'created': timestamp, 'modified': timestamp, 'labels': labels,
                              'x_misp_category': category, 'created_by_ref': self.identity_id}
        if hasattr(misp_object, 'comment') and misp_object.get('comment'):
            custom_object_args['x_misp_comment'] = misp_object['comment']
        if custom_object_type not in self.custom_objects:
            @CustomObject(custom_object_type, [
                ('id', StringProperty(required=True)),
                ('labels', ListProperty(stix_labels, required=True)),
                ('x_misp_values', DictionaryProperty(required=True)),
                ('created', TimestampProperty(required=True, precision='millisecond')),
                ('modified', TimestampProperty(required=True, precision='millisecond')),
                ('created_by_ref', StringProperty(required=True)),
                ('x_misp_comment', StringProperty()),
                ('x_misp_category', StringProperty())
            ])
            class Custom(object):
                def __init__(self, **kwargs):
                    return
            self.custom_objects[custom_object_type] = Custom
        else:
            Custom = self.custom_objects[custom_object_type]
        custom_object = Custom(**custom_object_args)
        self.append_object(custom_object)

    def add_object_indicator(self, misp_object, pattern_arg=None):
        indicator_id = 'indicator--{}'.format(misp_object['uuid'])
        if pattern_arg:
            name = 'WindowsPEBinaryFile'
            pattern = pattern_arg
        else:
            name = misp_object['name']
            pattern = f"[{' AND '.join(getattr(self, misp2stix2_mapping.objects_mapping[name]['pattern'])(misp_object['Attribute'], indicator_id))}]"
        category = misp_object.get('meta-category')
        killchain = self.create_killchain(category)
        labels = self.create_object_labels(name, category, True)
        timestamp = self.get_datetime_from_timestamp(misp_object['timestamp'])
        indicator_args = {'id': indicator_id, 'type': 'indicator',
                          'labels': labels, 'pattern': pattern,
                          'description': misp_object['description'], 'allow_custom': True,
                          'kill_chain_phases': killchain, 'interoperability': True,
                          'created_by_ref': self.identity_id}
        indicator_args.update(self.handle_time_fields(misp_object, timestamp, 'indicator'))
        indicator = Indicator(**indicator_args)
        self.append_object(indicator)

    def add_object_observable(self, misp_object, observable_arg=None):
        observed_data_id = 'observed-data--{}'.format(misp_object['uuid'])
        if observable_arg:
            name = 'WindowsPEBinaryFile'
            observable_objects = observable_arg
        else:
            name = misp_object['name']
            observable_objects = getattr(self, misp2stix2_mapping.objects_mapping[name]['observable'])(misp_object['Attribute'], observed_data_id)
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, False)
        timestamp = self.get_datetime_from_timestamp(misp_object['timestamp'])
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data', 'labels': labels,
                              'number_observed': 1, 'objects': observable_objects, 'allow_custom': True,
                              'created_by_ref': self.identity_id, 'interoperability': True}
        observed_data_args.update(self.handle_time_fields(misp_object, timestamp, 'observed-data'))
        try:
            observed_data = ObservedData(**observed_data_args)
        except InvalidValueError:
            observed_data = self.fix_enumeration_issues(name, observed_data_args)
        self.append_object(observed_data)

    @staticmethod
    def fix_enumeration_issues(name, args):
        if name == 'network-socket':
            socket_args = deepcopy(args)
            n = None
            for index, observable_object in socket_args['objects'].items():
                if observable_object['type'] == 'network-traffic':
                    n = index
                    break
            if n is not None:
                extension = socket_args['objects'][n]['extensions']['socket-ext']
                feature = 'address_family'
                if feature not in extension:
                    extension[feature] = 'AF_UNSPEC'
                elif extension[feature] not in SocketExt._properties[feature].allowed:
                    extension[f'x_misp_text_{feature}'] = extension[feature]
                    extension[feature] = 'AF_UNSPEC'
                feature = 'protocol_family'
                if feature in extension and extension[feature] not in SocketExt._properties[feature].allowed:
                    extension['x_misp_text_domain_family'] = extension.pop(feature)
            return ObservedData(**socket_args)
            # If there is still an issue at this point, well at least we tried to fix it
        return ObservedData(**args)

    def add_object_vulnerability(self, misp_object, to_ids):
        vulnerability_id = 'vulnerability--{}'.format(misp_object['uuid'])
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'created_by_ref': self.identity_id, 'interoperability': True}
        vulnerability_args.update(self.parse_vulnerability_fields(misp_object['Attribute']))
        vulnerability_args['labels'] = self.create_object_labels(misp_object['name'], misp_object['meta-category'], to_ids)
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability)

    def append_object(self, stix_object, id_mapping=True):
        self.SDOs.append(stix_object)
        self.object_refs.append(stix_object.id)
        if id_mapping:
            object_type, uuid = stix_object.id.split('--')
            self.ids[uuid] = object_type

    @staticmethod
    def create_killchain(category):
        return [{'kill_chain_name': 'misp-category', 'phase_name': category}]

    @staticmethod
    def create_labels(attribute):
        labels = [f'misp:{feature}="{attribute[feature]}"' for feature in ('type', 'category', 'to_ids')]
        markings = []
        if attribute.get('Tag'):
            for tag in attribute['Tag']:
                name = tag['name']
                markings.append(name) if name.startswith('tlp:') else labels.append(name)
        return labels, markings

    @staticmethod
    def create_object_labels(name, category, to_ids):
        return [
            f'misp:type="{name}"',
            f'misp:category="{category}"',
            f'misp:to_ids="{to_ids}"',
            'from_object'
        ]

    def create_marking(self, tag):
        if tag in misp2stix2_mapping.tlp_markings:
            marking_definition = globals()[misp2stix2_mapping.tlp_markings[tag]]
            self.markings[tag] = marking_definition
            return marking_definition.id
        marking_id = 'marking-definition--%s' % uuid.uuid4()
        definition_type, definition = tag.split(':')
        marking_definition = {'type': 'marking-definition', 'id': marking_id, 'definition_type': definition_type,
                              'definition': {definition_type: definition}}
        try:
            self.markings[tag] = MarkingDefinition(**marking_definition)
        except (TLPMarkingDefinitionError, ValueError):
            return
        return marking_id

    @staticmethod
    def _parse_tag(namespace, predicate):
        if '=' not in predicate:
            return "{} = {}".format(namespace, predicate)
        predicate, value = predicate.split('=')
        return "({}) {} = {}".format(namespace, predicate, value.strip('"'))

    def define_observable(self, attribute):
        attribute_type = attribute['type']
        attribute_value = attribute['value']
        args = self._get_attribute_arguments(attribute)
        observable = getattr(self, misp2stix2_mapping.mispTypesMapping[attribute_type]['observable'])(*args)
        if attribute_type == 'port':
            observable['0']['protocols'].append(misp2stix2_mapping.defineProtocols[attribute_value] if attribute_value in misp2stix2_mapping.defineProtocols else "tcp")
        return observable

    def define_pattern(self, attribute):
        attribute_value = attribute['value']
        if isinstance(attribute_value, str):
            attribute['value'] = attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')
        args = self._get_attribute_arguments(attribute)
        return getattr(self, misp2stix2_mapping.mispTypesMapping[attribute['type']]['pattern'])(*args)

    def fetch_custom_values(self, attributes, object_id):
        values = defaultdict(list)
        for attribute in attributes:
            try:
                self.parse_galaxies(attribute['Galaxy'], object_id)
            except KeyError:
                pass
            attribute_type = '{}_{}'.format(attribute['type'], attribute['object_relation'].replace('.', '_DOT_'))
            values[attribute_type].append(attribute['value'])
        return {attribute_type: value[0] if len(value) == 1 else value for attribute_type, value in values.items()}

    @staticmethod
    def fetch_ids_flag(attributes):
        for attribute in attributes:
            if attribute['to_ids']:
                return True
        return False

    def handle_tags(self, tags):
        marking_ids = []
        for tag in tags:
            marking_id = self.markings[tag]['id'] if tag in self.markings else self.create_marking(tag)
            if marking_id:
                marking_ids.append(marking_id)
        return marking_ids

    ################################################################################
    ##                     MISP ATTRIBUTES PARSING FUNCTIONS.                     ##
    ################################################################################

    @staticmethod
    def _get_artifact_observable(data):
        return {'type': 'artifact', 'payload_bin': data}

    @staticmethod
    def _get_artifact_pattern(data):
        return f"file:content_ref.payload_bin = '{data}'"

    def _get_as_observable(self, _, attribute_value):
        stix_type = 'number'
        return {'0': {'type': 'autonomous-system', stix_type: self._parse_as_attribute(stix_type, attribute_value)}}

    def _get_as_pattern(self, _, attribute_value):
        stix_type = 'number'
        return f"autonomous-system:{stix_type} = '{self._parse_as_attribute(stix_type, attribute_value)}'"

    def _get_attachment_observable(self, _, attribute_value, data=None):
        observable = self._get_file_observable(_, attribute_value)
        if data is not None:
            observable['0']['content_ref'] = '0'
            return {'0': self._get_artifact_observable(data), '1': observable['0']}
        return observable

    def _get_attachment_pattern(self, _, attribute_value, data=None):
        pattern = self._get_file_pattern(_, attribute_value)
        if data is not None:
            pattern = f'{pattern} AND {self._get_artifact_pattern(data)}'
        return pattern

    def _get_domain_ip_observable(self, _, attribute_value):
        domain_value, ip_value = attribute_value.split('|')
        address_type = self._define_address_type(ip_value)
        observable = self._get_domain_observable(None, domain_value)
        observable['0']['resolves_to_refs'] = ['1']
        observable['1'] = {'type': address_type, 'value': ip_value}
        return observable

    def _get_domain_ip_pattern(self, _, attribute_value):
        domain_value, ip_value = attribute_value.split('|')
        return f"{self._get_domain_pattern(None, domain_value)} AND domain-name:resolves_to_refs[*].value = '{ip_value}'"

    @staticmethod
    def _get_domain_observable(_, attribute_value):
        return {'0': {'type': 'domain-name', 'value': attribute_value}}

    @staticmethod
    def _get_domain_pattern(_, attribute_value):
        return f"domain-name:value = '{attribute_value}'"

    @staticmethod
    def _get_email_address_observable(attribute_type, attribute_value):
        observable = {
            '0': {
                'type': 'email-addr',
                'value': attribute_value
            },
            '1': {
                'type': 'email-message',
                'is_multipart': 'false'
            }
        }
        if 'src' in attribute_type:
            observable['1']['from_ref'] = '0'
        else:
            observable['1']['to_refs'] = ['0']
        return observable

    @staticmethod
    def _get_email_address_pattern(attribute_type, attribute_value):
        email_type = 'from_ref' if 'src' in attribute_type else 'to_refs[*]'
        return f"email-message:{email_type}.value = '{attribute_value}'"

    def _get_email_attachment_observable(self, _, attribute_value):
        observable = self._get_file_observable(None, attribute_value)
        observable[1] = {
            'type': 'email-message',
            'is_multipart': 'false',
            'body_multipart': [{
                'content_disposition': f"attachment; filename='{attribute_value}'",
                'body_raw_ref': '0'
            }]
        }
        return observable

    @staticmethod
    def _get_email_attachment_pattern(_, attribute_value):
        return f"email-message:body_multipart[*].body_raw_ref.name = '{attribute_value}'"

    @staticmethod
    def _get_email_message_observable(attribute_type, attribute_value):
        email_type = attribute_type.split('-')[1]
        observable = {
            '0': {
                'type': 'email-message',
                email_type: attribute_value,
                'is_multipart': 'false'
            }
        }
        return observable

    @staticmethod
    def _get_email_message_pattern(attribute_type, attribute_value):
        email_type = attribute_type.split('-')[1]
        return f"email-message:{email_type} = '{attribute_value}'"

    @staticmethod
    def _get_file_observable(_, attribute_value):
        return {'0': {'type': 'file', 'name': attribute_value}}

    @staticmethod
    def _get_file_pattern(_, attribute_value):
        return f"file:name = '{attribute_value}'"

    def _get_file_hash_observable(self, attribute_type, attribute_value):
        filename, hash_type, hash_value = self._split_composite_attribute(attribute_type, attribute_value, 1)
        return {'0': {'type': 'file', 'name': filename, 'hashes': {hash_type: hash_value}}}

    def _get_file_hash_pattern(self, attribute_type, attribute_value):
        filename, hash_type, hash_value = self._split_composite_attribute(attribute_type, attribute_value, 1)
        return f'{self._get_file_pattern(None, filename)} AND {self._get_hash_pattern(hash_type, hash_value)}'

    @staticmethod
    def _get_hash_observable(attribute_type, attribute_value):
        return {'0': {'type': 'file', 'hashes': {attribute_type: attribute_value}}}

    @staticmethod
    def _get_hash_pattern(attribute_type, attribute_value):
        return f"file:hashes.'{attribute_type}' = '{attribute_value}'"

    def _get_hostname_port_observable(self, _, attribute_value):
        hostname_value, port_value = attribute_value.split('|')
        observable = self._get_domain_observable(None, hostname_value)
        observable['1'] = self._get_port_observable(None, port_value)[0]
        return observable

    def _get_hostname_port_pattern(self, _, attribute_value):
        hostname_value, port_value = attribute_value.split('|')
        return f'{self._get_domain_pattern(None, hostname_value)} AND {self._get_port_pattern(None, port_value)}'

    def _get_ip_observable(self, attribute_type, attribute_value):
        address_type = self._define_address_type(attribute_value)
        observable = {
            '0': {
                'type': address_type,
                'value': attribute_value
            },
            '1': {
                'type': 'network-traffic',
                f'{attribute_type.split("-")[1]}_ref': '0',
                'protocols': [address_type.split('-')[0]]
            }
        }
        return observable

    def _get_ip_pattern(self, attribute_type, attribute_value):
        ip_type = attribute_type.split('-')[1]
        address_type = self._define_address_type(attribute_value)
        return f"network-traffic:{ip_type}_ref.type = '{address_type}' AND network-traffic:{ip_type}_ref.value = '{attribute_value}'"

    def _get_ip_port_observable(self, attribute_type, attribute_value):
        ip_value, ip_type, port_value = self._split_composite_attribute(attribute_type, attribute_value, 0)
        observable = self._get_ip_observable(ip_type, ip_value)
        observable['1'][f'{ip_type.split("-")[1]}_port'] = port_value
        return observable

    def _get_ip_port_pattern(self, attribute_type, attribute_value):
        ip_value, ip_type, port_value = self._split_composite_attribute(attribute_type, attribute_value, 0)
        port_type = f'{ip_type.split("-")[1]}_port'
        return f"network-traffic:{port_type} = '{port_value}' AND {self._get_ip_pattern(ip_type, ip_value)}"

    @staticmethod
    def _get_mac_address_observable(_, attribute_value):
        return {'0': {'type': 'mac-addr', 'value': attribute_value.lower()}}

    @staticmethod
    def _get_mac_address_pattern(_, attribute_value):
        return f"mac-addr:value = '{attribute_value.lower()}'"

    def _get_malware_sample_observable(self, _, attribute_value, data=None):
        observable = self._get_file_hash_observable('filename|md5', attribute_value)
        if data is not None:
            observable['0']['content_ref'] = '0'
            return {'0': self._get_artifact_observable(data), '1': observable['0']}
        return observable

    def _get_malware_sample_pattern(self, _, attribute_value, data=None):
        pattern = self._get_file_hash_pattern('filename|md5', attribute_value)
        if data is not None:
            pattern = f'{pattern} AND {self._get_artifact_pattern(data)}'
        return pattern

    @staticmethod
    def _get_mutex_observable(_, attribute_value):
        return {'0': {'type': 'mutex', 'name': attribute_value}}

    @staticmethod
    def _get_mutex_pattern(_, attribute_value):
        return f"mutex:name = '{attribute_value}'"

    # Usually broken and replaced by a custom object, because the network-traffic
    # object requires the protocols fields, and either a src or dst ref
    @staticmethod
    def _get_port_observable(_, attribute_value):
        return {'0': {'type': 'network-traffic', 'dst_port': attribute_value, 'protocols': []}}

    @staticmethod
    def _get_port_pattern(_, attribute_value):
        return f"network-traffic:dst_port = '{attribute_value}'"

    @staticmethod
    def _get_regkey_observable(_, attribute_value):
        return {'0': {'type': 'windows-registry-key', 'key': attribute_value.strip()}}

    @staticmethod
    def _get_regkey_pattern(_, attribute_value):
        if '\\\\' not in attribute_value:
            attribute_value = attribute_value.replace('\\', '\\\\')
        return f"windows-registry-key:key = '{attribute_value.strip()}'"

    def _get_regkey_value_observable(self, _, attribute_value):
        regkey, value = attribute_value.split('|')
        observable = self._get_regkey_observable(None, regkey)
        observable['0']['values'] = WindowsRegistryValueType(**{'data': value.strip(), 'name': ''})
        return observable

    def _get_regkey_value_pattern(self, _, attribute_value):
        if '\\\\' not in attribute_value:
            attribute_value = attribute_value.replace('\\', '\\\\')
        regkey, value = attribute_value.split('|')
        return f"{self._get_regkey_pattern(None, regkey)} AND windows-registry-key:values.data = '{value.strip()}'"

    @staticmethod
    def _get_reply_to_observable(_, attribute_value):
        observable = {
            '0': {
                'type': 'email-message',
                'is_multipart': 'false',
                'additional_header_fields': {
                    'Reply-To': attribute_value
                }
            }
        }
        return observable

    @staticmethod
    def _get_reply_to_pattern(_, attribute_value):
        return f"email-message:additional_header_fields.reply_to = '{attribute_value}'"

    @staticmethod
    def _get_url_observable(_, attribute_value):
        return {'0': {'type': 'url', 'value': attribute_value}}

    @staticmethod
    def _get_url_pattern(_, attribute_value):
        return f"url:value = '{attribute_value}'"

    @staticmethod
    def _get_vulnerability_data(vulnerability_name):
        return {'source_name': 'cve', 'external_id': vulnerability_name}

    @staticmethod
    def _get_x509_observable(attribute_type, attribute_value):
        hash_type = attribute_type.split('-')[-1]
        return {'0': {'type': 'x509-certificate', 'hashes': {hash_type: attribute_value}}}

    @staticmethod
    def _get_x509_pattern(attribute_type, attribute_value):
        hash_type = attribute_type.split('-')[-1]
        return f"x509-certificate:hashes.'{hash_type}' = '{attribute_value}'"

    @staticmethod
    def _split_composite_attribute(attribute_type, attribute_value, index):
        value1, value2 = attribute_value.split('|')
        return value1, attribute_type.split('|')[index], value2

    ################################################################################
    ##                       MISP OBJECTS PARSING FUNCTIONS                       ##
    ################################################################################

    def parse_attack_pattern_fields(self, attributes):
        attack_pattern = {}
        weaknesses = []
        references = []
        for attribute in attributes:
            relation = attribute['object_relation']
            if relation in misp2stix2_mapping.attackPatternObjectMapping:
                attack_pattern[misp2stix2_mapping.attackPatternObjectMapping[relation]] = attribute['value']
            else:
                if relation in ('id', 'references'):
                    references.append(self._parse_attack_pattern_reference(attribute))
                elif relation == 'related-weakness':
                    weaknesses.append(attribute['value'])
                else:
                    attack_pattern[f"x_misp_{attribute['type']}_{relation.replace('-', '_')}"] = attribute['value']
                    attack_pattern['allow_custom'] = True
        if references:
            attack_pattern['external_references'] = references
        if weaknesses:
            attack_pattern['x_misp_weakness_related_weakness'] = weaknesses[0] if len(weaknesses) == 1 else weaknesses
        return attack_pattern

    @staticmethod
    def _parse_attack_pattern_reference(attribute):
        object_relation = attribute['object_relation']
        source_name, key = misp2stix2_mapping.attack_pattern_reference_mapping[object_relation]
        value = attribute['value']
        if object_relation == 'id' and 'CAPEC' not in value:
            value = f'CAPEC-{value}'
        return {'source_name': source_name, key: value}

    @staticmethod
    def parse_vulnerability_fields(attributes):
        vulnerability = {}
        references = []
        custom_args = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            if relation in misp2stix2_mapping.vulnerabilityMapping:
                vulnerability[misp2stix2_mapping.vulnerabilityMapping[relation]] = attribute['value']
            else:
                if relation == 'references':
                    references.append({'source_name': 'url', 'url': attribute['value']})
                else:
                    custom_args[f"x_misp_{attribute['type']}_{relation.replace('-', '_')}"].append(attribute['value'])
                    vulnerability['allow_custom'] = True
        if 'name' in vulnerability:
            references.append({'source_name': 'cve', 'external_id': vulnerability['name']})
        if references:
            vulnerability['external_references'] = references
        if custom_args:
            vulnerability.update({key: value[0] if len(value) == 1 else value for key, value in custom_args.items()})
        return vulnerability

    def resolve_asn_observable(self, attributes, object_id):
        asn = misp2stix2_mapping.objectsMapping['asn']['observable']
        observable = {}
        object_num = 0
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = misp2stix2_mapping.asnObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            attribute_value = attribute['value']
            if relation == "subnet-announced":
                observable[str(object_num)] = {'type': self._define_address_type(attribute_value), 'value': attribute_value}
                object_num += 1
            else:
                asn[stix_type] = self._parse_as_attribute(stix_type, attribute_value)
        observable[str(object_num)] = asn
        for n in range(object_num):
            observable[str(n)]['belongs_to_refs'] = [str(object_num)]
        return observable

    def resolve_asn_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['asn']['pattern']
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = misp2stix2_mapping.asnObjectMapping[relation]
            except KeyError:
                stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
            attribute_value = attribute['value']
            if relation == "subnet-announced":
                pattern.append("{0}:{1} = '{2}'".format(self._define_address_type(attribute_value), stix_type, attribute_value))
            else:
                pattern.append(mapping.format(stix_type, attribute_value))
        return pattern

    def resolve_credential_observable(self, attributes, object_id):
        user_account = misp2stix2_mapping.objectsMapping['credential']['observable']
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = misp2stix2_mapping.credentialObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            user_account[stix_type] = attribute['value']
        return {'0': user_account}

    def resolve_credential_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['credential']['pattern']
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = misp2stix2_mapping.credentialObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            pattern.append(mapping.format(stix_type, attribute['value']))
        return pattern

    def resolve_domain_ip_observable(self, attributes, object_id):
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            if attribute['type'] == 'ip-dst':
                ip_value = attribute['value']
            elif attribute['type'] == 'domain':
                domain_value = attribute['value']
        domain_ip_value = "{}|{}".format(domain_value, ip_value)
        return getattr(self, misp2stix2_mapping.mispTypesMapping['domain|ip']['observable'])(None, domain_ip_value)

    def resolve_domain_ip_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['domain-ip']['pattern']
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            try:
                stix_type = misp2stix2_mapping.domainIpObjectMapping[attribute['type']]
            except KeyError:
                continue
            pattern.append(mapping.format(stix_type, attribute['value']))
        return pattern

    def resolve_email_object_observable(self, attributes, object_id):
        observable = {}
        message = defaultdict(list)
        additional_header = {}
        object_num = 0
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            attribute_value = attribute['value']
            try:
                mapping = misp2stix2_mapping.emailObjectMapping[relation]['stix_type']
                if relation in ('from', 'to', 'cc'):
                    object_str = str(object_num)
                    observable[object_str] = {'type': 'email-addr', 'value': attribute_value}
                    if relation == 'from':
                        message[mapping] = object_str
                    else:
                        message[mapping].append(object_str)
                    object_num += 1
                elif relation in ('attachment', 'screenshot'):
                    object_str = str(object_num)
                    body = {"content_disposition": "{}; filename='{}'".format(relation, attribute_value),
                            "body_raw_ref": object_str}
                    message['body_multipart'].append(body)
                    observable[object_str] = {'type': 'artifact', 'payload_bin': attribute['data']} if 'data' in attribute and attribute['data'] else {'type': 'file', 'name': attribute_value}
                    object_num += 1
                elif relation in ('x-mailer', 'reply-to'):
                    key = '-'.join([part.capitalize() for part in relation.split('-')])
                    additional_header[key] = attribute_value
                else:
                    message[mapping] = attribute_value
            except Exception:
                mapping = "x_misp_{}_{}".format(attribute['type'], relation)
                message[mapping] = {'value': attribute_value, 'data': attribute['data']} if relation == 'eml' else attribute_value
        if additional_header:
            message['additional_header_fields'] = additional_header
        message['type'] = 'email-message'
        if 'body_multipart' in message and len(message['body_multipart']) > 1:
            message['is_multipart'] = True
        else:
            message['is_multipart'] = False
        observable[str(object_num)] = dict(message)
        return observable

    def resolve_email_object_pattern(self, attributes, object_id):
        pattern_mapping = misp2stix2_mapping.objectsMapping['email']['pattern']
        pattern = []
        n = 0
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                mapping = misp2stix2_mapping.emailObjectMapping[relation]
                email_type = mapping['email_type']
                if relation in ('attachment', 'screenshot'):
                    stix_type = mapping['stix_type'].format(n)
                    if 'data' in attribute and attribute['data']:
                        pattern.append(pattern_mapping.format(email_type, 'body_multipart[{}].body_raw_ref.payload_bin'.format(n), attribute['data']))
                    n += 1
                else:
                    stix_type = self._parse_email_stix_type(relation, mapping['stix_type'])
            except KeyError:
                email_type = 'message'
                stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
                if relation == 'eml':
                    stix_type_data = "{}.data".format(stix_type)
                    pattern.append(pattern_mapping.format(email_type, stix_type_data, attribute['data']))
                    stix_type += ".value"
            pattern.append(pattern_mapping.format(email_type, stix_type, attribute['value']))
        return pattern

    def resolve_file_observable(self, attributes, object_id):
        observable = {}
        file_observable = defaultdict(dict)
        file_observable['type'] = 'file'
        n_object = 0
        attributes_dict = self.create_file_attributes_dict(attributes, object_id)
        for key, feature in misp2stix2_mapping.fileMapping.items():
            if key in attributes_dict:
                if key in misp2stix2_mapping.hash_types:
                    file_observable['hashes'][feature] = attributes_dict[key]
                else:
                    file_observable[feature] = attributes_dict[key]
        if 'filename' in attributes_dict:
            file_observable['name'] = attributes_dict['filename'][0]
            if len(attributes_dict['filename']) > 1:
                self._handle_multiple_file_fields_observable(file_observable, attributes_dict['filename'][1:], 'filename')
        if 'path' in attributes_dict:
            observable[str(n_object)] = {'type': 'directory', 'path': attributes_dict['path'][0]}
            file_observable['parent_directory_ref'] = str(n_object)
            n_object += 1
            if len(attributes_dict['path']) > 1:
                self._handle_multiple_file_fields_observable(file_observable, attributes_dict['path'][1:], 'path')
        if 'fullpath' in attributes_dict:
            if 'parent_directory_ref' not in file_observable:
                observable[str(n_object)] = {'type': 'directory', 'path': attributes_dict['fullpath'][0]}
                file_observable['parent_directory_ref'] = str(n_object)
                n_object += 1
                if len(attributes_dict['path']) > 1:
                    self._handle_multiple_file_fields_observable(file_observable, attributes_dict['fullpath'][1:], 'fullpath')
            else:
                self._handle_multiple_file_fields_observable(file_observable, attributes_dict['fullpath'], 'fullpath')
        if 'malware-sample' in attributes_dict:
            artifact, value = self._create_artifact_observable(attributes_dict['malware-sample'])
            filename, md5 = value.split('|')
            artifact['name'] = filename
            artifact['hashes'] = {'MD5': md5}
            observable[str(n_object)] = artifact
            file_observable['content_ref'] = str(n_object)
            n_object += 1
        if 'attachment' in attributes_dict:
            artifact, value = self._create_artifact_observable(attributes_dict['attachment'])
            artifact['name'] = value
            observable[str(n_object)] = artifact
            n_object += 1
        observable[str(n_object)] = file_observable
        return observable

    def resolve_file_pattern(self, attributes, object_id):
        patterns = []
        pattern = misp2stix2_mapping.objectsMapping['file']['pattern']
        attributes_dict = self.create_file_attributes_dict(attributes, object_id)
        for key, feature in misp2stix2_mapping.fileMapping.items():
            if key in attributes_dict:
                if key in misp2stix2_mapping.hash_types:
                    feature = f"hashes.'{feature}'"
                patterns.append(pattern.format(feature, attributes_dict[key]))
        if 'filename' in attributes_dict:
            self._handle_multiple_file_fields_pattern(patterns, attributes_dict['filename'], 'name')
        for feature in ('path', 'fullpath'):
            if feature in attributes_dict:
                self._handle_multiple_file_fields_pattern(patterns, attributes_dict[feature], 'parent_directory_ref.path')
        for feature, pattern_part in zip(('attachment', 'malware-sample'), ('artifact:', 'file:content_ref.')):
            if feature in attributes_dict:
                value = attributes_dict[feature]
                if ' | ' in value:
                    value, data = value.split(' | ')
                    patterns.append(f"{pattern_part}payload_bin = '{data}'")
                if feature == 'malware-sample':
                    value, md5 = value.split('|')
                    patterns.append(f"{pattern_part}hashes.'MD5' = '{md5}'")
                    patterns.append(f"{pattern_part}name = '{value}'")
                else:
                    patterns.append(f"{pattern_part}x_misp_text_name = '{value}'")
        return patterns

    def resolve_ip_port_observable(self, attributes, object_id):
        observable = {'type': 'network-traffic', 'protocols': ['tcp']}
        ip_address = {}
        domain = {}
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            attribute_value = attribute['value']
            if relation == 'ip':
                ip_address['type'] = self._define_address_type(attribute_value)
                ip_address['value'] = attribute_value
            elif relation == 'domain':
                domain['type'] = 'domain-name'
                domain['value'] = attribute_value
            else:
                try:
                    observable_type = misp2stix2_mapping.ipPortObjectMapping[relation]
                except KeyError:
                    continue
                observable[observable_type] = attribute_value
        ref_type = 'dst_ref'
        main_observable = None
        if 'src_port' in observable or 'dst_port' in observable:
            for port in ('src_port', 'dst_port'):
                try:
                    port_value = misp2stix2_mapping.defineProtocols[str(observable[port])]
                    if port_value not in observable['protocols']:
                        observable['protocols'].append(port_value)
                except KeyError:
                    pass
            main_observable = observable
        else:
            if domain:
                ref_type = 'resolves_to_refs'
        return self.ip_port_observable_to_return(ip_address, main_observable, domain, ref_type)

    @staticmethod
    def ip_port_observable_to_return(ip_address, d_object, domain, s_object):
        observable = {}
        o_id = 0
        if ip_address:
            observable['0'] = ip_address
            o_id += 1
        if d_object:
            if ip_address:
                d_object[s_object] = '0'
            observable[str(o_id)] = d_object
            o_id += 1
        if domain:
            if ip_address and not d_object:
                domain[s_object] = '0'
            observable[str(o_id)] = domain
        return observable

    def resolve_ip_port_pattern(self, attributes, object_id):
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            attribute_value = attribute['value']
            if relation == 'domain':
                mapping_type = 'domain-ip'
                stix_type = misp2stix2_mapping.ipPortObjectMapping[relation]
            elif relation == 'ip':
                mapping_type = 'ip-port'
                stix_type = misp2stix2_mapping.ipPortObjectMapping[relation].format('ref', self._define_address_type(attribute_value))
            else:
                try:
                    stix_type = misp2stix2_mapping.ipPortObjectMapping[relation]
                    mapping_type = 'ip-port'
                except KeyError:
                    continue
            pattern.append(misp2stix2_mapping.objectsMapping[mapping_type]['pattern'].format(stix_type, attribute_value))
        return pattern

    def resolve_network_connection_observable(self, attributes, object_id):
        attributes = {attribute['object_relation']: attribute['value'] for attribute in attributes}
        n, network_object, observable = self.create_network_observable(attributes)
        protocols = [attributes[layer] for layer in ('layer3-protocol', 'layer4-protocol', 'layer7-protocol') if layer in attributes]
        network_object['protocols'] = protocols if protocols else ['tcp']
        observable[str(n)] = network_object
        return observable

    def resolve_network_connection_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['network-connection']['pattern']
        attributes = {attribute['object_relation']: attribute['value'] for attribute in attributes}
        pattern = self.create_network_pattern(attributes, mapping)
        protocols = [attributes[layer] for layer in ('layer3-protocol', 'layer4-protocol', 'layer7-protocol') if layer in attributes]
        if protocols:
            for p in range(len(protocols)):
                pattern.append("network-traffic:protocols[{}] = '{}'".format(p, protocols[p]))
        return pattern

    def resolve_network_socket_observable(self, attributes, object_id):
        states, tmp_attributes = self.parse_network_socket_attributes(attributes, object_id)
        n, network_object, observable = self.create_network_observable(tmp_attributes)
        socket_extension = {misp2stix2_mapping.networkTrafficMapping[feature]: tmp_attributes[feature] for feature in ('address-family', 'domain-family') if feature in tmp_attributes}
        for state in states:
            state_type = "is_{}".format(state)
            socket_extension[state_type] = True
        network_object['protocols'] = [tmp_attributes['protocol']] if 'protocol' in tmp_attributes else ['tcp']
        if socket_extension:
            network_object['extensions'] = {'socket-ext': socket_extension}
        observable[str(n)] = network_object
        return observable

    def resolve_network_socket_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['network-socket']['pattern']
        states, tmp_attributes = self.parse_network_socket_attributes(attributes, object_id)
        pattern = self.create_network_pattern(tmp_attributes, mapping)
        stix_type = "extensions.'socket-ext'.{}"
        if "protocol" in tmp_attributes:
            pattern.append("network-traffic:protocols[0] = '{}'".format(tmp_attributes['protocol']))
        for feature in ('address-family', 'domain-family'):
            if feature in tmp_attributes:
                pattern.append(mapping.format(stix_type.format(misp2stix2_mapping.networkTrafficMapping[feature]), tmp_attributes[feature]))
        for state in states:
            state_type = "is_{}".format(state)
            pattern.append(mapping.format(stix_type.format(state_type), True))
        return pattern

    def parse_network_socket_attributes(self, attributes, object_id):
        states = []
        tmp_attributes = {}
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation == 'state':
                states.append(attribute['value'])
            else:
                tmp_attributes[relation] = attribute['value']
        return states, tmp_attributes

    def resolve_process_observable(self, attributes, object_id):
        observable = {}
        current_process = defaultdict(list)
        current_process['type'] = 'process'
        n = 0
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation == 'parent-pid':
                str_n = str(n)
                observable[str_n] = {'type': 'process', 'pid': attribute['value']}
                current_process['parent_ref'] = str_n
                n += 1
            elif relation == 'child-pid':
                str_n = str(n)
                observable[str_n] = {'type': 'process', 'pid': attribute['value']}
                current_process['child_refs'].append(str_n)
                n += 1
            elif relation == 'image':
                str_n = str(n)
                observable[str_n] = {'type': 'file', 'name': attribute['value']}
                current_process['binary_ref'] = str_n
                n += 1
            else:
                try:
                    current_process[misp2stix2_mapping.processMapping[relation]] = attribute['value']
                except KeyError:
                    pass
        observable[str(n)] = current_process
        return observable

    def resolve_process_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['process']['pattern']
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            try:
                pattern.append(mapping.format(misp2stix2_mapping.processMapping[attribute['object_relation']], attribute['value']))
            except KeyError:
                continue
        return pattern

    def resolve_regkey_observable(self, attributes, object_id):
        observable = {'type': 'windows-registry-key'}
        values = {}
        registry_value_types = ('data', 'data-type', 'name')
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = misp2stix2_mapping.regkeyMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            if relation in registry_value_types:
                values[stix_type] = attribute['value']
            else:
                observable[stix_type] = attribute['value']
        if values:
            if 'name' not in values:
                values['name'] = ''
            observable['values'] = [values]
        return {'0': observable}

    def resolve_regkey_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['registry-key']['pattern']
        pattern = []
        fields = ('key', 'value')
        registry_value_types = ('data', 'data-type', 'name')
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = misp2stix2_mapping.regkeyMapping[relation]
            except KeyError:
                stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
            value = attribute['value'].strip().replace('\\', '\\\\') if relation in fields and '\\\\' not in attribute['value'] else attribute['value'].strip()
            if relation in registry_value_types:
                stix_type = "values.{}".format(stix_type)
            pattern.append(mapping.format(stix_type, value))
        return pattern

    def create_network_observable(self, attributes):
        n = 0
        network_object = {'type': 'network-traffic'}
        observable = {}
        for feature in ('src', 'dst'):
            ip_feature = 'ip-{}'.format(feature)
            host_feature = 'hostname-{}'.format(feature)
            refs = []
            if host_feature in attributes:
                str_n = str(n)
                observable[str_n] = {'type': 'domain-name', 'value': attributes[host_feature]}
                refs.append(str_n)
                n += 1
            if ip_feature in attributes:
                feature_value = attributes[ip_feature]
                str_n = str(n)
                observable[str_n] = {'type': self._define_address_type(feature_value), 'value': feature_value}
                refs.append(str_n)
                n +=1
            if refs:
                ref_str, ref_list = ('ref', refs[0]) if len(refs) == 1 else ('refs', refs)
                network_object['{}_{}'.format(feature, ref_str)] = ref_list
        for feature in ('src-port', 'dst-port'):
            if feature in attributes:
                network_object[misp2stix2_mapping.networkTrafficMapping[feature]] = attributes[feature]
        return n, network_object, observable

    def create_network_pattern(self, attributes, mapping):
        pattern = []
        features = ('ip-{}', 'hostname-{}')
        for feature in ('src', 'dst'):
            index = 0
            references = {ftype: attributes[ftype] for ftype in (f_type.format(feature) for f_type in features) if ftype in attributes}
            ref  = 'ref' if len(references) == 1 else 'ref[{}]'
            if f'ip-{feature}' in attributes:
                value = references[f'ip-{feature}']
                pattern.append(mapping.format(misp2stix2_mapping.networkTrafficMapping[f'ip-{feature}'].format(ref.format(index), self._define_address_type(value)), value))
                index += 1
            if f'hostname-{feature}' in attributes:
                key = f'hostname-{feature}'
                pattern.append(mapping.format(misp2stix2_mapping.networkTrafficMapping[key].format(ref.format(index), 'domain-name'), references[key]))
            if f'{feature}-port' in attributes:
                key = f'{feature}-port'
                pattern.append(mapping.format(misp2stix2_mapping.networkTrafficMapping[key], attributes[key]))
        return pattern

    @staticmethod
    def resolve_stix2_pattern(attributes, _):
        for attribute in attributes:
            if attribute['object_relation'] == 'stix2-pattern':
                return attribute['value']

    def resolve_url_observable(self, attributes, object_id):
        url_args = {}
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            if attribute['type'] == 'url':
                # If we have the url (WE SHOULD), we return the observable supported atm with the url value
                observable = {'0': {'type': 'url', 'value': attribute['value']}}
            else:
                # otherwise, we need to see if there is a port or domain value to parse
                url_args[attribute['type']] = attribute['value']
        if 'domain' in url_args:
            observable['1'] = {'type': 'domain-name', 'value': url_args['domain']}
        if 'port' in url_args:
            port_value = url_args['port']
            port = {'type': 'network-traffic', 'dst_ref': '1', 'protocols': ['tcp'], 'dst_port': port_value}
            try:
                port['protocols'].append(misp2stix2_mapping.defineProtocols[port_value])
            except KeyError:
                pass
            if '1' in observable:
                observable['2'] = port
            else:
                observable['1'] = port
        return observable

    def resolve_url_pattern(self, attributes, object_id):
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            attribute_type = attribute['type']
            try:
                stix_type = misp2stix2_mapping.urlMapping[attribute_type]
            except KeyError:
                continue
            if attribute_type == 'port':
                mapping = 'ip-port'
            elif attribute_type == 'domain':
                mapping = 'domain-ip'
            else:
                mapping = attribute_type
            pattern.append(misp2stix2_mapping.objectsMapping[mapping]['pattern'].format(stix_type, attribute['value']))
        return pattern

    def resolve_user_account_observable(self, attributes, object_id):
        attributes = self.parse_user_account_attributes(attributes, object_id)
        observable = {'type': 'user-account'}
        extension = {}
        for relation, value in attributes.items():
            try:
                observable[misp2stix2_mapping.userAccountMapping[relation]] = value
            except KeyError:
                try:
                    extension[misp2stix2_mapping.unixAccountExtensionMapping[relation]] = value
                except KeyError:
                    continue
        if extension:
            observable['extensions'] = {'unix-account-ext': extension}
        return {'0': observable}

    def resolve_user_account_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['user-account']['pattern']
        extension_pattern = "extensions.'unix-account-ext'.{}"
        attributes = self.parse_user_account_attributes(attributes, object_id)
        pattern = []
        if 'group' in attributes:
            i = 0
            for group in attributes.pop('group'):
                pattern.append(mapping.format(extension_pattern.format('groups[{}]'.format(i)), group))
                i += 1
        for relation, value in attributes.items():
            try:
                pattern_part = mapping.format(misp2stix2_mapping.userAccountMapping[relation], value)
            except KeyError:
                try:
                    pattern_part = mapping.format(extension_pattern.format(misp2stix2_mapping.unixAccountExtensionMapping[relation]), value)
                except KeyError:
                    continue
            pattern.append(pattern_part)
        return pattern

    def parse_user_account_attributes(self, attributes, object_id):
        tmp_attributes = defaultdict(list)
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation == 'group':
                tmp_attributes[relation].append(attribute['value'])
            else:
                tmp_attributes[relation] = attribute['value']
        if 'user-id' not in tmp_attributes and 'username' in tmp_attributes:
            tmp_attributes['user-id'] = tmp_attributes.pop('username')
        if 'text' in tmp_attributes:
            tmp_attributes.pop('text')
        return tmp_attributes

    def resolve_x509_observable(self, attributes, object_id):
        observable = {'type': 'x509-certificate'}
        hashes = {}
        attributes2parse = defaultdict(list)
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                hashes[relation.split('-')[2]] = attribute['value']
            else:
                try:
                    observable[misp2stix2_mapping.x509mapping[relation]] = attribute['value']
                except KeyError:
                    value = bool(attribute['value']) if attribute['type'] == 'boolean' else attribute['value']
                    attributes2parse["x_misp_{}_{}".format(attribute['type'], relation)].append(value)
        if hashes:
            observable['hashes'] = hashes
        for stix_type, value in attributes2parse.items():
            observable[stix_type] = value if len(value) > 1 else value[0]
        return {'0': observable}

    def resolve_x509_pattern(self, attributes, object_id):
        mapping = misp2stix2_mapping.objectsMapping['x509']['pattern']
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                stix_type = f"hashes.'{relation.split('-')[2]}'"
            else:
                try:
                    stix_type = misp2stix2_mapping.x509mapping[relation]
                except KeyError:
                    stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
            value = bool(attribute['value']) if attribute['type'] == 'boolean' else attribute['value']
            pattern.append(mapping.format(stix_type, value))
        return pattern

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    @staticmethod
    def _create_artifact_observable(value):
        artifact = {'type': 'artifact'}
        if ' | ' in value:
            value, data = value.split(' | ')
            artifact['payload_bin'] = data
        return artifact, value

    def create_file_attributes_dict(self, attributes, object_id):
        multiple_fields = ('filename', 'path', 'fullpath')
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(self._parse_attribute(attribute))
            self.parse_galaxies(attribute['Galaxy'], object_id)
        return {key: value[0] if key not in multiple_fields and len(value) == 1 else value for key, value in attributes_dict.items()}

    @staticmethod
    def _define_address_type(address):
        if ':' in address:
            return 'ipv6-addr'
        return 'ipv4-addr'

    @staticmethod
    def _get_attribute_arguments(attribute):
        if attribute.get('data'):
            return (attribute['type'], attribute['value'], attribute['data'])
        return (attribute['type'], attribute['value'])

    @staticmethod
    def _get_function_to_call(attribute_type):
        if attribute_type in misp2stix2_mapping.mispTypesMapping:
            return 'handle_usual_type'
        if attribute_type == 'link':
            return 'handle_link'
        if attribute_type == 'vulnerability':
            return 'add_vulnerability'
        return 'add_custom'

    @staticmethod
    def get_datetime_from_timestamp(timestamp):
        return datetime.utcfromtimestamp(int(timestamp))

    @staticmethod
    def _handle_multiple_file_fields_observable(file_observable, values, feature):
        if len(values) > 1:
            file_observable[f'x_misp_multiple_{feature}s'] = values
        else:
            file_observable[f'x_misp_multiple_{feature}'] = values[0]

    @staticmethod
    def _handle_multiple_file_fields_pattern(patterns, values, feature):
        if len(values) > 1:
            patterns.extend([f"file:{feature} = '{value}'" for value in values])
        else:
            patterns.append(f"file:{feature} = '{values[0]}'")

    @staticmethod
    def handle_time_fields(attribute, timestamp, stix_type):
        to_return = {'created': timestamp, 'modified': timestamp}
        for misp_field, stix_field in zip(('first_seen', 'last_seen'), _time_fields[stix_type]):
            to_return[stix_field] = datetime.strptime(attribute[misp_field].split('+')[0], '%Y-%m-%dT%H:%M:%S.%f') if attribute.get(misp_field) else timestamp
        return to_return

    @staticmethod
    def _parse_as_attribute(stix_type, attribute_value):
        if stix_type == 'number' and attribute_value.startswith('AS'):
            return attribute_value[2:]
        return attribute_value

    @staticmethod
    def _parse_attribute(attribute):
        if attribute['type'] in ('attachment', 'malware-sample') and attribute.get('data') is not None:
            return f"{attribute['value'].replace(' | ', '|')} | {attribute['data']}"
        return attribute['value']

    @staticmethod
    def _parse_email_stix_type(relation, mapping):
        if relation == 'from':
            return f'{mapping}.value'
        if relation in ('to', 'cc'):
            return f'{mapping}[*].value'
        return mapping


def main(args):
    stix_builder = StixBuilder()
    stix_builder.loadEvent(args)
    stix_builder.buildEvent()

if __name__ == "__main__":
    main(sys.argv)
