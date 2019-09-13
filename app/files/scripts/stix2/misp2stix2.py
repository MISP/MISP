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

import sys, json, os, datetime
import pymisp
import re
import uuid
from stix2 import *
from misp2stix2_mapping import *
from collections import defaultdict
from copy import deepcopy

misp_hash_types = ("authentihash", "ssdeep", "imphash", "md5", "sha1", "sha224",
                   "sha256", "sha384", "sha512", "sha512/224","sha512/256","tlsh")
attack_pattern_galaxies_list = ('mitre-attack-pattern', 'mitre-enterprise-attack-attack-pattern',
                                'mitre-mobile-attack-attack-pattern', 'mitre-pre-attack-attack-pattern')
course_of_action_galaxies_list = ('mitre-course-of-action', 'mitre-enterprise-attack-course-of-action',
                                  'mitre-mobile-attack-course-of-action')
intrusion_set_galaxies_list = ('mitre-enterprise-attack-intrusion-set', 'mitre-mobile-attack-intrusion-set',
                               'mitre-pre-attack-intrusion-set', 'mitre-intrusion-set')
malware_galaxies_list = ('android', 'banker', 'stealer', 'backdoor', 'ransomware', 'mitre-malware',
                         'mitre-enterprise-attack-malware', 'mitre-mobile-attack-malware')
threat_actor_galaxies_list = ('threat-actor', 'microsoft-activity-group')
tool_galaxies_list = ('botnet', 'rat', 'exploit-kit', 'tds', 'tool', 'mitre-tool',
                      'mitre-enterprise-attack-tool', 'mitre-mobile-attack-tool')
_MISP_event_tags = ['Threat-Report', 'misp:tool="misp2stix2"']

class StixBuilder():
    def __init__(self):
        self.orgs = []
        self.galaxies = []
        self.ids = {}

    def loadEvent(self, args):
        pathname = os.path.dirname(args[0])
        filename = os.path.join(pathname, args[1])
        with open(filename, 'rt', encoding='utf-8') as f:
            self.json_event = json.loads(f.read())
        self.filename = filename
        self.load_objects_mapping()
        self.load_galaxy_mapping()

    def buildEvent(self):
        self.initialize_misp_types()
        stix_packages = [sdo for event in self.json_event['response'] for sdo in self.handler(event['Event'])] if self.json_event.get('response') else self.handler(self.json_event['Event'])
        outputfile = "{}.out".format(self.filename)
        with open(outputfile, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(stix_packages, cls=base.STIXJSONEncoder))
        print(json.dumps({'success': 1}))

    def eventReport(self):
        if not self.object_refs and self.links:
            self.add_custom(self.links.pop(0))
        external_refs = [self.__parse_link(link) for link in self.links]
        report_args = {'type': 'report', 'id': self.report_id, 'name': self.misp_event['info'],
                       'created_by_ref': self.identity_id, 'created': self.misp_event['date'],
                       'published': self.get_datetime_from_timestamp(self.misp_event['publish_timestamp']),
                       'interoperability': True}
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
        for marking_args in self.markings.values():
            marking = MarkingDefinition(**marking_args)
            self.append_object(marking)

    def add_all_relationships(self):
        for source, targets in self.relationships['defined'].items():
            if source.startswith('report'):
                continue
            source_type,_ = source.split('--')
            for target in targets:
                target_type,_ = target.split('--')
                try:
                    relation = relationshipsSpecifications[source_type][target_type]
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
                relationship = Relationship(source_ref=source, relationship_type=relationship_type,
                                            target_ref=target, interoperability=True)
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

    def initialize_misp_types(self):
        describe_types_filename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
        describe_types = open(describe_types_filename, 'r')
        categories_mapping = json.loads(describe_types.read())['result']['category_type_mappings']
        for category in categories_mapping:
            mispTypesMapping[category] = {'to_call': 'handle_person'}

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
                try:
                    getattr(self, mispTypesMapping[attribute['type']]['to_call'])(attribute)
                except KeyError:
                    self.add_custom(attribute)
        if self.misp_event.get('Object'):
            self.objects_to_parse = defaultdict(dict)
            for misp_object in self.misp_event['Object']:
                name = misp_object['name']
                if name == 'original-imported-file':
                    continue
                to_ids = self.fetch_ids_flag(misp_object['Attribute'])
                try:
                    getattr(self, objectsMapping[name]['to_call'])(misp_object, to_ids)
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

    def load_objects_mapping(self):
        self.objects_mapping = {
            'asn': {'observable': self.resolve_asn_observable,
                    'pattern': self.resolve_asn_pattern},
            'credential': {'observable': self.resolve_credential_observable,
                           'pattern': self.resolve_credential_pattern},
            'domain-ip': {'observable': self.resolve_domain_ip_observable,
                          'pattern': self.resolve_domain_ip_pattern},
            'email': {'observable': self.resolve_email_object_observable,
                      'pattern': self.resolve_email_object_pattern},
            'file': {'observable': self.resolve_file_observable,
                     'pattern': self.resolve_file_pattern},
            'ip-port': {'observable': self.resolve_ip_port_observable,
                        'pattern': self.resolve_ip_port_pattern},
            'network-connection': {'observable': self.resolve_network_connection_observable,
                                   'pattern': self.resolve_network_connection_pattern},
            'network-socket': {'observable': self.resolve_network_socket_observable,
                               'pattern': self.resolve_network_socket_pattern},
            'process': {'observable': self.resolve_process_observable,
                        'pattern': self.resolve_process_pattern},
            'registry-key': {'observable': self.resolve_regkey_observable,
                             'pattern': self.resolve_regkey_pattern},
            'stix2': {'pattern': self.resolve_stix2_pattern},
            'url': {'observable': self.resolve_url_observable,
                    'pattern': self.resolve_url_pattern},
            'user-account': {'observable': self.resolve_user_account_observable,
                             'pattern': self.resolve_user_account_pattern},
            'x509': {'observable': self.resolve_x509_observable,
                     'pattern': self.resolve_x509_pattern}
        }

    def load_galaxy_mapping(self):
        self.galaxies_mapping = {'branded-vulnerability': ['vulnerability', self.add_vulnerability_from_galaxy]}
        self.galaxies_mapping.update(dict.fromkeys(attack_pattern_galaxies_list, ['attack-pattern', self.add_attack_pattern]))
        self.galaxies_mapping.update(dict.fromkeys(course_of_action_galaxies_list, ['course-of-action', self.add_course_of_action]))
        self.galaxies_mapping.update(dict.fromkeys(intrusion_set_galaxies_list, ['intrusion-set', self.add_intrusion_set]))
        self.galaxies_mapping.update(dict.fromkeys(malware_galaxies_list, ['malware', self.add_malware]))
        self.galaxies_mapping.update(dict.fromkeys(threat_actor_galaxies_list, ['threat-actor', self.add_threat_actor]))
        self.galaxies_mapping.update(dict.fromkeys(tool_galaxies_list, ['tool', self.add_tool]))

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
        except Exception:
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
        for uuid, misp_object in self.objects_to_parse['file'].items():
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
                pattern = self.resolve_file_pattern(file_object['Attribute'], file_id)[1:-1]
                pattern += " AND {}".format(self.parse_pe_extensions_pattern(pe_object, sections))
                self.add_object_indicator(file_object, pattern_arg="[{}]".format(pattern))
            else:
                observable = self.resolve_file_observable(file_object['Attribute'], file_id)
                pe_type = self._get_pe_type_from_filename(observable['0'])
                observable['0']['extensions'] = self.parse_pe_extensions_observable(pe_object, sections, pe_type)
                self.add_object_observable(file_object, observable_arg=observable)

    @staticmethod
    def _create_pe_type_test(observable, extension):
        return [
            ('name' in observable and observable['name'].endswith('.%s' % extension)),
            ('mime_type' in observable and re.compile(".* .+{0}.+ .*|.* {0} .*".format(extension)).match(observable['mime_type'].lower()))]

    def _get_pe_type_from_filename(self, observable):
        for extension in ('exe', 'dll'):
            if any(self._create_pe_type_test(observable, extension)):
                return extension
        return 'sys'

    def parse_pe_extensions_observable(self, pe_object, sections, pe_type):
        extension = defaultdict(list)
        extension['pe_type'] = pe_type
        for attribute in pe_object['Attribute']:
            try:
                extension[peMapping[attribute['object_relation']]] = attribute['value']
            except KeyError:
                extension["x_misp_{}_{}".format(attribute['type'], attribute['object_relation'].replace('-', '_'))] = attribute['value']
        for section in sections:
            d_section = defaultdict(dict)
            for attribute in section['Attribute']:
                relation = attribute['object_relation']
                if relation in misp_hash_types:
                    d_section['hashes'][relation] = attribute['value']
                else:
                    try:
                        d_section[peSectionMapping[relation]] = attribute['value']
                    except KeyError:
                        continue
            if 'name' not in d_section:
                d_section['name'] = 'Section {}'.format(sections.index(section))
            extension['sections'].append(WindowsPESection(**d_section))
        if len(sections) != int(extension['number_of_sections']):
            extension['number_of_sections'] = str(len(sections))
        return {"windows-pebinary-ext": extension}

    def parse_pe_extensions_pattern(self, pe_object, sections):
        pattern = ""
        mapping = objectsMapping['file']['pattern']
        pe_mapping = "extensions.'windows-pebinary-ext'"
        for attribute in pe_object['Attribute']:
            try:
                stix_type = "{}.{}".format(pe_mapping, peMapping[attribute['object_relation']])
            except KeyError:
                stix_type = "{}.{}'".format(pe_mapping[:-1], "x_misp_{}_{}".format(attribute['type'], attribute['object_relation'].replace('-', '_')))
            pattern += mapping.format(stix_type, attribute['value'])
        n_section = 0
        for section in sections:
            section_mapping = "{}.sections[{}]".format(pe_mapping, str(n_section))
            for attribute in section['Attribute']:
                relation = attribute['object_relation']
                if relation in misp_hash_types:
                    stix_type = "{}.hashes.'{}'".format(section_mapping, relation)
                    pattern += mapping.format(stix_type, attribute['value'])
                else:
                    try:
                        stix_type = "{}.{}".format(section_mapping, peSectionMapping[relation])
                        pattern += mapping.format(stix_type, attribute['value'])
                    except KeyError:
                        continue
            n_section += 1
        return pattern[:-5]

    def parse_galaxies(self, galaxies, source_id):
        for galaxy in galaxies:
            self.parse_galaxy(galaxy, source_id)

    def parse_galaxy(self, galaxy, source_id):
        galaxy_type = galaxy.get('type')
        galaxy_uuid = galaxy['GalaxyCluster'][0]['collection_uuid']
        try:
            stix_type, to_call = self.galaxies_mapping[galaxy_type]
        except Exception:
            return
        if galaxy_uuid not in self.galaxies:
            to_call(galaxy)
            self.galaxies.append(galaxy_uuid)
        self.relationships['defined'][source_id].append("{}--{}".format(stix_type, galaxy_uuid))

    @staticmethod
    def generate_galaxy_args(galaxy, b_killchain, b_alias, sdo_type):
        cluster = galaxy['GalaxyCluster'][0]
        try:
            cluster_uuid = cluster['collection_uuid']
        except KeyError:
            cluster_uuid = cluster['uuid']
        sdo_id = "{}--{}".format(sdo_type, cluster_uuid)
        description = "{} | {}".format(galaxy['description'], cluster['description'])
        labels = ['misp:name=\"{}\"'.format(galaxy['name'])]
        sdo_args = {'id': sdo_id, 'type': sdo_type, 'name': cluster['value'],
                    'description': description, 'interoperability': True}
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
        a_p_id = 'attack-pattern--{}'.format(misp_object['uuid'])
        attributes_dict = {attribute['object_relation']: attribute['value'] for attribute in misp_object['Attribute']}
        a_p_args = {'id': a_p_id, 'type': 'attack-pattern', 'created_by_ref': self.identity_id}
        a_p_args['labels'] = self.create_object_labels(misp_object['name'], misp_object['meta-category'], to_ids)
        for relation, key in attackPatternObjectMapping.items():
            if relation in attributes_dict:
                a_p_args[key] = attributes_dict[relation]
        if 'id' in attributes_dict:
            capec_id = "CAPEC-{}".format(attributes_dict['id'])
            a_p_args['external_references'] = [{'source_name': 'capec', 'external_id': capec_id}]
        attack_pattern = AttackPattern(**a_p_args)
        self.append_object(attack_pattern)

    def add_course_of_action(self, misp_object):
        coa_args= self.generate_galaxy_args(misp_object, False, False, 'course-of-action')
        self.add_coa_stix_object(coa_args)

    def add_course_of_action_from_object(self, misp_object, _):
        coa_id = 'course-of-action--{}'.format(misp_object['uuid'])
        coa_args = {'id': coa_id, 'type': 'course-of-action'}
        for attribute in misp_object['Attribute']:
            self.parse_galaxies(attribute['Galaxy'], coa_id)
            relation = attribute['object_relation']
            if relation == 'name':
                coa_args['name'] = attribute['value']
            elif relation == 'description':
                coa_args['description'] = attribute['value']
        if not 'name' in coa_args:
            return
        self.add_coa_stix_object(coa_args)

    def add_coa_stix_object(self, coa_args):
        coa_args['created_by_ref'] = self.identity_id
        course_of_action = CourseOfAction(**coa_args)
        self.append_object(course_of_action)

    def add_custom(self, attribute):
        custom_object_id = "x-misp-object--{}".format(attribute['uuid'])
        custom_object_type = "x-misp-object-{}".format(attribute['type'].replace('|', '-').replace(' ', '-').lower())
        labels, markings = self.create_labels(attribute)
        custom_object_args = {'id': custom_object_id, 'x_misp_category': attribute['category'], 'labels': labels,
                              'x_misp_timestamp': self.get_datetime_from_timestamp(attribute['timestamp']),
                              'x_misp_value': attribute['value'], 'created_by_ref': self.identity_id}
        if attribute.get('comment'):
            custom_object_args['x_misp_comment'] = attribute['comment']
        if markings:
            markings = self.handle_tags(markings)
            custom_object_args['object_marking_refs'] = markings
        @CustomObject(custom_object_type, [('id', properties.StringProperty(required=True)),
                                          ('x_misp_timestamp', properties.StringProperty(required=True)),
                                          ('labels', properties.ListProperty(labels, required=True)),
                                          ('x_misp_value', properties.StringProperty(required=True)),
                                          ('created_by_ref', properties.StringProperty(required=True)),
                                          ('object_marking_refs', properties.ListProperty(markings)),
                                          ('x_misp_comment', properties.StringProperty()),
                                          ('x_misp_category', properties.StringProperty())
                                         ])
        class Custom(object):
            def __init__(self, **kwargs):
                return
        custom_object = Custom(**custom_object_args)
        self.append_object(custom_object)

    def add_identity(self, attribute):
        identity_id = "identity--{}".format(attribute['uuid'])
        name = attribute['value']
        labels, markings = self.create_labels(attribute)
        identity_args = {'id': identity_id,  'type': identity, 'name': name, 'labels': labels,
                          'identity_class': 'individual', 'created_by_ref': self.identity_id,
                          'interoperability': True}
        if attribute.get('comment'):
            identity_args['description'] = attribute['comment']
        if markings:
            identity_args['object_marking_refs'] = self.handle_tags(markings)
        identity = Identity(**identity_args)
        self.append_object(identity)

    def add_indicator(self, attribute):
        attribute_type = attribute['type']
        indicator_id = "indicator--{}".format(attribute['uuid'])
        self.parse_galaxies(attribute['Galaxy'], indicator_id)
        category = attribute['category']
        killchain = self.create_killchain(category)
        labels, markings = self.create_labels(attribute)
        attribute_value = attribute['value'] if attribute_type != "AS" else self.define_attribute_value(attribute['value'], attribute['comment'])
        pattern = mispTypesMapping[attribute_type]['pattern'](attribute_type, attribute_value, attribute['data']) if attribute.get('data') else self.define_pattern(attribute_type, attribute_value)
        indicator_args = {'id': indicator_id, 'type': 'indicator', 'labels': labels, 'kill_chain_phases': killchain,
                           'valid_from': self.misp_event['date'], 'created_by_ref': self.identity_id,
                           'pattern': pattern, 'interoperability': True}
        if hasattr(attribute, 'Sighting'):
            for sighting in attribute['Sighting']:
                if sighting['Organisation']['name'] == self.misp_event['Orgc']['name'] and sighting['type'] == "2":
                    indicator_args['valid_until'] = self.get_datetime_from_timestamp(sighting['date_sighting'])
                    break
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
        attribute_type = attribute['type']
        observed_data_id = "observed-data--{}".format(attribute['uuid'])
        self.parse_galaxies(attribute['Galaxy'], observed_data_id)
        timestamp = self.get_datetime_from_timestamp(attribute['timestamp'])
        labels, markings = self.create_labels(attribute)
        attribute_value = attribute['value'] if attribute_type != "AS" else self.define_attribute_value(attribute['value'], attribute['comment'])
        observable = mispTypesMapping[attribute_type]['observable'](attribute_type, attribute_value, attribute['data']) if attribute.get('data') else self.define_observable(attribute_type, attribute_value)
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data', 'number_observed': 1,
                              'first_observed': timestamp, 'last_observed': timestamp, 'labels': labels,
                              'created_by_ref': self.identity_id, 'objects': observable, 'interoperability': True}
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
        vulnerability_data = [mispTypesMapping['vulnerability']['vulnerability_args'](name)]
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
        if cluster['meta'] and cluster['meta']['aliases']:
            vulnerability_data = [mispTypesMapping['vulnerability']['vulnerability_args'](alias) for alias in cluster['meta']['aliases']]
        else:
            vulnerability_data = [mispTypesMapping['vulnerability']['vulnerability_args'](name)]
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
        custom_object_id = 'x-misp-object--{}'.format(misp_object['uuid'])
        name = misp_object['name']
        custom_object_type = 'x-misp-object-{}'.format(name)
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, to_ids)
        values = self.fetch_custom_values(misp_object['Attribute'], custom_object_id)
        custom_object_args = {'id': custom_object_id, 'x_misp_values': values, 'labels': labels,
                              'x_misp_category': category, 'created_by_ref': self.identity_id,
                              'x_misp_timestamp': self.get_datetime_from_timestamp(misp_object['timestamp'])}
        if hasattr(misp_object, 'comment') and misp_object.get('comment'):
            custom_object_args['x_misp_comment'] = misp_object['comment']
        @CustomObject(custom_object_type, [('id', properties.StringProperty(required=True)),
                                           ('x_misp_timestamp', properties.StringProperty(required=True)),
                                           ('labels', properties.ListProperty(labels, required=True)),
                                           ('x_misp_values', properties.DictionaryProperty(required=True)),
                                           ('created_by_ref', properties.StringProperty(required=True)),
                                           ('x_misp_comment', properties.StringProperty()),
                                           ('x_misp_category', properties.StringProperty())
                                          ])
        class Custom(object):
            def __init__(self, **kwargs):
                return
        custom_object = Custom(**custom_object_args)
        self.append_object(custom_object)

    def add_object_indicator(self, misp_object, pattern_arg=None):
        indicator_id = 'indicator--{}'.format(misp_object['uuid'])
        if pattern_arg:
            name = 'WindowsPEBinaryFile'
            pattern = pattern_arg
        else:
            name = misp_object['name']
            pattern = self.objects_mapping[name]['pattern'](misp_object['Attribute'], indicator_id)
        category = misp_object.get('meta-category')
        killchain = self.create_killchain(category)
        labels = self.create_object_labels(name, category, True)
        indicator_args = {'id': indicator_id, 'valid_from': self.misp_event['date'],
                          'type': 'indicator', 'labels': labels, 'pattern': pattern,
                          'description': misp_object['description'], 'allow_custom': True,
                          'kill_chain_phases': killchain, 'interoperability': True,
                          'created_by_ref': self.identity_id}
        indicator = Indicator(**indicator_args)
        self.append_object(indicator)

    def add_object_observable(self, misp_object, observable_arg=None):
        observed_data_id = 'observed-data--{}'.format(misp_object['uuid'])
        if observable_arg:
            name = 'WindowsPEBinaryFile'
            observable_objects = observable_arg
        else:
            name = misp_object['name']
            observable_objects = self.objects_mapping[name]['observable'](misp_object['Attribute'], observed_data_id)
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, False)
        timestamp = self.get_datetime_from_timestamp(misp_object['timestamp'])
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data', 'labels': labels,
                              'number_observed': 1, 'objects': observable_objects, 'allow_custom': True,
                              'first_observed': timestamp, 'last_observed': timestamp,
                              'created_by_ref': self.identity_id, 'interoperability': True}
        try:
            observed_data = ObservedData(**observed_data_args)
        except exceptions.InvalidValueError:
            observed_data = self.fix_enumeration_issues(name, observed_data_args)
        self.append_object(observed_data)

    @staticmethod
    def fix_enumeration_issues(name, args):
        enumeration_fails = {}
        if name == 'network-socket':
            ns_args = deepcopy(args)
            observable_object = ns_args['objects']
            n = sorted(observable_object.keys())[-1]
            current_dict = observable_object[n]['extensions']['socket-ext']
            for field in ('address_family', 'protocol_family'):
                enumeration_fails[field] = current_dict.pop(field)
                try:
                    return ObservedData(**ns_args)
                except (exceptions.InvalidValueError, exceptions.MissingPropertiesError):
                    current_dict[field] = enumeration_fails[field]
            for field in enumeration_fails:
                current_dict.pop(field)
            return ObservedData(**ns_args)
        return ObservedData(**args)

    def add_object_vulnerability(self, misp_object, to_ids):
        vulnerability_id = 'vulnerability--{}'.format(misp_object['uuid'])
        name = self.fetch_vulnerability_name(misp_object['Attribute'])
        labels = self.create_object_labels(name, misp_object.get('meta-category'), to_ids)
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'name': name, 'created_by_ref': self.identity_id,
                              'labels': labels, 'interoperability': True}
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
        labels = ['misp:type="{}"'.format(attribute['type']),
                  'misp:category="{}"'.format(attribute['category']),
                  'misp:to_ids="{}"'.format(attribute['to_ids'])]
        markings = []
        if attribute.get('Tag'):
            for tag in attribute['Tag']:
                name = tag['name']
                markings.append(name) if name.startswith('tlp:') else labels.append(name)
        return labels, markings

    @staticmethod
    def create_object_labels(name, category, to_ids):
        return ['misp:type="{}"'.format(name),
                'misp:category="{}"'.format(category),
                'misp:to_ids="{}"'.format(to_ids),
                'from_object']

    def create_marking(self, tag):
        try:
            marking_definition = globals()[tlp_markings[tag]]
            id = marking_definition.id
        except KeyError:
            id = 'marking-definition--%s' % uuid.uuid4()
            definition_type, definition = tag.split(':')
            marking_definition = {'type': 'marking-definition', 'id': id, 'definition_type': definition_type,
                                  'definition': {definition_type: definition}}
        self.markings[tag] = marking_definition
        return id

    @staticmethod
    def _parse_tag(namespace, predicate):
        if '=' not in predicate:
            return "{} = {}".format(namespace, predicate)
        predicate, value = predicate.split('=')
        return "({}) {} = {}".format(namespace, predicate, value.strip('"'))

    @staticmethod
    def define_observable(attribute_type, attribute_value):
        if attribute_type == 'malware-sample':
            return mispTypesMapping[attribute_type]['observable']('filename|md5', attribute_value)
        observable = mispTypesMapping[attribute_type]['observable'](attribute_type, attribute_value)
        if attribute_type == 'port':
            observable['0']['protocols'].append(defineProtocols[attribute_value] if attribute_value in defineProtocols else "tcp")
        return observable

    @staticmethod
    def define_pattern(attribute_type, attribute_value):
        attribute_value = attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##') if isinstance(attribute_value, str) else attribute_value
        if attribute_type == 'malware-sample':
            return mispTypesMapping[attribute_type]['pattern']('filename|md5', attribute_value)
        return mispTypesMapping[attribute_type]['pattern'](attribute_type, attribute_value)

    def fetch_custom_values(self, attributes, object_id):
        values = {}
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            attribute_type = '{}_{}'.format(attribute['type'], attribute['object_relation'])
            values[attribute_type] = attribute['value']
        return values

    @staticmethod
    def fetch_ids_flag(attributes):
        for attribute in attributes:
            if attribute['to_ids']:
                return True
        return False

    @staticmethod
    def fetch_vulnerability_name(attributes):
        for attribute in attributes:
            if attribute['type'] == 'vulnerability':
                return attribute['value']
        return "Undefined name"

    def handle_tags(self, tags):
        return [self.markings[tag]['id'] if tag in self.markings else self.create_marking(tag) for tag in tags]

    def resolve_asn_observable(self, attributes, object_id):
        asn = objectsMapping['asn']['observable']
        observable = {}
        object_num = 0
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = asnObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            attribute_value = attribute['value']
            if relation == "subnet-announced":
                observable[str(object_num)] = {'type': define_address_type(attribute_value), 'value': attribute_value}
                object_num += 1
            else:
                asn[stix_type] = int(attribute_value[2:]) if (stix_type == 'number' and attribute_value.startswith("AS")) else attribute_value
        observable[str(object_num)] = asn
        for n in range(object_num):
            observable[str(n)]['belongs_to_refs'] = [str(object_num)]
        return observable

    def resolve_asn_pattern(self, attributes, object_id):
        mapping = objectsMapping['asn']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = asnObjectMapping[relation]
            except KeyError:
                stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
            attribute_value = attribute['value']
            if relation == "subnet-announced":
                pattern += "{0}:{1} = '{2}' AND ".format(define_address_type(attribute_value), stix_type, attribute_value)
            else:
                pattern += mapping.format(stix_type, attribute_value)
        return "[{}]".format(pattern[:-5])

    def resolve_credential_observable(self, attributes, object_id):
        user_account = objectsMapping['credential']['observable']
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = credentialObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            user_account[stix_type] = attribute['value']
        return {'0': user_account}

    def resolve_credential_pattern(self, attributes, object_id):
        mapping = objectsMapping['credential']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = credentialObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            pattern += mapping.format(stix_type, attribute['value'])
        return "[{}]".format(pattern[:-5])

    def resolve_domain_ip_observable(self, attributes, object_id):
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            if attribute['type'] == 'ip-dst':
                ip_value = attribute['value']
            elif attribute['type'] == 'domain':
                domain_value = attribute['value']
        domain_ip_value = "{}|{}".format(domain_value, ip_value)
        return mispTypesMapping['domain|ip']['observable']('', domain_ip_value)

    def resolve_domain_ip_pattern(self, attributes, object_id):
        mapping = objectsMapping['domain-ip']['pattern']
        pattern = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            try:
                stix_type = domainIpObjectMapping[attribute['type']]
            except KeyError:
                continue
            pattern.append(mapping.format(stix_type, attribute['value']))
        return "[{}]".format(" AND ".join(pattern))

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
                mapping = emailObjectMapping[relation]['stix_type']
                if relation in ('from', 'to', 'cc'):
                    object_str = str(object_num)
                    observable[object_str] = {'type': 'email-addr', 'value': attribute_value}
                    if relation == 'from':
                        message[mapping] = object_str
                    else:
                        message[mapping].append(object_str)
                    object_num += 1
                elif relation == 'attachment':
                    object_str = str(object_num)
                    body = {"content_disposition": "{}; filename='{}'".format(relation, attribute_value),
                            "body_raw_ref": object_str}
                    message['body_multipart'].append(body)
                    observable[object_str] = {'type': 'file', 'name': attribute_value}
                    object_num += 1
                elif relation in ('x-mailer', 'reply-to'):
                    key = '-'.join([part.capitalize() for part in relation.split('-')])
                    additional_header[key] = attribute_value
                else:
                    message[mapping] = attribute_value
            except Exception:
                mapping = "x_misp_{}_{}".format(attribute['type'], relation)
                if relation in ('eml', 'screenshot'):
                    message[mapping] = {'value': attribute_value, 'data': attribute['data']}
                else:
                    message[mapping] = attribute_value
        if additional_header:
            message['additional_header_fields'] = additional_header
        message['type'] = 'email-message'
        if 'body_multipart' in message:
            message['is_multipart'] = True
        else:
            message['is_multipart'] = False
        observable[str(object_num)] = dict(message)
        return observable

    def resolve_email_object_pattern(self, attributes, object_id):
        pattern_mapping = objectsMapping['email']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                mapping = emailObjectMapping[relation]
                stix_type = mapping['stix_type']
                email_type = mapping['email_type']
            except KeyError:
                email_type = 'message'
                stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
                if relation in ('eml', 'screenshot'):
                    stix_type_data = "{}.data".format(stix_type)
                    pattern += pattern_mapping.format(email_type, stix_type_data, attribute['data'])
                    stix_type += ".value"
            pattern += pattern_mapping.format(email_type, stix_type, attribute['value'])
        return "[{}]".format(pattern[:-5])

    def resolve_file_observable(self, attributes, object_id):
        observable = {}
        observable_file = defaultdict(dict)
        observable_file['type'] = 'file'
        malware_sample = {}
        d_observable = {}
        n_object = 0
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            attribute_type = attribute['type']
            if attribute_type == 'malware-sample':
                filename, md5 = attribute['value'].split('|')
                malware_sample['filename'] = filename
                malware_sample['md5'] = md5
                if attribute.get('data'):
                    observable[str(n_object)] = {'type': 'artifact', 'payload_bin': attribute['data']}
                    observable_file['content_ref'] = str(n_object)
                    n_object += 1
            elif attribute_type in ('filename', 'md5'):
                d_observable[attribute_type] = attribute['value']
            elif attribute_type in misp_hash_types:
                observable_file['hashes'][attribute_type] = attribute['value']
            else:
                try:
                    observable_type = fileMapping[attribute_type]
                except KeyError:
                    observable_type = "x_misp_{}_{}".format(attribute_type, attribute['object_relation'])
                observable_file[observable_type] = attribute['value']
        if 'md5' in d_observable:
            observable_file['hashes']['MD5'] = malware_sample['md5'] if 'md5' in malware_sample else d_observable['md5']
        if 'filename' in d_observable:
            observable_file['name'] = malware_sample['filename'] if 'filename' in malware_sample else d_observable['filename']
        observable[str(n_object)] = observable_file
        return observable

    def resolve_file_pattern(self, attributes, object_id):
        pattern = ""
        d_pattern = {}
        s_pattern = objectsMapping['file']['pattern']
        malware_sample = {}
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            attribute_type = attribute['type']
            if attribute_type == "malware-sample":
                filename, md5 = attribute['value'].split('|')
                malware_sample['filename'] = filename
                malware_sample['md5'] = md5
                if attribute.get('data'):
                    pattern += "{} AND ".format(attribute_data_pattern(attribute['data']))
            elif attribute_type in ("filename", "md5"):
                d_pattern[attribute_type] = attribute['value']
            else:
                try:
                    stix_type = fileMapping['hashes'].format(attribute_type) if attribute_type in misp_hash_types else fileMapping[attribute_type]
                except KeyError:
                    stix_type = "'x_misp_{}_{}'".format(attribute_type, attribute['object_relation'])
                pattern += s_pattern.format(stix_type, attribute['value'])
        for attribute_type in ('filename', 'md5'):
            stix_type = fileMapping['hashes'].format(attribute_type) if attribute_type in misp_hash_types else fileMapping[attribute_type]
            if attribute_type in malware_sample:
                pattern += s_pattern.format(stix_type, malware_sample[attribute_type])
            elif attribute_type in d_pattern:
                pattern += s_pattern.format(stix_type, d_pattern[attribute_type])
        return "[{}]".format(pattern[:-5])

    def resolve_ip_port_observable(self, attributes, object_id):
        observable = {'type': 'network-traffic', 'protocols': ['tcp']}
        ip_address = {}
        domain = {}
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            attribute_value = attribute['value']
            if relation == 'ip':
                ip_address['type'] = define_address_type(attribute_value)
                ip_address['value'] = attribute_value
            elif relation == 'domain':
                domain['type'] = 'domain-name'
                domain['value'] = attribute_value
            else:
                try:
                    observable_type = ipPortObjectMapping[relation]
                except KeyError:
                    continue
                observable[observable_type] = attribute_value
        ref_type = 'dst_ref'
        main_observable = None
        if 'src_port' in observable or 'dst_port' in observable:
            for port in ('src_port', 'dst_port'):
                try:
                    port_value = defineProtocols[str(observable[port])]
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
                stix_type = ipPortObjectMapping[relation]
            elif relation == 'ip':
                mapping_type = 'ip-port'
                stix_type = ipPortObjectMapping[relation].format(define_address_type(attribute_value))
            else:
                try:
                    stix_type = ipPortObjectMapping[relation]
                    mapping_type = 'ip-port'
                except KeyError:
                    continue
            pattern.append(objectsMapping[mapping_type]['pattern'].format(stix_type, attribute_value))
        return "[{}]".format(" AND ".join(pattern))

    def resolve_network_connection_observable(self, attributes, object_id):
        attributes = {attribute['object_relation']: attribute['value'] for attribute in attributes}
        n, network_object, observable = self.create_network_observable(attributes)
        protocols = [attributes[layer] for layer in ('layer3-protocol', 'layer4-protocol', 'layer7-protocol') if layer in attributes]
        network_object['protocols'] = protocols if protocols else ['tcp']
        observable[str(n)] = network_object
        return observable

    def resolve_network_connection_pattern(self, attributes, object_id):
        mapping = objectsMapping['network-connection']['pattern']
        attributes = {attribute['object_relation']: attribute['value'] for attribute in attributes}
        pattern = self.create_network_pattern(attributes, mapping)
        protocols = [attributes[layer] for layer in ('layer3-protocol', 'layer4-protocol', 'layer7-protocol') if layer in attributes]
        if protocols:
            for p in range(len(protocols)):
                pattern.append("network-traffic:protocols[{}] = '{}'".format(p, protocols[p]))
        return "[{}]".format(" AND ".join(pattern))

    def resolve_network_socket_observable(self, attributes, object_id):
        states, tmp_attributes = self.parse_network_socket_attributes(attributes, object_id)
        n, network_object, observable = self.create_network_observable(tmp_attributes)
        socket_extension = {networkTrafficMapping[feature]: tmp_attributes[feature] for feature in ('address-family', 'domain-family') if feature in tmp_attributes}
        for state in states:
            state_type = "is_{}".format(state)
            socket_extension[state_type] = True
        network_object['protocols'] = [tmp_attributes['protocol']] if 'protocol' in tmp_attributes else ['tcp']
        if socket_extension:
            network_object['extensions'] = {'socket-ext': socket_extension}
        observable[str(n)] = network_object
        return observable

    def resolve_network_socket_pattern(self, attributes, object_id):
        mapping = objectsMapping['network-socket']['pattern']
        states, tmp_attributes = self.parse_network_socket_attributes(attributes, object_id)
        pattern = self.create_network_pattern(tmp_attributes, mapping)
        stix_type = "extensions.'socket-ext'.{}"
        if "protocol" in tmp_attributes:
            pattern.append("network-traffic:protocols[0] = '{}'".format(tmp_attributes['protocol']))
        for feature in ('address-family', 'domain-family'):
            if feature in tmp_attributes:
                pattern.append(mapping.format(stix_type.format(networkTrafficMapping[feature]), tmp_attributes[feature]))
        for state in states:
            state_type = "is_{}".format(state)
            pattern.append(mapping.format(stix_type.format(state_type), True))
        return "[{}]".format(" AND ".join(pattern))

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
            else:
                try:
                    current_process[processMapping[relation]] = attribute['value']
                except KeyError:
                    pass
        observable[str(n)] = current_process
        return observable

    def resolve_process_pattern(self, attributes, object_id):
        mapping = objectsMapping['process']['pattern']
        pattern = ""
        child_refs = []
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation == 'parent-pid':
                pattern += mapping.format('parent_ref', attribute['value'])
            elif relation == 'child-pid':
                child_refs.append(attribute['value'])
            else:
                try:
                    pattern += mapping.format(processMapping[relation], attribute['value'])
                except KeyError:
                    continue
        if child_refs: pattern += mapping.format('child_refs', child_refs)
        return "[{}]".format(pattern[:-5])

    def resolve_regkey_observable(self, attributes, object_id):
        observable = {'type': 'windows-registry-key'}
        values = {}
        registry_value_types = ('data', 'data-type', 'name')
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = regkeyMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute['type'], relation)
            if relation in registry_value_types:
                values[stix_type] = attribute['value']
            else:
                observable[stix_type] = attribute['value']
        if values:
            observable['values'] = [values]
        return {'0': observable}

    def resolve_regkey_pattern(self, attributes, object_id):
        mapping = objectsMapping['registry-key']['pattern']
        pattern = []
        fields = ('key', 'value')
        registry_value_types = ('data', 'data-type', 'name')
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            try:
                stix_type = regkeyMapping[relation]
            except KeyError:
                stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
            value = attribute['value'].strip().replace('\\', '\\\\') if relation in fields and '\\\\' not in attribute['value'] else attribute['value'].strip()
            if relation in registry_value_types:
                stix_type = "values.{}".format(stix_type)
            pattern.append(mapping.format(stix_type, value))
        return "[{}]".format(" AND ".join(pattern))

    @staticmethod
    def create_network_observable(attributes):
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
                observable[str_n] = {'type': define_address_type(feature_value), 'value': feature_value}
                refs.append(str_n)
                n +=1
            if refs:
                ref_str, ref_list = ('ref', refs[0]) if len(refs) == 1 else ('refs', refs)
                network_object['{}_{}'.format(feature, ref_str)] = ref_list
        for feature in ('src-port', 'dst-port'):
            if feature in attributes:
                network_object[networkTrafficMapping[feature]] = attributes[feature]
        return n, network_object, observable

    @staticmethod
    def create_network_pattern(attributes, mapping):
        pattern = []
        for feature in ('src', 'dst'):
            ip_feature = 'ip-{}'.format(feature)
            if ip_feature in attributes:
                value = attributes[ip_feature]
                pattern.append(mapping.format(networkTrafficMapping[ip_feature].format(define_address_type(value)), value))
            host_feature = 'hostname-{}'.format(feature)
            if host_feature in attributes:
                pattern.append(mapping.format(networkTrafficMapping[host_feature].format('domain-name'), attributes[host_feature]))
            port_feature = '{}-port'.format(feature)
            if port_feature in attributes:
                pattern.append(mapping.format(networkTrafficMapping[port_feature], attributes[port_feature]))
        return pattern

    @staticmethod
    def resolve_stix2_pattern(attributes):
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
                port['protocols'].append(defineProtocols[port_value])
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
                stix_type = urlMapping[attribute_type]
            except KeyError:
                continue
            if attribute_type == 'port':
                mapping = 'ip-port'
            elif attribute_type == 'domain':
                mapping = 'domain-ip'
            else:
                mapping = attribute_type
            pattern.append(objectsMapping[mapping]['pattern'].format(stix_type, attribute['value']))
        return "[{}]".format(" AND ".join(pattern))

    def resolve_user_account_observable(self, attributes, object_id):
        attributes = self.parse_user_account_attributes(attributes, object_id)
        observable = {'type': 'user-account'}
        extension = {}
        for relation, value in attributes.items():
            try:
                observable[userAccountMapping[relation]] = value
            except KeyError:
                try:
                    extension[unixAccountExtensionMapping[relation]] = value
                except KeyError:
                    continue
        if extension:
            observable['extensions'] = {'unix-account-ext': extension}
        return {'0': observable}

    def resolve_user_account_pattern(self, attributes, object_id):
        mapping = objectsMapping['user-account']['pattern']
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
                pattern_part = mapping.format(userAccountMapping[relation], value)
            except KeyError:
                try:
                    pattern_part = mapping.format(extension_pattern.format(unixAccountExtensionMapping[relation]), value)
                except KeyError:
                    continue
            pattern.append(pattern_part)
        return "[{}]".format(' AND '.join(pattern))

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
                    observable[x509mapping[relation]] = attribute['value']
                except KeyError:
                    value = bool(attribute['value']) if attribute['type'] == 'boolean' else attribute['value']
                    attributes2parse["x_misp_{}_{}".format(attribute['type'], relation)].append(value)
        if hashes:
            observable['hashes'] = hashes
        for stix_type, value in attributes2parse.items():
            observable[stix_type] = value if len(value) > 1 else value[0]
        return {'0': observable}

    def resolve_x509_pattern(self, attributes, object_id):
        mapping = objectsMapping['x509']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute['Galaxy'], object_id)
            relation = attribute['object_relation']
            if relation in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                stix_type = fileMapping['hashes'].format(relation.split('-')[2])
            else:
                try:
                    stix_type = x509mapping[relation]
                except KeyError:
                    stix_type = "'x_misp_{}_{}'".format(attribute['type'], relation)
            value = bool(attribute['value']) if attribute['type'] == 'boolean' else attribute['value']
            pattern += mapping.format(stix_type, value)
        return "[{}]".format(pattern[:-5])

    @staticmethod
    def define_attribute_value(value, comment):
        if value.isdigit() or value.startswith("AS"):
            return int(value) if value.isdigit() else int(value[2:].split(' ')[0])
        if comment.startswith("AS") or comment.isdigit():
            return int(comment) if comment.isdigit() else int(comment[2:].split(' ')[0])

    @staticmethod
    def get_datetime_from_timestamp(timestamp):
        return datetime.datetime.utcfromtimestamp(int(timestamp))

def main(args):
    stix_builder = StixBuilder()
    stix_builder.loadEvent(args)
    stix_builder.buildEvent()

if __name__ == "__main__":
    main(sys.argv)
