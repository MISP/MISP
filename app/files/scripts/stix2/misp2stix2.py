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
from stix2 import *
from base64 import b64encode
from misp2stix2_mapping import *
from collections import defaultdict
from copy import deepcopy

misp_hash_types = ["authentihash", "ssdeep", "imphash", "md5", "sha1", "sha224",
                   "sha256", "sha384", "sha512", "sha512/224","sha512/256","tlsh"]
attack_pattern_galaxies_list = ['mitre-attack-pattern', 'mitre-enterprise-attack-attack-pattern',
                                'mitre-mobile-attack-attack-pattern', 'mitre-pre-attack-attack-pattern']
course_of_action_galaxies_list = ['mitre-course-of-action', 'mitre-enterprise-attack-course-of-action',
                                  'mitre-mobile-attack-course-of-action']
intrusion_set_galaxies_list = ['mitre-enterprise-attack-intrusion-set', 'mitre-mobile-attack-intrusion-set',
                               'mitre-pre-attack-intrusion-set', 'mitre-intrusion-set']
malware_galaxies_list = ['android', 'banker', 'stealer', 'backdoor', 'ransomware', 'mitre-malware',
                         'mitre-enterprise-attack-malware', 'mitre-mobile-attack-malware']
threat_actor_galaxies_list = ['threat-actor', 'microsoft-activity-group']
tool_galaxies_list = ['botnet', 'rat', 'exploit-kit', 'tds', 'tool', 'mitre-tool',
                      'mitre-enterprise-attack-tool', 'mitre-mobile-attack-tool']

class StixBuilder():
    def __init__(self):
        self.misp_event = pymisp.MISPEvent()
        self.SDOs = []
        self.object_refs = []
        self.external_refs = []
        self.galaxies = []
        self.relationships = defaultdict(list)
        self.to_return = {}

    def loadEvent(self, args):
        pathname = os.path.dirname(args[0])
        filename = os.path.join(pathname, args[1])
        self.orgs = [org for org in args[2:]] if len(args) > 2 else []
        self.misp_event.load_file(filename)
        self.filename = filename
        self.report_id = "report--{}".format(self.misp_event.uuid)

    def buildEvent(self):
        i = self.__set_identity()
        self.read_attributes()
        report = self.eventReport()
        self.SDOs.insert(i, report)

    def eventReport(self):
        report_args = {'type': 'report', 'id': self.report_id, 'name': self.misp_event.info,
                       'created_by_ref': self.identity_id, 'published': self.misp_event.publish_timestamp,
                       'created': self.misp_event.date, 'object_refs': self.object_refs}
        if self.misp_event.Tag:
            labels = []
            for tag in self.misp_event.Tag:
                labels.append(tag.name)
            report_args['labels'] = labels
            if 'misp:tool="misp2stix2"' not in labels:
                report_args['labels'].append('misp:tool="misp2stix2"')
        else:
            report_args['labels'] = ['Threat-Report']
            report_args['labels'].append('misp:tool="misp2stix2"')
        if self.external_refs:
            report_args['external_references'] = self.external_refs
        return Report(**report_args)

    def saveFile(self):
        outputfile = "{}.out".format(self.filename)
        with open(outputfile, 'w') as f:
            f.write(json.dumps(self.SDOs, cls=base.STIXJSONEncoder))
        self.to_return['success'] = 1
        print(json.dumps(self.to_return))

    def __set_identity(self):
        org = self.misp_event.Orgc
        org_uuid = org['uuid']
        identity_id = 'identity--{}'.format(org_uuid)
        self.identity_id = identity_id
        if org_uuid not in self.orgs:
            identity = Identity(type="identity", id=identity_id,
                                name=org["name"], identity_class="organization")
            self.SDOs.append(identity)
            self.to_return['org'] = org_uuid
            return 1
        return 0

    def misp_types(self):
        describe_types_filename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
        describe_types = open(describe_types_filename, 'r')
        categories_mapping = json.loads(describe_types.read())['result']['category_type_mappings']
        for category in categories_mapping:
            mispTypesMapping[category] = {'to_call': 'handle_person'}

    def read_attributes(self):
        self.misp_types()
        if hasattr(self.misp_event, 'attributes') and self.misp_event.attributes:
            for attribute in self.misp_event.attributes:
                try:
                    getattr(self, mispTypesMapping[attribute.type]['to_call'])(attribute)
                except KeyError:
                    self.add_custom(attribute)
        if hasattr(self.misp_event, 'objects') and self.misp_event.objects:
            self.load_objects_mapping()
            self.objects_to_parse = defaultdict(dict)
            misp_objects = self.misp_event.objects
            self.object_references, self.processes = self.fetch_object_references(misp_objects)
            for misp_object in misp_objects:
                to_ids = self.fetch_ids_flag(misp_object.attributes)
                name = misp_object.name
                try:
                    getattr(self, objectsMapping[name]['to_call'])(misp_object, to_ids)
                except KeyError:
                    self.add_object_custom(misp_object, to_ids)
            if self.objects_to_parse:
                self.resolve_objects2parse()
        if hasattr(self.misp_event, 'Galaxy') and self.misp_event.Galaxy:
            for galaxy in self.misp_event.Galaxy:
                self.parse_galaxy(galaxy, self.report_id)
        for source, targets in self.relationships.items():
            if source.startswith('report'): continue
            source_type,_ = source.split('--')
            for target in targets:
                target_type,_ = target.split('--')
                try:
                    relation = relationshipsSpecifications[source_type][target_type]
                except KeyError:
                    # custom relationship (suggested by iglocska)
                    relation = "has"
                relationship = Relationship(source_ref=source, target_ref=target, relationship_type=relation)
                self.append_object(relationship, relationship.id)

    def load_objects_mapping(self):
        self.objects_mapping = {
            'asn': {'observable': self.resolve_asn_observable,
                    'pattern': self.resolve_asn_pattern},
            'domain-ip': {'observable': self.resolve_domain_ip_observable,
                          'pattern': self.resolve_domain_ip_pattern},
            'email': {'observable': self.resolve_email_object_observable,
                      'pattern': self.resolve_email_object_pattern},
            'file': {'observable': self.resolve_file_observable,
                     'pattern': self.resolve_file_pattern},
            'ip-port': {'observable': self.resolve_ip_port_observable,
                        'pattern': self.resolve_ip_port_pattern},
            'network-socket': {'observable': self.resolve_network_socket_observable,
                               'pattern': self.resolve_network_socket_pattern},
            'process': {'observable': self.resolve_process_observable,
                        'pattern': self.resolve_process_pattern},
            'registry-key': {'observable': self.resolve_regkey_observable,
                             'pattern': self.resolve_regkey_pattern},
            'stix2': {'pattern': self.resolve_stix2_pattern},
            'url': {'observable': self.resolve_url_observable,
                    'pattern': self.resolve_url_pattern},
            'x509': {'observable': self.resolve_x509_observable,
                     'pattern': self.resolve_x509_pattern}
        }
        self.galaxies_mapping = {'branded-vulnerability': ['vulnerability', self.add_vulnerability_from_galaxy]}
        self.galaxies_mapping.update(dict.fromkeys(attack_pattern_galaxies_list, ['attack-pattern', self.add_attack_pattern]))
        self.galaxies_mapping.update(dict.fromkeys(course_of_action_galaxies_list, ['course-of-action', self.add_course_of_action]))
        self.galaxies_mapping.update(dict.fromkeys(intrusion_set_galaxies_list, ['intrusion-set', self.add_intrusion_set]))
        self.galaxies_mapping.update(dict.fromkeys(malware_galaxies_list, ['malware', self.add_malware]))
        self.galaxies_mapping.update(dict.fromkeys(threat_actor_galaxies_list, ['threat-actor', self.add_threat_actor]))
        self.galaxies_mapping.update(dict.fromkeys(tool_galaxies_list, ['tool', self.add_tool]))

    def fetch_object_references(self, misp_objects):
        object_references, processes = {}, {}
        for misp_object in misp_objects:
            attributes = misp_object.attributes
            if misp_object.name == "process":
                self.get_process_attributes(processes, misp_object.attributes)
            if misp_object.references and not self.fetch_ids_flag(attributes):
                for reference in misp_object.references:
                    try:
                        referenced_object = reference.Attribute
                    except:
                        referenced_object = self.misp_event.get_object_by_uuid(reference.referenced_uuid)
                    object_references[reference.referenced_uuid] = referenced_object
        return object_references, processes

    @staticmethod
    def get_process_attributes(processes, attributes):
        pid, process = None, {}
        for attribute in attributes:
            relation = attribute.object_relation
            attribute_value = attribute.value
            if relation == 'pid':
                if attribute_value in processes:
                    return
                pid = attribute_value
                process[relation] = attribute_value
            elif relation in ('name', 'creation-time'):
                process[relation] = attribute_value
        if pid is not None:
            process['type'] = 'process'
            processes[pid] = process

    def handle_person(self, attribute):
        if attribute.category == "Person":
            self.add_identity(attribute)
        else:
            self.add_custom(attribute)

    def handle_usual_type(self, attribute):
        try:
            if attribute.to_ids:
                self.add_indicator(attribute)
            else:
                self.add_observed_data(attribute)
        except:
            self.add_custom(attribute)

    def handle_usual_object_name(self, misp_object, to_ids):
        name = misp_object.name
        if  name == 'file' and misp_object.references:
            for reference in misp_object.references:
                if reference.relationship_type == 'included-in' and reference.Object['name'] == "pe":
                    self.objects_to_parse[name][misp_object.uuid] = to_ids, misp_object
                    return
        try:
            if to_ids or name == "stix2-pattern":
                self.add_object_indicator(misp_object)
            else:
                self.add_object_observable(misp_object)
        except:
            self.add_object_custom(misp_object, to_ids)

    def handle_link(self, attribute):
        url = attribute.value
        source = "url"
        try:
            if hasattr(attribute, 'comment') and attribute.comment:
                source += " - {}".format(attribute.comment)
        except AttributeError:
            pass
        link = {'source_name': source, 'url': url}
        self.external_refs.append(link)

    def populate_objects_to_parse(self, misp_object, to_ids):
        self.objects_to_parse[misp_object.name][misp_object.uuid] = to_ids, misp_object

    def resolve_objects2parse(self):
        for uuid, misp_object in self.objects_to_parse['file'].items():
            to_ids_file, file_object = misp_object
            file_id = "file--{}".format(file_object.uuid)
            to_ids_list = [to_ids_file]
            object2create = defaultdict(list)
            for reference in file_object.references:
                if reference.relationship_type == "included-in" and reference.Object['name'] == "pe":
                    pe_uuid = reference.referenced_uuid
                    break
            to_ids_pe, pe_object = self.objects_to_parse['pe'][pe_uuid]
            to_ids_list.append(to_ids_pe)
            sections = []
            for reference in pe_object.references:
                if reference.Object['name'] == "pe-section":
                    to_ids_section, section_object = self.objects_to_parse['pe-section'][reference.referenced_uuid]
                    to_ids_list.append(to_ids_section)
                    sections.append(section_object)
            if True in to_ids_list:
                pattern = self.resolve_file_pattern(file_object.attributes, file_id)[1:-1]
                pattern += " AND {}".format(self.parse_pe_extensions_pattern(pe_object, sections))
                self.add_object_indicator(file_object, pattern_arg="[{}]".format(pattern))
            else:
                observable = self.resolve_file_observable(file_object.attributes, file_id)
                observable['1']['extensions'] = self.parse_pe_extensions_observable(pe_object, sections)
                self.add_object_observable(file_object, observable_arg=observable)

    def parse_pe_extensions_observable(self, pe_object, sections):
        extension = defaultdict(list)
        for attribute in pe_object.attributes:
            try:
                extension[peMapping[attribute.object_relation]] = attribute.value
            except KeyError:
                extension["x_misp_{}_{}".format(attribute.type, attribute.object_relation.replace('-', '_'))] = attribute.value
        for section in sections:
            d_section = defaultdict(dict)
            for attribute in section.attributes:
                relation = attribute.object_relation
                if relation in misp_hash_types:
                    d_section['hashes'][relation] = attribute.value
                else:
                    try:
                        d_section[peSectionMapping[relation]] = attribute.value
                    except KeyError:
                        continue
            extension['sections'].append(WindowsPESection(**d_section))
        return {"windows-pebinary-ext": extension}

    def parse_pe_extensions_pattern(self, pe_object, sections):
        pattern = ""
        mapping = objectsMapping['file']['pattern']
        pe_mapping = "extensions.'windows-pebinary-ext'"
        for attribute in pe_object.attributes:
            try:
                stix_type = "{}.{}".format(pe_mapping, peMapping[attribute.object_relation])
            except KeyError:
                stix_type = "{}.{}'".format(pe_mapping[:-1], "x_misp_{}_{}".format(attribute.type, attribute.object_relation.replace('-', '_')))
            pattern += mapping.format(stix_type, attribute.value)
        n_section = 0
        for section in sections:
            section_mapping = "{}.sections[{}]".format(pe_mapping, str(n_section))
            for attribute in section.attributes:
                relation = attribute.object_relation
                if relation in misp_hash_types:
                    stix_type = "{}.hashes.'{}'".format(section_mapping, relation)
                    pattern += mapping.format(stix_type, attribute.value)
                else:
                    try:
                        stix_type = "{}.{}".format(section_mapping, peSectionMapping[relation])
                        pattern += mapping.format(stix_type, attribute.value)
                    except KeyError:
                        continue
            n_section += 1
        return pattern[:-5]

    def parse_galaxies(self, galaxies, source_id):
        for galaxy in galaxies:
            self.parse_galaxy(galaxy, source_id)

    def parse_galaxy(self, galaxy, source_id):
        galaxy_type = galaxy.get('type')
        galaxy_uuid = galaxy['GalaxyCluster'][0]['uuid']
        try:
            stix_type, to_call = self.galaxies_mapping[galaxy_type]
        except:
            return
        if galaxy_uuid not in self.galaxies:
            to_call(galaxy)
            self.galaxies.append(galaxy_uuid)
        self.relationships[source_id].append("{}--{}".format(stix_type, galaxy_uuid))

    @staticmethod
    def generate_galaxy_args(galaxy, b_killchain, b_alias, sdo_type):
        cluster = galaxy['GalaxyCluster'][0]
        sdo_id = "{}--{}".format(sdo_type, cluster.get('uuid'))
        description = "{} | {}".format(galaxy['description'], cluster['description'])
        labels = ['misp:name=\"{}\"'.format(galaxy['name'])]
        sdo_args = {'id': sdo_id, 'type': sdo_type, 'name': cluster['value'], 'description': description}
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
        return sdo_args, sdo_id

    def add_attack_pattern(self, galaxy):
        a_p_args, a_p_id = self.generate_galaxy_args(galaxy, True, False, 'attack-pattern')
        a_p_args['created_by_ref'] = self.identity_id
        attack_pattern = AttackPattern(**a_p_args)
        self.append_object(attack_pattern, a_p_id)

    def add_course_of_action(self, misp_object):
        coa_args, coa_id = self.generate_galaxy_args(misp_object, False, False, 'course-of-action')
        self.add_coa_stix_object(coa_args, coa_id)

    def add_course_of_action_from_object(self, misp_object, _):
        coa_id = 'course-of-action--{}'.format(misp_object.uuid)
        coa_args = {'id': coa_id, 'type': 'course-of-action'}
        for attribute in misp_object.attributes:
            self.parse_galaxies(attribute.Galaxy, coa_id)
            relation = attribute.object_relation
            if relation == 'name':
                coa_args['name'] = attribute.value
            elif relation == 'description':
                coa_args['description'] = attribute.value
        if not 'name' in coa_args:
            return
        self.add_coa_stix_object(coa_args, coa_id)

    def add_coa_stix_object(self, coa_args):
        coa_args['created_by_ref'] = self.identity_id
        course_of_action = CourseOfAction(**coa_args)
        self.append_object(course_of_action, coa_id)

    def add_custom(self, attribute):
        custom_object_id = "x-misp-object--{}".format(attribute.uuid)
        custom_object_type = "x-misp-object-{}".format(attribute.type.replace('|', '-').lower())
        labels = self.create_labels(attribute)
        custom_object_args = {'id': custom_object_id, 'x_misp_timestamp': attribute.timestamp, 'labels': labels,
                               'x_misp_value': attribute.value, 'created_by_ref': self.identity_id,
                               'x_misp_category': attribute.category}
        if hasattr(attribute, 'comment') and attribute.comment:
            custom_object_args['x_misp_comment'] = attribute.comment
        @CustomObject(custom_object_type, [('id', properties.StringProperty(required=True)),
                                          ('x_misp_timestamp', properties.StringProperty(required=True)),
                                          ('labels', properties.ListProperty(labels, required=True)),
                                          ('x_misp_value', properties.StringProperty(required=True)),
                                          ('created_by_ref', properties.StringProperty(required=True)),
                                          ('x_misp_comment', properties.StringProperty()),
                                          ('x_misp_category', properties.StringProperty())
                                         ])
        class Custom(object):
            def __init__(self, **kwargs):
                return
        custom_object = Custom(**custom_object_args)
        self.append_object(custom_object, custom_object_id)

    def add_identity(self, attribute):
        identity_id = "identity--{}".format(attribute.uuid)
        name = attribute.value
        labels = self.create_labels(attribute)
        identity_args = {'id': identity_id,  'type': identity, 'name': name, 'labels': labels,
                          'identity_class': 'individual', 'created_by_ref': self.identity_id}
        if hasattr(attribute, 'comment') and attribute.comment:
            identity_args['description'] = attribute.comment
        identity = Identity(**identity_args)
        self.append_object(identity, identity_id)

    def add_indicator(self, attribute):
        attribute_type = attribute.type
        indicator_id = "indicator--{}".format(attribute.uuid)
        self.parse_galaxies(attribute.Galaxy, indicator_id)
        category = attribute.category
        killchain = self.create_killchain(category)
        labels = self.create_labels(attribute)
        attribute_value = attribute.value if attribute_type != "AS" else self.define_attribute_value(attribute.value, attribute.comment)
        pattern = mispTypesMapping[attribute_type]['pattern'](attribute_type, attribute_value, b64encode(attribute.data.getbuffer()).decode()[1:-1]) if ('data' in attribute and attribute.data) else self.define_pattern(attribute_type, attribute_value)
        indicator_args = {'id': indicator_id, 'type': 'indicator', 'labels': labels, 'kill_chain_phases': killchain,
                           'valid_from': self.misp_event.date, 'created_by_ref': self.identity_id, 'pattern': pattern}
        if hasattr(attribute, 'Sighting'):
            for sighting in attribute.Sighting:
                if sighting['Organisation']['name'] == self.misp_event.Orgc.name and sighting['type'] == "2":
                    indicator_args['valid_until'] = datetime.datetime.fromtimestamp(int(sighting['date_sighting']), datetime.timezone.utc).isoformat()
                    break
        if hasattr(attribute, 'comment') and attribute.comment:
            indicator_args['description'] = attribute.comment
        indicator = Indicator(**indicator_args)
        self.append_object(indicator, indicator_id)

    def add_intrusion_set(self, galaxy):
        i_s_args, i_s_id = self.generate_galaxy_args(galaxy, False, True, 'intrusion-set')
        i_s_args['created_by_ref'] = self.identity_id
        intrusion_set = IntrusionSet(**i_s_args)
        self.append_object(intrusion_set, i_s_id)

    def add_malware(self, galaxy):
        malware_args, malware_id = self.generate_galaxy_args(galaxy, True, False, 'malware')
        malware_args['created_by_ref'] = self.identity_id
        malware = Malware(**malware_args)
        self.append_object(malware, malware_id)

    def add_observed_data(self, attribute):
        attribute_type = attribute.type
        observed_data_id = "observed-data--{}".format(attribute.uuid)
        self.parse_galaxies(attribute.Galaxy, observed_data_id)
        timestamp = attribute.timestamp
        labels = self.create_labels(attribute)
        attribute_value = attribute.value if attribute_type != "AS" else self.define_attribute_value(attribute.value, attribute.comment)
        observable = mispTypesMapping[attribute_type]['observable'](attribute_type, attribute_value, b64encode(attribute.data.getbuffer())) if 'data' in attribute else self.define_observable(attribute_type, attribute_value)
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data', 'number_observed': 1,
                              'first_observed': timestamp, 'last_observed': timestamp, 'labels': labels,
                              'created_by_ref': self.identity_id, 'objects': observable}
        observed_data = ObservedData(**observed_data_args)
        self.append_object(observed_data, observed_data_id)

    def add_threat_actor(self, galaxy):
        t_a_args,  t_a_id = self.generate_galaxy_args(galaxy, False, True, 'threat-actor')
        t_a_args['created_by_ref'] = self.identity_id
        threat_actor = ThreatActor(**t_a_args)
        self.append_object(threat_actor, t_a_id)

    def add_tool(self, galaxy):
        tool_args, tool_id = self.generate_galaxy_args(galaxy, True, False, 'tool')
        tool_args['created_by_ref'] = self.identity_id
        tool = Tool(**tool_args)
        self.append_object(tool, tool_id)

    def add_vulnerability(self, attribute):
        vulnerability_id = "vulnerability--{}".format(attribute.uuid)
        name = attribute.value
        vulnerability_data = [mispTypesMapping['vulnerability']['vulnerability_args'](name)]
        labels = self.create_labels(attribute)
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'name': name, 'external_references': vulnerability_data,
                              'created_by_ref': self.identity_id, 'labels': labels}
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability, vulnerability_id)

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
                              'description': description}
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability, vulnerability_id)

    def add_object_custom(self, misp_object, to_ids):
        custom_object_id = 'x-misp-object--{}'.format(misp_object.uuid)
        name = misp_object.name
        custom_object_type = 'x-misp-object-{}'.format(name)
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, to_ids)
        values = self.fetch_custom_values(misp_object.attributes, custom_object_id)
        custom_object_args = {'id': custom_object_id, 'x_misp_values': values, 'labels': labels,
                              'x_misp_category': category, 'created_by_ref': self.identity_id,
                              'x_misp_timestamp': misp_object.timestamp}
        if hasattr(misp_object, 'comment') and misp_object.comment:
            custom_object_args['x_misp_comment'] = misp_object.comment
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
        self.append_object(custom_object, custom_object_id)

    def add_object_indicator(self, misp_object, pattern_arg=None):
        indicator_id = 'indicator--{}'.format(misp_object.uuid)
        if pattern_arg:
            name = 'WindowsPEBinaryFile'
            pattern = pattern_arg
        else:
            name = misp_object.name
            pattern = self.objects_mapping[name]['pattern'](misp_object.attributes, indicator_id)
        category = misp_object.get('meta-category')
        killchain = self.create_killchain(category)
        labels = self.create_object_labels(name, category, True)
        indicator_args = {'id': indicator_id, 'valid_from': self.misp_event.date, 'type': 'indicator',
                          'labels': labels, 'description': misp_object.description,
                          'pattern': pattern, 'kill_chain_phases': killchain,
                          'created_by_ref': self.identity_id, 'allow_custom': True}
        indicator = Indicator(**indicator_args)
        self.append_object(indicator, indicator_id)

    def add_object_observable(self, misp_object, observable_arg=None):
        observed_data_id = 'observed-data--{}'.format(misp_object.uuid)
        if observable_arg:
            name = 'WindowsPEBinaryFile'
            observable_objects = observable_arg
        else:
            name = misp_object.name
            observable_objects = self.objects_mapping[name]['observable'](misp_object.attributes, observed_data_id)
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, False)
        timestamp = misp_object.timestamp
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data',
                              'number_observed': 1, 'labels': labels, 'objects': observable_objects,
                              'first_observed': timestamp, 'last_observed': timestamp,
                              'created_by_ref': self.identity_id, 'allow_custom': True}
        try:
            observed_data = ObservedData(**observed_data_args)
        except exceptions.InvalidValueError:
            observed_data = self.fix_enumeration_issues(name, observed_data_args)
        self.append_object(observed_data, observed_data_id)

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
                except exceptions.InvalidValueError:
                    current_dict[field] = enumeration_fails[field]
            for field in enumeration_fails:
                current_dict.pop(field)
            try:
                return ObservedData(**ns_args)
            except:
                pass
        return ObservedData(**args)

    def add_object_vulnerability(self, misp_object, to_ids):
        vulnerability_id = 'vulnerability--{}'.format(misp_object.uuid)
        name = self.fetch_vulnerability_name(misp_object.attributes)
        labels = self.create_object_labels(name, misp_object.get('meta-category'), to_ids)
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'name': name, 'created_by_ref': self.identity_id,
                              'labels': labels}
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability, vulnerability_id)

    def append_object(self, stix_object, stix_object_id):
        self.SDOs.append(stix_object)
        self.object_refs.append(stix_object_id)

    @staticmethod
    def create_killchain(category):
        return [{'kill_chain_name': 'misp-category', 'phase_name': category}]

    @staticmethod
    def create_labels(attribute):
        labels = ['misp:type="{}"'.format(attribute.type),
                  'misp:category="{}"'.format(attribute.category),
                  'misp:to_ids="{}"'.format(attribute.to_ids)]
        labels += [tag.name for tag in attribute.Tag]
        return labels

    @staticmethod
    def create_object_labels(name, category, to_ids):
        return ['misp:type="{}"'.format(name),
                'misp:category="{}"'.format(category),
                'misp:to_ids="{}"'.format(to_ids),
                'from_object']

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
            self.parse_galaxies(attribute.Galaxy, object_id)
            attribute_type = '{}_{}'.format(attribute.type, attribute.object_relation)
            values[attribute_type] = attribute.value
        return values

    @staticmethod
    def fetch_ids_flag(attributes):
        for attribute in attributes:
            if attribute.to_ids:
                return True
        return False

    @staticmethod
    def fetch_vulnerability_name(attributes):
        for attribute in attributes:
            if attribute.type == 'vulnerability':
                return attribute.value
        return "Undefined name"

    def resolve_asn_observable(self, attributes, object_id):
        asn = objectsMapping['asn']['observable']
        observable = {}
        object_num = 0
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            try:
                stix_type = asnObjectMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute.type, relation)
            attribute_value = attribute.value
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
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            try:
                stix_type = asnObjectMapping[relation]
            except KeyError:
                stix_type = "'x_misp_{}_{}'".format(attribute.type, relation)
            attribute_value = attribute.value
            if relation == "subnet-announced":
                pattern += "{0}:{1} = '{2}' AND ".format(define_address_type(attribute_value), stix_type, attribute_value)
            else:
                pattern += mapping.format(stix_type, attribute_value)
        return "[{}]".format(pattern[:-5])

    def resolve_domain_ip_observable(self, attributes, object_id):
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            if attribute.type == 'ip-dst':
                ip_value = attribute.value
            elif attribute.type == 'domain':
                domain_value = attribute.value
        domain_ip_value = "{}|{}".format(domain_value, ip_value)
        return mispTypesMapping['domain|ip']['observable']('', domain_ip_value)

    def resolve_domain_ip_pattern(self, attributes, object_id):
        mapping = objectsMapping['domain-ip']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            try:
                stix_type = domainIpObjectMapping[attribute.type]
            except:
                continue
            pattern += mapping.format(stix_type, attribute.value)
        return "[{}]".format(pattern[:-5])

    def resolve_email_object_observable(self, attributes, object_id):
        observable = {}
        message = defaultdict(list)
        reply_to = []
        object_num = 0
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            attribute_value = attribute.value
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
                elif relation == 'reply-to':
                    reply_to.append(attribute_value)
                elif relation == 'attachment':
                    object_str = str(object_num)
                    body = {"content_disposition": "{}; filename='{}'".format(relation, attribute_value),
                            "body_raw_ref": object_str}
                    message['body_multipart'].append(body)
                    observable[object_str] = {'type': 'file', 'name': attribute_value}
                    object_num += 1
                elif relation == 'x-mailer':
                    if 'additional_header_fields' in message:
                        message['additional_header_fields']['X-Mailer'] = attribute_value
                    else:
                        message['additional_header_fields'] = {'X-Mailer': attribute_value}
                else:
                    message[mapping] = attribute_value
            except:
                mapping = "x_misp_{}_{}".format(attribute.type, relation)
                if relation in ('eml', 'screenshot'):
                    message[mapping] = {'value': attribute_value, 'data': b64encode(attribute.data.getbuffer()).decode()[1:-1]}
                else:
                    message[mapping] = attribute_value
        if reply_to and 'additional_header_fields' in message:
            message['additional_header_fields']['Reply-To'] = reply_to
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
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            try:
                mapping = emailObjectMapping[relation]
                stix_type = mapping['stix_type']
                email_type = mapping['email_type']
            except:
                email_type = 'message'
                stix_type = "'x_misp_{}_{}'".format(attribute.type, relation)
                if relation in ('eml', 'screenshot'):
                    stix_type_data = "{}.data".format(stix_type)
                    pattern += pattern_mapping.format(email_type, stix_type_data, b64encode(attribute.data.getbuffer()).decode()[1:-1])
                    stix_type += ".value"
            pattern += pattern_mapping.format(email_type, stix_type, attribute.value)
        return "[{}]".format(pattern[:-5])

    def resolve_file_observable(self, attributes, object_id):
        observable = {}
        observable_file = defaultdict(dict)
        observable_file['type'] = 'file'
        malware_sample = {}
        d_observable = {}
        n_object = 0
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            attribute_type = attribute.type
            if attribute_type == 'malware-sample':
                filename, md5 = attribute.value.split('|')
                malware_sample['filename'] = filename
                malware_sample['md5'] = md5
                if attribute.data:
                    observable[str(n_object)] = {'type': 'artifact', 'payload_bin': b64encode(attribute.data.getbuffer())}
                    observable_file['content_ref'] = str(n_object)
                    n_object += 1
            elif attribute_type in ('filename', 'md5'):
                d_observable[attribute_type] = attribute.value
            elif attribute_type in misp_hash_types:
                observable_file['hashes'][attribute_type] = attribute.value
            else:
                try:
                    observable_type = fileMapping[attribute_type]
                except:
                    observable_type = "x_misp_{}_{}".format(attribute_type, attribute.object_relation)
                observable_file[observable_type] = attribute.value
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
            self.parse_galaxies(attribute.Galaxy, object_id)
            attribute_type = attribute.type
            if attribute_type == "malware-sample":
                filename, md5 = attribute.value.split('|')
                malware_sample['filename'] = filename
                malware_sample['md5'] = md5
                if attribute.data:
                    pattern += "{} AND ".format(attribute_data_pattern(b64encode(attribute.data.getbuffer()).decode()))
            elif attribute_type in ("filename", "md5"):
                d_pattern[attribute_type] = attribute.value
            else:
                try:
                    stix_type = fileMapping['hashes'].format(attribute_type) if attribute_type in misp_hash_types else fileMapping[attribute_type]
                except KeyError:
                    stix_type = "'x_misp_{}_{}'".format(attribute_type, attribute.object_relation)
                pattern += s_pattern.format(stix_type, attribute.value)
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
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            attribute_value = attribute.value
            if relation == 'ip':
                ip_address['type'] = define_address_type(attribute_value)
                ip_address['value'] = attribute_value
            elif relation == 'domain':
                domain['type'] = 'domain-name'
                domain['value'] = attribute_value
            else:
                try:
                    observable_type = ipPortObjectMapping[relation]
                except:
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
                except:
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
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            attribute_value = attribute.value
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
                except:
                    continue
            pattern += objectsMapping[mapping_type]['pattern'].format(stix_type, attribute_value)
        return "[{}]".format(pattern[:-5])

    def resolve_network_socket_observable(self, attributes, object_id):
        observable, socket_extension = {}, {}
        network_object = defaultdict(list)
        network_object['type'] = 'network-traffic'
        n = 0
        ip_src, ip_dst, domain_src, domain_dst = [None] * 4
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            if relation in ('address-family', 'domain-family'):
                socket_extension[networkSocketMapping[relation]] = attribute.value
            elif relation == 'state':
                state_type = "is_{}".format(attribute.value)
                socket_extension[state_type] = True
            elif relation == 'protocol':
                network_object['protocols'].append(attribute.value)
            elif relation == 'ip-src': ip_src = attribute.value
            elif relation == 'ip-dst': ip_dst = attribute.value
            elif relation == 'hostname-src': domain_src = attribute.value
            elif relation == 'hostname-dst': domain_dst = attribute.value
            else:
                try:
                    network_object[networkSocketMapping[relation]] = attribute.value
                except:
                    continue
        if ip_src is not None:
            str_n = str(n)
            observable[str_n] = {'type': define_address_type(ip_src), 'value': ip_src}
            network_object['src_ref'] = str_n
            n += 1
        elif domain_src is not None:
            str_n = str(n)
            observable[str_n] = {'type': 'domain-name', 'value': domain_src}
            network_object['src_ref'] = str_n
            n += 1
        if ip_dst is not None:
            str_n = str(n)
            observable[str_n] = {'type': define_address_type(ip_dst), 'value': ip_dst}
            network_object['dst_ref'] = str_n
            n += 1
        elif domain_dst is not None:
            str_n = str(n)
            observable[str_n] = {'type': 'domain-name', 'value': domain_dst}
            network_object['dst_ref'] = str_n
            n += 1
        if socket_extension: network_object['extensions'] = {'socket-ext': socket_extension}
        observable[str(n)] = network_object
        return observable

    def resolve_network_socket_pattern(self, attributes, object_id):
        mapping = objectsMapping['network-socket']['pattern']
        pattern = ""
        stix_type = "extensions.'socket-ext'.{}"
        ip_src, ip_dst, domain_src, domain_dst = [None] * 4
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            attribute_value = attribute.value
            if relation in ('address-family', 'domain-family'):
                pattern += mapping.format(stix_type.format(networkSocketMapping[relation]), attribute_value)
            elif relation == 'state':
                state_type = "is_{}".format(attribute_value)
                pattern += mapping.format(stix_type.format(state_type), True)
            elif relation == 'protocol':
                pattern += "network-traffic:{0}[0] = '{1}' AND ".format(networkSocketMapping[relation], attribute_value)
            elif relation == 'ip-src':
                ip_src = mapping.format(networkSocketMapping[relation].format(define_address_type(attribute_value)), attribute_value)
            elif relation == 'ip-dst':
                ip_dst = mapping.format(networkSocketMapping[relation].format(define_address_type(attribute_value)), attribute_value)
            elif relation == 'hostname-src':
                domain_src = mapping.format(networkSocketMapping[relation].format('domain-name'), attribute_value)
            elif relation == 'hostname-dst':
                domain_dst = mapping.format(networkSocketMapping[relation].format('domain-name'), attribute_value)
            else:
                try:
                    pattern += mapping.format(networkSocketMapping[relation], attribute_value)
                except:
                    continue
        if ip_src is not None: pattern += ip_src
        elif domain_src is not None: pattern += domain_src
        if ip_dst is not None: pattern += ip_dst
        elif domain_dst is not None: pattern += domain_dst
        return "[{}]".format(pattern[:-5])

    def resolve_process_observable(self, attributes, object_id):
        observable = {}
        current_process = defaultdict(list)
        current_process['type'] = 'process'
        n = 0
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            if relation == 'parent-pid':
                str_n = str(n)
                try:
                    observable[str_n] = self.processes[attribute.value]
                except:
                    continue
                current_process['parent_ref'] = str_n
                n += 1
            elif relation == 'child-pid':
                str_n = str(n)
                try:
                    observable[str_n] = self.processes[attribute.value]
                except:
                    continue
                current_process['child_refs'].append(str_n)
                n += 1
            else:
                try:
                    current_process[processMapping[relation]] = attribute.value
                except:
                    pass
        observable[str(n)] = current_process
        return observable

    def resolve_process_pattern(self, attributes, object_id):
        mapping = objectsMapping['process']['pattern']
        pattern = ""
        child_refs = []
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            if relation == 'parent-pid':
                pattern += mapping.format('parent_ref', attribute.value)
            elif relation == 'child-pid':
                child_refs.append(attribute.value)
            else:
                try:
                    pattern += mapping.format(processMapping[relation], attribute.value)
                except:
                    continue
        if child_refs: pattern += mapping.format('child_refs', child_refs)
        return "[{}]".format(pattern[:-5])

    def resolve_regkey_observable(self, attributes, object_id):
        observable = {'type': 'windows-registry-key'}
        values = {}
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            try:
                stix_type = regkeyMapping[relation]
            except KeyError:
                stix_type = "x_misp_{}_{}".format(attribute.type, relation)
            if relation in ('data', 'data-type', 'name'):
                values[stix_type] = attribute.value
            else:
                observable[stix_type] = attribute.value
        if values:
            observable['values'] = [values]
        return {'0': observable}

    def resolve_regkey_pattern(self, attributes, object_id):
        mapping = objectsMapping['registry-key']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            try:
                stix_type = regkeyMapping[attribute.object_relation]
            except:
                stix_type = "'x_misp_{}_{}'".format(attribute.type, attribute.object_relation)
            pattern += mapping.format(stix_type, attribute.value)
        return "[{}]".format(pattern[:-5])

    @staticmethod
    def resolve_stix2_pattern(attributes):
        for attribute in attributes:
            if attribute.object_relation == 'stix2-pattern':
                return attribute.value

    def resolve_url_observable(self, attributes, object_id):
        url_args = {}
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            if attribute.type == 'url':
                # If we have the url (WE SHOULD), we return the observable supported atm with the url value
                observable = {'0': {'type': 'url', 'value': attribute.value}}
            else:
                # otherwise, we need to see if there is a port or domain value to parse
                url_args[attribute.type] = attribute.value
        if 'domain' in url_args:
            observable['1'] = {'type': 'domain-name', 'value': url_args['domain']}
        if 'port' in url_args:
            port_value = url_args['port']
            port = {'type': 'network-traffic', 'dst_ref': '1', 'protocols': ['tcp'], 'dst_port': port_value}
            try:
                port['protocols'].append(defineProtocols[port_value])
            except:
                pass
            if '1' in observable:
                observable['2'] = port
            else:
                observable['1'] = port
        return observable

    def resolve_url_pattern(self, attributes, object_id):
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            attribute_type = attribute.type
            try:
                stix_type = urlMapping[attribute_type]
            except:
                continue
            if attribute_type == 'port':
                mapping = 'ip-port'
            elif attribute_type == 'domain':
                mapping = 'domain-ip'
            else:
                mapping = attribute_type
            pattern += objectsMapping[mapping]['pattern'].format(stix_type, attribute.value)
        return "[{}]".format(pattern[:-5])

    def resolve_x509_observable(self, attributes, object_id):
        observable = {'type': 'x509-certificate'}
        hashes = {}
        attributes2parse = defaultdict(list)
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            if relation in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                hashes[relation.split('-')[2]] = attribute.value
            else:
                try:
                    observable[x509mapping[relation]] = attribute.value
                except KeyError:
                    value = bool(attribute.value) if attribute.type == 'boolean' else attribute.value
                    attributes2parse["x_misp_{}_{}".format(attribute.type, relation)].append(value)
        if hashes:
            observable['hashes'] = hashes
        for stix_type, value in attributes2parse.items():
            observable[stix_type] = value if len(value) > 1 else value[0]
        return {'0': observable}

    def resolve_x509_pattern(self, attributes, object_id):
        mapping = objectsMapping['x509']['pattern']
        pattern = ""
        for attribute in attributes:
            self.parse_galaxies(attribute.Galaxy, object_id)
            relation = attribute.object_relation
            if relation in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                stix_type = fileMapping['hashes'].format(relation.split('-')[2])
            else:
                try:
                    stix_type = x509mapping[relation]
                except KeyError:
                    stix_type = "'x_misp_{}_{}'".format(attribute.type, relation)
            value = bool(attribute.value) if attribute.type == 'boolean' else attribute.value
            pattern += mapping.format(stix_type, value)
        return "[{}]".format(pattern[:-5])

    @staticmethod
    def define_attribute_value(value, comment):
        if value.isdigit() or value.startswith("AS"):
            return int(value) if value.isdigit() else int(value[2:].split(' ')[0])
        if comment.startswith("AS") or comment.isdigit():
            return int(comment) if comment.isdigit() else int(comment[2:].split(' ')[0])

def main(args):
    stix_builder = StixBuilder()
    stix_builder.loadEvent(args)
    stix_builder.buildEvent()
    stix_builder.saveFile()

if __name__ == "__main__":
    main(sys.argv)
