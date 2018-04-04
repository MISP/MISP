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

import sys, json, os, datetime, re, base64
import pymisp
from stix2 import *
from misp2stix2_mapping import *
from collections import defaultdict

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email',
                            'target-machine', 'target-org', 'target-location', 'target-external',
                            'vulnerability', 'attachment']

misp_hash_types = ["authentihash", "ssdeep", "imphash", "md5", "sha1", "sha224",
                   "sha256", "sha384", "sha512", "sha512/224","sha512/256","tlsh"]

class StixBuilder():
    def __init__(self):
        self.misp_event = pymisp.MISPEvent()
        self.SDOs = []
        self.object_refs = []
        self.external_refs = []

    def loadEvent(self, pathname, args):
        filename = os.path.join(pathname, args[1])
        self.misp_event.load_file(filename)
        self.filename = filename

    def buildEvent(self):
        self.__set_identity()
        self.read_attributes()
        report = self.eventReport()
        self.SDOs.insert(1, report)
        self.stix_package = self.generate_package()

    def eventReport(self):
        report_args = {'type': 'report', 'id': 'report--{}'.format(self.misp_event.uuid),
                       'created_by_ref': self.identity_id, 'name': self.misp_event.info,
                       'published': self.misp_event.publish_timestamp,
                       'object_refs': self.object_refs}
        labels = []
        if self.misp_event.Tag:
            for tag in self.misp_event.Tag:
                labels.append(tag.name)
        if labels:
            report_args['labels'] = labels
        else:
            report_args['labels'] = ['Threat-Report']
        report_args['labels'].append('misp:tool="misp2stix2"')
        if self.external_refs:
            report_args['external_references'] = external_refs
        return Report(**report_args)

    def generate_package(self):
        bundle_args = {"type": "bundle", "spec_version": "2.0", "objects": self.SDOs,
                       "id": "bundle--{}".format(self.misp_event.uuid)}
        return Bundle(**bundle_args)

    def saveFile(self):
        outputfile = "{}.out".format(self.filename)
        with open(outputfile, 'w') as f:
            f.write(json.dumps(self.stix_package, cls=base.STIXJSONEncoder))

    def __set_identity(self):
        org = self.misp_event.Orgc
        identity_id = 'identity--{}'.format(org['uuid'])
        identity = Identity(type="identity", id=identity_id,
                            name=org["name"], identity_class="organization")
        self.SDOs.append(identity)
        self.identity_id = identity_id

    def misp_types(self):
        describe_types_filename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
        describe_types = open(describe_types_filename, 'r')
        self.categories_mapping = json.loads(describe_types.read())['result']['category_type_mappings']

    def read_attributes(self):
        self.misp_types()
        if hasattr(self.misp_event, 'attributes') and self.misp_event.attributes:
            for attribute in self.misp_event.attributes:
                attribute_type = attribute.type
                if attribute_type in non_indicator_attributes:
                    self.handle_non_indicator(attribute, attribute_type)
                else:
                    if attribute_type in self.categories_mapping['Person']:
                        self.handle_person(attribute)
                    elif attribute_type in mispTypesMapping:
                        self.handle_usual_type(attribute)
                    else:
                        self.add_custom(attribute)
        if hasattr(self.misp_event, 'objects') and self.misp_event.objects:
            self.load_objects_mapping()
            for misp_object in self.misp_event.objects:
                object_attributes = misp_object.attributes
                to_ids = self.fetch_ids_flag(object_attributes)
                object_name = misp_object.name
                if object_name == "vulnerability":
                    self.add_object_vulnerability(misp_object, to_ids)
                elif object_name in objectsMapping:
                    if to_ids:
                        self.add_object_indicator(misp_object, to_ids)
                    else:
                        self.add_object_observable(misp_object, to_ids)
                else:
                    self.add_object_custom(misp_object, to_ids)
        if hasattr(self.misp_event, 'Galaxy') and self.misp_event.Galaxy:
            for galaxy in self.misp_event.Galaxy:
                galaxy_type = galaxy.get('type')
                if 'attack-pattern' in galaxy_type:
                    self.add_attack_pattern(galaxy)
                elif 'course' in galaxy_type:
                    self.add_course_of_action(galaxy)
                elif 'intrusion' in galaxy_type:
                    self.add_intrusion_set(galaxy)
                elif 'ware' in galaxy_type:
                    self.add_malware(galaxy)
                elif galaxy_type in ['threat-actor', 'microsoft-activity-group']:
                    self.add_threat_actor(galaxy)
                elif galaxy_type in ['rat', 'exploit-kit'] or 'tool' in galaxy_type:
                    self.add_tool(galaxy)

    def load_objects_mapping(self):
        self.objects_mapping = {
            'domain-ip': {'observable': self.resolve_domain_ip_observable,
                          'pattern': self.resolve_domain_ip_pattern},
            'email': {'observable': self.resolve_email_object_observable,
                      'pattern': self.resolve_email_object_pattern},
            'file': {'observable': self.resolve_file_observable,
                     'pattern': self.resolve_file_pattern},
            'ip-port': {'observable': self.resolve_ip_port_observable,
                        'pattern': self.resolve_ip_port_pattern},
            'registry-key': {'observable': self.resolve_regkey_observable,
                             'pattern': self.resolve_regkey_pattern},
            'url': {'observable': self.resolve_url_observable,
                    'pattern': self.resolve_url_pattern},
            'x509': {'observable': self.resolve_x509_observable,
                     'pattern': self.resolve_x509_pattern}
        }

    def handle_non_indicator(self, attribute, attribute_type):
        if attribute_type == "link":
            self.handle_link(attribute)
        elif attribute_type in ('text', 'comment', 'other') or attribute_type not in mispTypesMapping:
            self.add_custom(attribute)
        else:
            try:
                self.handle_non_indicator_attribute(attribute, attribute_type)
            except:
                self.add_custom(attribute)

    def handle_non_indicator_attribute(self, attribute, attribute_type):
        if attribute_type == "vulnerability":
            self.add_vulnerability(attribute)
        else:
            self.add_observed_data(attribute)

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

    @staticmethod
    def generate_galaxy_args(galaxy, b_killchain, b_alias, sdo_type):
        galaxy_type = galaxy.get('type')
        name = galaxy.get('name')
        cluster = galaxy['GalaxyCluster'][0]
        sdo_id = "{}--{}".format(sdo_type, cluster.get('uuid'))
        description = "{} | {}".format(galaxy.get('description'), cluster.get('description'))
        labels = ['misp:type=\"{}\"'.format(galaxy_type)]
        sdo_args = {'id': sdo_id, 'type': sdo_type, 'name': name, 'description': description}
        if b_killchain:
            killchain = [{'kill_chain_name': 'misp-category',
                          'phase_name': galaxy_type}]
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

    def add_course_of_action(self, galaxy):
        c_o_a_args, c_o_a_id = self.generate_galaxy_args(galaxy, False, False, 'course-of-action')
        c_o_a_args['created_by_ref'] = self.identity_id
        course_of_action = CourseOfAction(**c_o_a_args)
        self.append_object(course_of_action, c_o_a_id)

    def add_custom(self, attribute):
        custom_object_id = "x-misp-object--{}".format(attribute.uuid)
        custom_object_type = "x-misp-object-{}".format(attribute.type)
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
        indicator_id = "indicator--{}".format(attribute.uuid)
        category = attribute.category
        killchain = self.create_killchain(category)
        labels = self.create_labels(attribute)
        indicator_args = {'id': indicator_id, 'type': 'indicator', 'labels': labels, 'kill_chain_phases': killchain,
                           'valid_from': attribute.timestamp, 'created_by_ref': self.identity_id,
                           'pattern': [self.define_pattern(attribute.type, attribute.value)]}
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
        observed_data_id = "observed-data--{}".format(attribute.uuid)
        timestamp = attribute.timestamp
        labels = self.create_labels(attribute)
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data', 'number_observed': 1,
                              'first_observed': timestamp, 'last_observed': timestamp, 'labels': labels,
                              'created_by_ref': self.identity_id,
                              'objects': self.define_observable(attribute.type, attribute.value)}
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
        vulnerability_data = mispTypesMapping['vulnerability'](name)
        labels = self.create_labels(attribute)
        vulnerability_args = {'id': vulnerability_id, 'type': 'vulnerability',
                              'name': name, 'external_references': [vulnerability_data],
                              'created_by_ref': self.identity_id, 'labels': labels}
        vulnerability = Vulnerability(**vulnerability_args)
        self.append_object(vulnerability, vulnerability_id)

    def add_object_custom(self, misp_object, to_ids):
        custom_object_id = 'x-misp-object--{}'.format(misp_object.uuid)
        name = misp_object.name
        custom_object_type = 'x-misp-object--{}'.format(name)
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, to_ids)
        values = self.fetch_custom_values(misp_object.attributes)
        timestamp = self.get_date_from_timestamp(int(misp_object.timestamp))
        custom_object_args = {'id': custom_object_id, 'x_misp_values': values,
                              'x_misp_category': category, 'created_by_ref': self.identity_id,
                              'x_misp_timestamp': timestamp}
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

    def add_object_indicator(self, misp_object, to_ids):
        indicator_id = 'indicator--{}'.format(misp_object.uuid)
        name = misp_object.name
        category = misp_object.get('meta-category')
        killchain = self.create_killchain(category)
        labels = self.create_object_labels(name, category, to_ids)
        pattern = self.define_object_pattern(name, misp_object.attributes)
        timestamp = self.get_date_from_timestamp(int(misp_object.timestamp))
        indicator_args = {'id': indicator_id, 'valid_from': timestamp, 'type': 'indicator',
                          'labels': labels, 'description': misp_object.description,
                          'pattern': [pattern], 'kill_chain_phases': killchain,
                          'created_by_ref': self.identity_id}
        indicator = Indicator(**indicator_args)
        self.append_object(indicator, indicator_id)

    def add_object_observable(self, misp_object, to_ids):
        observed_data_id = 'observed-data--{}'.format(misp_object.uuid)
        name = misp_object.name
        category = misp_object.get('meta-category')
        labels = self.create_object_labels(name, category, to_ids)
        observable_objects = self.define_object_observable(name, misp_object.attributes)
        timestamp = self.get_date_from_timestamp(int(misp_object.timestamp))
        observed_data_args = {'id': observed_data_id, 'type': 'observed-data',
                              'number_observed': 1, 'labels': labels, 'objects': observable_objects,
                              'first_observed': timestamp, 'last_observed': timestamp,
                              'created_by_ref': self.identity_id}
        observed_data = ObservedData(**observed_data_args)
        self.append_object(observed_data, observed_data_id)

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
        return ['misp:type="{}"'.format(attribute.type),
                'misp:category="{}"'.format(attribute.category),
                'misp:to_ids="{}"'.format(attribute.to_ids)]

    @staticmethod
    def create_object_labels(name, category, to_ids):
        return ['misp:type="{}"'.format(name),
                'misp:category="{}"'.format(category),
                'misp:to_ids="{}"'.format(to_ids),
                'from_object']

    @staticmethod
    def define_address_type(value):
        if ':' in value:
            return 'ipv6-addr'
        else:
            return 'ipv4-addr'

    @staticmethod
    def define_observable(attribute_type, attribute_value):
        if attribute_type == 'malware-sample':
            return mispTypesMapping[attribute_type]['observable']('filename|md5', attribute_value)
        observable = mispTypesMapping[attribute_type]['observable'](attribute_type, attribute_value)
        if 'port' in attribute_type:
            try:
                observable['0']['protocols'].append(defineProtocols[attribute_value] if attribute_value in defineProtocols else "tcp")
            except AttributeError:
                observable['1']['protocols'].append(defineProtocols[attribute_value] if attribute_value in defineProtocols else "tcp")
        return observable

    def define_object_observable(self, name, attributes):
        return self.objects_mapping[name]['observable'](attributes)

    @staticmethod
    def define_pattern(attribute_type, attribute_value):
        attribute_value = attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')
        if attribute_type == 'malware-sample':
            return [mispTypesMapping[attribute_type]['pattern']('filename|md5', attribute_value)]
        return mispTypesMapping[attribute_type]['pattern'](attribute_type, attribute_value)

    def define_object_pattern(self, name, attributes):
        return self.objects_mapping[name]['pattern'](attributes)

    @staticmethod
    def fetch_custom_values(attributes):
        values = {}
        for attribute in attributes:
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

    @staticmethod
    def get_date_from_timestamp(timestamp):
        return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=timestamp)

    @staticmethod
    def resolve_domain_ip_observable(attributes):
        for attribute in attributes:
            if attribute.type == 'ip-dst':
                ip_value = attribute.value
            elif attribute.type == 'domain':
                domain_value = attribute.value
        domain_ip_value = "{}|{}".format(domain_value, ip_value)
        return mispTypesMapping['domain|ip']['observable']('', domain_ip_value)

    @staticmethod
    def resolve_domain_ip_pattern(attributes):
        pattern = ""
        for attribute in attributes:
            try:
                stix_type = domainIpObjectMapping[attribute.type]
            except:
                continue
            pattern += objectsMapping['domain-ip']['pattern'].format(stix_type, attribute.value)
        return pattern[:-5]

    @staticmethod
    def resolve_email_object_observable(attributes):
        observable = {}
        message = defaultdict(list)
        reply_to = []
        object_num = 0
        for attribute in attributes:
            attribute_type = attribute.type
            attribute_value = attribute.value
            try:
                mapping = emailObjectMapping[attribute_type]
            except:
                continue
            if attribute_type in ('email-src', 'email-dst'):
                object_str = str(object_num)
                observable[object_str] = {'type': 'email-addr', 'value': attribute_value}
                try:
                    message[mapping['stix_type'][attribute.object_relation]].append(object_str)
                except:
                    message[mapping['stix_type']] = object_str
                object_num += 1
            elif attribute_type == 'email-reply-to':
                reply_to.append(attribute_value)
            elif attribute_type == 'email-attachment':
                object_str = str(object_num)
                body = {"content_disposition": "attachment; filename='{}'".format(attribute_value),
                                  "body_raw_ref": object_str}
                message['body_multipart'].append(body)
                observable[object_str] = {'type': 'file', 'name': attribute_value}
                object_num += 1
            elif attribute_type == 'email-x-mailer':
                if 'additional_header_fields' in message:
                    message['additional_header_fields']['X-Mailer'] = attribute_value
                else:
                    message['additional_header_fields'] = {'X-Mailer': attribute_value}
            else:
                message[mapping['stix_type']] = attribute_value
        if reply_to and 'additional_header_fields' in message:
            message['additional_header_fields']['Reply-To'] = reply_to
        message['type'] = 'email-message'
        if 'body_multipart' in message:
            message['is_multipart'] = True
        else:
            message['is_multipart'] = False
        observable[str(object_num)] = dict(message)
        return observable

    @staticmethod
    def resolve_email_object_pattern(attributes):
        pattern = ""
        for attribute in attributes:
            try:
                mapping = emailObjectMapping[attribute.type]
            except:
                continue
            try:
                stix_type = mapping['stix_type'][attribute.object_relation]
            except:
                stix_type = mapping['stix_type']
            pattern += objectsMapping['email']['pattern'].format(mapping['email_type'], stix_type, attribute.value)
        return pattern[:-5]

    @staticmethod
    def resolve_file_observable(attributes):
        observable = defaultdict(dict)
        observable['type'] = 'file'
        for attribute in attributes:
            attribute_type = attribute.type
            if attribute_type in misp_hash_types:
                observable['hashes'][attribute_type.upper()] = attribute.value
            else:
                try:
                    observable_type = fileMapping[attribute_type]
                except:
                    continue
                observable[observable_type] = attribute.value
        return {'0': dict(observable)}

    @staticmethod
    def resolve_file_pattern(attributes):
        pattern = ""
        d_pattern = {}
        s_pattern = objectsMapping['file']['pattern']
        malware_sample = {}
        for attribute in attributes:
            attribute_type = attribute.type
            attribute_value = attribute.value
            if attribute_type == "malware-sample":
                filename, md5 = attribute_value.slit('|')
                malware_sample['filename'] = filename
                malware_sample['md5'] = md5
            else:
                d_pattern[attribute_type] = attribute_value
        if malware_sample:
            if not('md5' in d_pattern and 'filename' in d_pattern and d_pattern['md5'] == malware_sample['md5'] and d_pattern['filename'] == malware_sample['filename']):
                filename_pattern = s_pattern.format('name', malware_sample['filename'])
                md5_pattern = s_pattern.format(fileMapping['hashes'].format('md5'), malware_sample['md5'])
                pattern += "{}{}".format(filename_pattern, md5_pattern)
        for p in d_pattern:
            if p in misp_hash_types:
                stix_type = fileMapping['hashes'].format(p)
            else:
                try:
                    stix_type = fileMapping[p]
                except:
                    continue
            pattern += s_pattern.format(stix_type, d_pattern[p])
        return pattern[:-5]

    def resolve_ip_port_observable(self, attributes):
        observable = {'type': 'network-traffic', 'protocols': ['tcp']}
        ip_address = {}
        domain = {}
        for attribute in attributes:
            attribute_type = attribute.type
            attribute_value = attribute.value
            if attribute_type == 'ip-dst':
                ip_address['type'] = self.define_address_type(attribute_value)
                ip_address['value'] = attribute_value
            elif attribute_type == 'domain':
                domain['type'] = 'domain-name'
                domain['value'] = attribute_value
            else:
                try:
                    observable_type = ipPortObjectMapping[attribute_type][attribute.object_relation]
                except:
                    continue
                observable[observable_type] = attribute_value
        if 'src_port' in observable or 'dst_port' in observable:
            for port in ('src_port', 'dst_port'):
                try:
                    port_value = defineProtocols[str(observable[port])]
                    if port_value not in observable['protocols']:
                        observable['protocols'].append(port_value)
                except:
                    pass
            return self.ip_port_observable_to_return(ip_address, observable, 'dst_ref')
        elif domain:
            return self.ip_port_observable_to_return(ip_address, domain, 'resolves_to_refs')
        return {'0': ip_address}

    @staticmethod
    def ip_port_observable_to_return(ip_address, d_object, s_object):
        if ip_address:
            d_object[s_object] = '0'
            return {'0': ip_address, '1': d_object}
        return {'0': d_object}

    def resolve_ip_port_pattern(self, attributes):
        pattern = ""
        for attribute in attributes:
            attribute_type = attribute.type
            attribute_value = attribute.value
            if attribute_type == 'domain':
                pattern += objectsMapping['domain-ip']['pattern'].format(ipPortObjectMapping[attribute_type], attribute_value)
            else:
                try:
                    try:
                        stix_type = ipPortObjectMapping[attribute_type][attribute.object_relation]
                    except:
                        stix_type = ipPortObjectMapping[attribute_type].format(self.define_address_type(attribute_value))
                except:
                    continue
                pattern += objectsMapping['ip-port']['pattern'].format(stix_type, attribute_value)
        return pattern[:-5]

    @staticmethod
    def resolve_regkey_observable(attributes):
        observable = {'0': {'type': 'windows-registry-key'}}
        values = {}
        for attribute in attributes:
            attribute_type = attribute.type
            if attribute_type == 'text':
                values[regkeyMapping[attribute_type][attribute.object_relation]] = attribute.value
            else:
                try:
                    observable['0'][regkeyMapping[attribute_type]] = attribute.value
                except:
                    pass
        if values:
            observable['0']['values'] = [values]
        return observable

    @staticmethod
    def resolve_regkey_pattern(attributes):
        pattern = ""
        for attribute in attributes:
            attribute_type = attribute.type
            try:
                try:
                    stix_type = regkeyMapping[attribute_type][attribute.object_relation]
                except:
                    stix_type = regkeyMapping[attribute_type]
            except:
                continue
            pattern += objectsMapping['registry-key']['pattern'].format(stix_type, attribute.value)
        return pattern[:-5]

    @staticmethod
    def resolve_url_observable(attributes):
        url_args = {}
        for attribute in attributes:
            if attribute.type == 'url':
                # If we have the url (WE SHOULD), we return the observable supported atm with the url value
                return {'0': {'type': 'url', 'value': attribute.value}}
            else:
                # otherwise, we need to see if there is a port or domain value to parse
                url_args[attribute.type] = attribute.value
        observable = {}
        if 'domain' in url_args:
            observable['0'] = {'type': 'domain-name', 'value': url_args['domain']}
        if 'port' in url_args:
            port_value = url_args['port']
            port = {'type': 'network-traffic', 'dst_ref': '0', 'protocols': ['tcp'], 'dst_port': port_value}
            try:
                port['protocols'].append(defineProtocols[port_value])
            except:
                pass
            if observable:
                observable['1'] = port
            else:
                observable['0'] = port
        return observable

    @staticmethod
    def resolve_url_pattern(attributes):
        pattern = ""
        for attribute in attributes:
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
        return pattern[:-5]

    @staticmethod
    def resolve_x509_observable(attributes):
        observable = {'0': {'type': 'x509-certificate'}}
        hashes = {}
        for attribute in attributes:
            attribute_type = attribute.type
            if attribute_type in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                h_type = attribute_type.split('-')[2]
                hashes[h_type] = attribute.value
            else:
                try:
                    observable['0'][x509mapping[attribute_type][attribute.object_relation]] = attribute.value
                except:
                    pass
        if hashes:
            observable['0']['hashes'] = hashes
        return observable

    @staticmethod
    def resolve_x509_pattern(attributes):
        pattern = ""
        for attribute in attributes:
            attribute_type = attribute.type
            if attribute_type in ("x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256"):
                h_type = attribute_type.split('-')[2]
                stix_type = fileMapping['hashes'].format(h_type)
            else:
                try:
                    stix_type = x509mapping[attribute_type][attribute.object_relation]
                except:
                    continue
            pattern += objectsMapping['x509']['pattern'].format(stix_type, attribute.value)
        return pattern[:-5]

def main(args):
    pathname = os.path.dirname(args[0])
    stix_builder = StixBuilder()
    stix_builder.loadEvent(pathname, args)
    stix_builder.buildEvent()
    stix_builder.saveFile()
    print(1)

if __name__ == "__main__":
    main(sys.argv)
