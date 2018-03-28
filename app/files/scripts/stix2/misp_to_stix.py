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
from misp2stix2_dictionaries import *
from collections import defaultdict

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email',
                            'target-machine', 'target-org', 'target-location', 'target-external',
                            'vulnerability', 'attachment']

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
            if attribute.comment:
                source += " - {}".format(attribute.comment)
        except AttributeError:
            pass
        link = {'source_name': source, 'url': url}
        self.external_refs.append(link)

    def add_custom(self, attribute):
        custom_object_id = "x-misp-object--{}".format(attribute.uuid)
        custom_object_type = "x-misp-object-{}".format(attribute.type)
        labels = self.create_labels(attribute)
        custom_object_args = {'id': custom_object_id, 'x_misp_timestamp': attribute.timestamp, 'labels': labels,
                               'x_misp_value': attribute.value, 'created_by_ref': self.identity_id,
                               'x_misp_category': attribute.category}
        if attribute.comment:
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
        if attribute.comment:
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
                           'pattern': self.define_pattern(attribute.type, attribute.value)}
        if attribute.comment:
            indicator_args['description'] = attribute.comment
        indicator = Indicator(**indicator_args)
        self.append_object(indicator, indicator_id)

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

    def append_object(self, stix_object, stix_object_id):
        self.SDOs.append(stix_object)
        self.object_refs.append(stix_object_id)

    @staticmethod
    def create_killchain(name):
        return [{'kill_chain_name': 'misp-category', 'phase_name': name}]

    @staticmethod
    def create_labels(attribute):
        return ['misp:type="{}"'.format(attribute.type),
                'misp:category="{}"'.format(attribute.category),
                'misp:to_ids="{}"'.format(attribute.to_ids)]

    @staticmethod
    def define_address_type(value):
        if ':' in value:
            return 'ipv6-addr'
        else:
            return 'ipv4:addr'

    def define_observable(self, attribute_type, attribute_value):
        if attribute_type == 'malware-sample':
            return mispTypesMapping[attribute_type]['observable']('filename|md5', attribute_value)
        observable = mispTypesMapping[attribute_type]['observable'](attribute_type, attribute_value)
        if 'port' in attribute_type:
            try:
                observable['0']['protocols'].append(defineProtocols[attribute_value] if attribute_value in defineProtocols else "tcp")
            except AttributeError:
                observable['1']['protocols'].append(defineProtocols[attribute_value] if attribute_value in defineProtocols else "tcp")
        return observable

    def define_pattern(self, attribute_type, attribute_value):
        attribute_value = attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')
        if attribute_type == 'malware-sample':
            return [mispTypesMapping[attribute_type]['pattern']('filename|md5', attribute_value)]
        return [mispTypesMapping[attribute_type]['pattern'](attribute_type, attribute_value)]

def main(args):
    pathname = os.path.dirname(args[0])
    stix_builder = StixBuilder()
    stix_builder.loadEvent(pathname, args)
    stix_builder.buildEvent()
    stix_builder.saveFile()
    print(1)

if __name__ == "__main__":
    main(sys.argv)
