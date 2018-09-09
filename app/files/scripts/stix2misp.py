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
import base64
import stix2misp_mapping
from operator import attrgetter
from pymisp import MISPEvent, MISPObject, MISPAttribute, __path__
from stix.core import STIXPackage
from collections import defaultdict

cybox_to_misp_object = {"Account": "credential", "AutonomousSystem": "asn",
                        "EmailMessage": "email", "NetworkConnection": "network-connection",
                        "NetworkSocket": "network-socket", "Process": "process",
                        "x509Certificate": "x509", "Whois": "whois"}

threat_level_mapping = {'High': '1', 'Medium': '2', 'Low': '3', 'Undefined': '4'}

descFilename = os.path.join(__path__[0], 'data/describeTypes.json')
with open(descFilename, 'r') as f:
    categories = json.loads(f.read())['result'].get('categories')

class StixParser():
    def __init__(self):
        self.misp_event = MISPEvent()
        self.misp_event['Galaxy'] = []
        self.references = defaultdict(list)
        self.dns_objects = defaultdict(dict)
        self.dns_ips = []

    # Load data from STIX document, and other usefull data
    def load(self, args):
        filename = '{}/tmp/{}'.format(os.path.dirname(args[0]), args[1])
        try:
            event = STIXPackage.from_xml(filename)
        except Exception:
            try:
                import maec
                print(2)
            except ImportError:
                print(3)
            sys.exit(0)
        self.filename = filename
        title = event.stix_header.title
        fromMISP = (title is not None and "Export from " in title and "MISP" in title)
        if fromMISP:
            package = event.related_packages.related_package[0].item
            self.event = package.incidents[0]
            self.ttps = package.ttps.ttps if package.ttps else None
        else:
            self.event = event
        if args[2] is not None:
            self.add_original_file(args[2])
        try:
            event_distribution = args[3]
            if not isinstance(event_distribution, int):
                event_distribution = int(event_distribution) if event_distribution.isdigit() else 5
        except IndexError:
            event_distribution = 5
        try:
            attribute_distribution = args[4]
            if attribute_distribution != 'event' and not isinstance(attribute_distribution, int):
                attribute_distribution = int(attribute_distribution) if attribute_distribution.isdigit() else 5
        except IndexError:
            attribute_distribution = 5
        self.misp_event.distribution = event_distribution
        self.__attribute_distribution = event_distribution if attribute_distribution == 'event' else attribute_distribution
        self.fromMISP = fromMISP
        self.load_mapping()

    def add_original_file(self, original_filename):
        with open(self.filename, 'rb') as f:
            sample = base64.b64encode(f.read()).decode('utf-8')
        original_file = MISPObject('original-imported_file')
        original_file.add_attribute(**{'type': 'attachment', 'value': original_filename,
                                       'object_relation': 'imported-sample', 'data': sample})
        original_file.add_attribute(**{'type': 'text', 'object_relation': 'format',
                                       'value': 'STIX {}'.format(self.event.version)})
        self.misp_event.add_object(**original_file)

    # Load the mapping dictionary for STIX object types
    def load_mapping(self):
        self.attribute_types_mapping = {
            "AccountObjectType": self.handle_credential,
            'AddressObjectType': self.handle_address,
            "ArtifactObjectType": self.handle_attachment,
            "ASObjectType": self.handle_as,
            "CustomObjectType": self.handle_custom,
            "DNSRecordObjectType": self.handle_dns,
            'DomainNameObjectType': self.handle_domain_or_url,
            'EmailMessageObjectType': self.handle_email_attribute,
            'FileObjectType': self.handle_file,
            'HostnameObjectType': self.handle_hostname,
            'HTTPSessionObjectType': self.handle_http,
            'MutexObjectType': self.handle_mutex,
            'NetworkConnectionObjectType': self.handle_network_connection,
            'NetworkSocketObjectType': self.handle_network_socket,
            'PDFFileObjectType': self.handle_file,
            'PortObjectType': self.handle_port,
            'ProcessObjectType': self.handle_process,
            'SocketAddressObjectType': self.handle_socket_address,
            'SystemObjectType': self.handle_system,
            'URIObjectType': self.handle_domain_or_url,
            "WhoisObjectType": self.handle_whois,
            "WindowsFileObjectType": self.handle_file,
            'WindowsRegistryKeyObjectType': self.handle_regkey,
            "WindowsExecutableFileObjectType": self.handle_pe,
            "WindowsServiceObjectType": self.handle_windows_service,
            "X509CertificateObjectType": self.handle_x509
        }

    # Define if the STIX document is from MISP or is an external one
    # and call the appropriate function to parse it.
    # Then, make references between objects
    def handler(self):
        self.outputname = '{}.json'.format(self.filename)
        if self.fromMISP:
            # STIX format coming from a MISP export
            self.buildMispDict()
        else:
            # external STIX format file
            self.buildExternalDict()
        if self.dns_objects:
            self.resolve_dns_objects()
        self.set_distribution()
        if self.references:
            self.build_references()

    # Build a MISP event, parsing STIX data following the structure used in our own exporter
    def buildMispDict(self):
        self.dictTimestampAndDate()
        self.eventInfo()
        if self.event.related_indicators:
            for indicator in self.event.related_indicators.indicator:
                self.parse_misp_indicator(indicator)
        if self.event.related_observables:
            for observable in self.event.related_observables.observable:
                self.parse_misp_observable(observable)
        if self.event.history:
            self.parse_journal_entries()
        if self.event.information_source and self.event.information_source.references:
            for reference in self.event.information_source.references:
                self.misp_event.add_attribute(**{'type': 'link', 'value': reference})
        if self.ttps:
            for ttp in self.ttps:
                if ttp.exploit_targets:
                    self.parse_vulnerability(ttp.exploit_targets.exploit_target)
                # if ttp.handling:
                #     self.parse_tlp_marking(ttp.handling)

    def parse_journal_entries(self):
        for entry in self.event.history.history_items:
            journal_entry = entry.journal_entry.value
            try:
                entry_type, entry_value = journal_entry.split(': ')
                if entry_type == "MISP Tag":
                    self.parse_tag(entry_value)
                elif entry_type.startswith('attribute['):
                    _, category, attribute_type = entry_type.split('[')
                    self.misp_event.add_attribute(**{'type': attribute_type[:-1], 'category': category[:-1], 'value': entry_value})
                elif entry_type == "Event Threat Level":
                    self.misp_event.threat_level_id = threat_level_mapping[entry_value]
            except ValueError:
                continue

    def parse_tag(self, entry):
        if entry.startswith('misp-galaxy:'):
            tag_type, value = entry.split('=')
            galaxy_type = tag_type.split(':')[1]
            cluster = {'type': galaxy_type, 'value': value[1:-1], 'tag_name': entry}
            self.misp_event['Galaxy'].append({'type': galaxy_type, 'GalaxyCluster': [cluster]})
        self.misp_event.add_tag(entry)

    def parse_vulnerability(self, exploit_targets):
        for exploit_target in exploit_targets:
            if exploit_target.item:
                for vulnerability in exploit_target.item.vulnerabilities:
                    self.misp_event.add_attribute(**{'type': 'vulnerability', 'value': vulnerability.cve_id})

    # Try to parse data from external STIX documents
    def buildExternalDict(self):
        self.dictTimestampAndDate()
        self.eventInfo()
        if self.event.indicators:
            self.parse_external_indicator(self.event.indicators)
        if self.event.observables:
            self.parse_external_observable(self.event.observables.observables)
        if self.event.ttps:
            self.parse_ttps(self.event.ttps.ttps)
        if self.event.courses_of_action:
            self.parse_coa(self.event.courses_of_action)

    # Parse a DNS object
    def resolve_dns_objects(self):
        for domain, domain_dict in self.dns_objects['domain'].items():
            ip_reference = domain_dict['related']
            domain_attribute = domain_dict['data']
            if ip_reference in self.dns_objects['ip']:
                misp_object = MISPObject('passive-dns')
                domain_attribute['object_relation'] = "rrname"
                misp_object.add_attribute(**domain_attribute)
                ip = self.dns_objects['ip'][ip_reference]['value']
                ip_attribute = {"type": "text", "value": ip, "object_relation": "rdata"}
                misp_object.add_attribute(**ip_attribute)
                rrtype = "AAAA" if ":" in ip else "A"
                rrtype_attribute = {"type": "text", "value": rrtype, "object_relation": "rrtype"}
                misp_object.add_attribute(**rrtype_attribute)
                self.misp_event.add_object(**misp_object)
            else:
                self.misp_event.add_attribute(**domain_attribute)
        for ip, ip_dict in self.dns_objects['ip'].items():
            if ip not in self.dns_ips:
                self.misp_event.add_attribute(**ip_dict)

    def set_distribution(self):
        for attribute in self.misp_event.attributes:
            attribute.distribution = self.__attribute_distribution
        for misp_object in self.misp_event.objects:
            misp_object.distribution = self.__attribute_distribution
            for attribute in misp_object.attributes:
                attribute.distribution = self.__attribute_distribution

    # Make references between objects
    def build_references(self):
        for misp_object in self.misp_event.objects:
            object_uuid = misp_object.uuid
            if object_uuid in self.references:
                for reference in self.references[object_uuid]:
                    misp_object.add_reference(reference['idref'], reference['relationship'])

    # Set timestamp & date values in the new MISP event
    def dictTimestampAndDate(self):
        if self.event.timestamp:
            stixTimestamp = self.event.timestamp
            try:
                date = stixTimestamp.split("T")[0]
            except AttributeError:
                date = stixTimestamp
            self.misp_event.date = date
            self.misp_event.timestamp = self.getTimestampfromDate(stixTimestamp)

    # Translate date into timestamp
    @staticmethod
    def getTimestampfromDate(date):
        try:
            try:
                dt = date.split('+')[0]
                d = int(time.mktime(time.strptime(dt, "%Y-%m-%d %H:%M:%S")))
            except ValueError:
                dt = date.split('.')[0]
                d = int(time.mktime(time.strptime(dt, "%Y-%m-%d %H:%M:%S")))
        except AttributeError:
            d = int(time.mktime(date.timetuple()))
        return d

    # Set info & title values in the new MISP event
    def eventInfo(self):
        info = "Imported from external STIX event"
        try:
            try:
                title = self.event.stix_header.title
            except AttributeError:
                title = self.event.title
            if title:
                info = title
        except AttributeError:
            pass
        self.misp_event.info = str(info)

    # Parse indicators of a STIX document coming from our exporter
    def parse_misp_indicator(self, indicator):
        # define is an indicator will be imported as attribute or object
        if indicator.relationship in categories:
            self.parse_misp_attribute_indicator(indicator)
        else:
            self.parse_misp_object_indicator(indicator)

    def parse_misp_observable(self, observable):
        if observable.relationship in categories:
            self.parse_misp_attribute_observable(observable)
        else:
            self.parse_misp_object_observable(observable)

    # Parse STIX objects that we know will give MISP attributes
    def parse_misp_attribute_indicator(self, indicator):
        misp_attribute = {'to_ids': True, 'category': str(indicator.relationship)}
        item = indicator.item
        misp_attribute['timestamp'] = self.getTimestampfromDate(item.timestamp)
        if item.observable:
            observable = item.observable
            self.parse_misp_attribute(observable, misp_attribute, to_ids=True)

    def parse_misp_attribute_observable(self, observable):
        misp_attribute = {'to_ids': False, 'category': str(observable.relationship)}
        if observable.item:
            self.parse_misp_attribute(observable.item, misp_attribute)

    def parse_misp_attribute(self, observable, misp_attribute, to_ids=False):
        try:
            properties = observable.object_.properties
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                if isinstance(attribute_value, (str, int)):
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, misp_attribute)
                else:
                    self.handle_object_case(attribute_type, attribute_value, compl_data, to_ids=to_ids)
        except AttributeError:
            attribute_dict = {}
            for observables in observable.observable_composition.observables:
                properties = observables.object_.properties
                attribute_type, attribute_value, _ = self.handle_attribute_type(properties, observable_id=observable.id_)
                attribute_dict[attribute_type] = attribute_value
            attribute_type, attribute_value = self.composite_type(attribute_dict)
            self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attribute)

    # Return type & value of a composite attribute in MISP
    @staticmethod
    def composite_type(attributes):
        if "port" in attributes:
            if "ip-src" in attributes:
                return "ip-src|port", "{}|{}".format(attributes["ip-src"], attributes["port"])
            elif "ip-dst" in attributes:
                return "ip-dst|port", "{}|{}".format(attributes["ip-dst"], attributes["port"])
            elif "hostname" in attributes:
                return "hostname|port", "{}|{}".format(attributes["hostname"], attributes["port"])
        elif "domain" in attributes:
            if "ip-src" in attributes:
                ip_value = attributes["ip-src"]
            elif "ip-dst" in attributes:
                ip_value = attributes["ip-dst"]
            return "domain|ip", "{}|{}".format(attributes["domain"], ip_value)

    # Define type & value of an attribute or object in MISP
    def handle_attribute_type(self, properties, is_object=False, title=None, observable_id=None):
        xsi_type = properties._XSI_TYPE
        # try:
        args = [properties]
        if xsi_type in ("FileObjectType", "PDFFileObjectType", "WindowsFileObjectType"):
            args.append(is_object)
        elif xsi_type == "ArtifactObjectType":
            args.append(title)
        return self.attribute_types_mapping[xsi_type](*args)
        # except AttributeError:
        #     # ATM USED TO TEST TYPES
        #     print("Unparsed type: {}".format(xsi_type))
        #     sys.exit(1)

    # Return type & value of an ip address attribute
    @staticmethod
    def handle_address(properties):
        if properties.is_source:
            ip_type = "ip-src"
        else:
            ip_type = "ip-dst"
        return ip_type, properties.address_value.value, "ip"

    def handle_as(self, properties):
        attributes = self.fetch_attributes_with_partial_key_parsing(properties, stix2misp_mapping._as_mapping)
        return attributes[0] if len(attributes) == 1 else ('asn', self.return_attributes(attributes), '')

    # Return type & value of an attachment attribute
    @staticmethod
    def handle_attachment(properties, title):
        if properties.hashes:
            return "malware-sample", "{}|{}".format(title, properties.hashes[0], properties.raw_artifact.value)
        return stix2misp_mapping.eventTypes[properties._XSI_TYPE]['type'], title, properties.raw_artifact.value

    # Return type & attributes of a credential object
    def handle_credential(self, properties):
        attributes = []
        if properties.description:
            attributes.append(["text", properties.description.value, "text"])
        if properties.authentication:
            for authentication in properties.authentication:
                attributes += self.fetch_attributes_with_key_parsing(authentication, stix2misp_mapping._credential_authentication_mapping)
        if properties.custom_properties:
            for prop in properties.custom_properties:
                if prop.name in stix2misp_mapping._credential_custom_types:
                    attributes.append(['text', prop.value, prop.name])
        return attributes[0] if len(attributes) == 1 else ("credential", self.return_attributes(attributes), "")

    # Return type & attributes (or value) of a Custom Object
    def handle_custom(self, properties):
        custom_properties = properties.custom_properties
        # if the stix file is coming from MISP, we import a MISP object from it
        if self.fromMISP:
            attributes = []
            for prop in custom_properties:
                attribute_type, relation = prop.name.split(': ')
                attribute_type = attribute_type.split(' ')[1]
                attributes.append([attribute_type, prop.value, relation])
            if len(attributes) > 1:
                name = custom_properties[0].name.split(' ')[0]
                return name, self.return_attributes(attributes), ""
            return attributes[0]
        # otherwise, each property is imported as text
        if len(custom_properties) > 1:
            for prop in custom_properties[:-1]:
                misp_attribute = {'type': 'text', 'value': prop.value, 'comment': prop.name}
                self.misp_event.add_attribute(MISPAttribute(**misp_attribute))


    # Return type & attributes of a dns object
    def handle_dns(self, properties):
        relation = []
        if properties.domain_name:
            relation.append(["domain", str(properties.domain_name.value), ""])
        if properties.ip_address:
            relation.append(["ip-dst", str(properties.ip_address.value), ""])
        if relation:
            if len(relation) == '2':
                domain = relation[0][1]
                ip = relattion[1][1]
                attributes = [["text", domain, "rrname"], ["text", ip, "rdata"]]
                rrtype = "AAAA" if ":" in ip else "A"
                attributes.append(["text", rrtype, "rrtype"])
                return "passive-dns", self.return_attributes(attributes), ""
            return relation[0]

    # Return type & value of a domain or url attribute
    @staticmethod
    def handle_domain_or_url(properties):
        event_types = stix2misp_mapping.eventTypes[properties._XSI_TYPE]
        return event_types['type'], properties.value.value, event_types['relation']

    # Return type & value of an email attribute
    def handle_email_attribute(self, properties):
        if properties.header:
            header = properties.header
            attributes = self.fetch_attributes_with_key_parsing(header, stix2misp_mapping._email_mapping)
            if header.to:
                for to in header.to:
                    attributes.append(["email-dst", to.address_value.value, "to"])
            if header.cc:
                for cc in header.cc:
                    attributes.append(["email-dst", cc.address_value.value, "cc"])
        else:
            attributes = []
        if properties.attachments:
            attributes.append(self.handle_email_attachment(properties.parent))
        return attributes[0] if len(attributes) == 1 else ("email", self.return_attributes(attributes), "")

    # Return type & value of an email attachment
    @staticmethod
    def handle_email_attachment(indicator_object):
        properties = indicator_object.related_objects[0].properties
        return ["email-attachment", properties.file_name.value, "attachment"]

    # Return type & attributes of a file object
    def handle_file(self, properties, is_object):
        b_hash, b_file = False, False
        attributes = []
        if properties.hashes:
            b_hash = True
            for h in properties.hashes:
                attributes.append(self.handle_hashes_attribute(h))
        if properties.file_name:
            value = properties.file_name.value
            if value:
                b_file = True
                attribute_type, relation = stix2misp_mapping.eventTypes[properties._XSI_TYPE]
                attributes.append([attribute_type, value, relation])
        attributes.extend(self.fetch_attributes_with_keys(properties, stix2misp_mapping._file_mapping))
        if len(attributes) == 1:
            attribute = attributes[0]
            return attribute if attribute[2] != "fullpath" else "filename", attribute[1], ""
        if len(attributes) == 2:
            if b_hash and b_file:
                return self.handle_filename_object(attributes, is_object)
            path, filename = self.handle_filename_path_case(attributes)
            if path and filename:
                attribute_value = "{}\\{}".format(path, filename)
                if '\\' in filename and path == filename:
                    attribute_value = filename
                return "filename", attribute_value, ""
        return "file", self.return_attributes(attributes), ""

    # Determine path & filename from a complete path or filename attribute
    @staticmethod
    def handle_filename_path_case(attributes):
        path, filename = [""] * 2
        if attributes[0][2] == 'filename' and attributes[1][2] == 'path':
            path = attributes[1][1]
            filename = attributes[0][1]
        elif attributes[0][2] == 'path' and attributes[1][2] == 'filename':
            path = attributes[0][1]
            filename = attributes[1][1]
        return path, filename

    # Return the appropriate type & value when we have 1 filename & 1 hash value
    @staticmethod
    def handle_filename_object(attributes, is_object):
        for attribute in attributes:
            attribute_type, attribute_value, _ = attribute
            if attribute_type == "filename":
                filename_value = attribute_value
            else:
                hash_type, hash_value = attribute_type, attribute_value
        value = "{}|{}".format(filename_value,  hash_value)
        if is_object:
            # file object attributes cannot be filename|hash, so it is malware-sample
            attr_type = "malware-sample"
            return attr_type, value, attr_type
        # it could be malware-sample as well, but STIX is losing this information
        return "filename|{}".format(hash_type), value, ""

    # Return type & value of a hash attribute
    @staticmethod
    def handle_hashes_attribute(properties):
        hash_type = properties.type_.value.lower()
        try:
            hash_value = properties.simple_hash_value.value
        except AttributeError:
            hash_value = properties.fuzzy_hash_value.value
        return hash_type, hash_value, hash_type

    # Return type & value of a hostname attribute
    @staticmethod
    def handle_hostname(properties):
        event_types = stix2misp_mapping.eventTypes[properties._XSI_TYPE]
        return event_types['type'], properties.hostname_value.value, event_types['relation']

    # Return type & value of a http request attribute
    @staticmethod
    def handle_http(properties):
        client_request = properties.http_request_response[0].http_client_request
        if client_request.http_request_header:
            request_header = client_request.http_request_header
            if request_header.parsed_header:
                value = request_header.parsed_header.user_agent.value
                return "user-agent", value, "user-agent"
            elif request_header.raw_header:
                value = request_header.raw_header.value
                return "http-method", value, "method"
        elif client_request.http_request_line:
            value = client_request.http_request_line.http_method.value
            return "http-method", value, "method"

    # Return type & value of a mutex attribute
    @staticmethod
    def handle_mutex(properties):
        event_types = stix2misp_mapping.eventTypes[properties._XSI_TYPE]
        return event_types['type'], properties.name.value, event_types['relation']

    # Return type & attributes of a network connection object
    def handle_network_connection(self, properties):
        attributes = self.fetch_attributes_from_sockets(properties, stix2misp_mapping._network_connection_addresses)
        for prop in ('layer3_protocol', 'layer4_protocol', 'layer7_protocol'):
            if getattr(properties, prop):
                attributes.append(['text', attrgetter("{}.value".format(prop))(properties), prop.replace('_', '-')])
        if attributes:
            return "network-connection", self.return_attributes(attributes), ""

    # Return type & attributes of a network socket objet
    def handle_network_socket(self, properties):
        attributes = self.fetch_attributes_from_sockets(properties, stix2misp_mapping._network_socket_addresses)
        attributes.extend(self.fetch_attributes_with_keys(properties, stix2misp_mapping._network_socket_mapping))
        for prop in ('is_listening', 'is_blocking'):
            if getattr(properties, prop):
                attributes.append(["text", prop.split('_')[1], "state"])
        if attributes:
            return "network-socket", self.return_attributes(attributes), ""

    # Return type & value of a port attribute
    @staticmethod
    def handle_port(*kwargs):
        properties = kwargs[0]
        event_types = stix2misp_mapping.eventTypes[properties._XSI_TYPE]
        relation = event_types['relation']
        if len(kwargs) > 1:
            observable_id = kwargs[1]
            if "srcPort" in observable_id:
                relation = "src-{}".format(relation)
            elif "dstPort" in observable_id:
                relation = "dst-{}".format(relation)
        return event_types['type'], properties.port_value.value, relation

    # Return type & attributes of a process object
    def handle_process(self, properties):
        attributes = self.fetch_attributes_with_partial_key_parsing(properties, stix2misp_mapping._process_mapping)
        if properties.child_pid_list:
            for child in properties.child_pid_list:
                attributes.append(["text", child.value, "child-pid"])
        # if properties.port_list:
        #     for port in properties.port_list:
        #         attributes.append(["src-port", port.port_value.value, "port"])
        if properties.network_connection_list:
            references = []
            for connection in properties.network_connection_list:
                object_name, object_attributes, _ = self.handle_network_connection(connection)
                object_uuid = str(uuid.uuid4())
                misp_object = MISPObject(object_name)
                misp_object.uuid = object_uuid
                for attribute in object_attributes:
                    misp_object.add_attribute(**attribute)
                references.append(object_uuid)
            return "process", self.return_attributes(attributes), {"process_uuid": references}
        return "process", self.return_attributes(attributes), ""

    # Return type & value of a regkey attribute
    def handle_regkey(self, properties):
        attributes = self.fetch_attributes_with_partial_key_parsing(properties, stix2misp_mapping._regkey_mapping)
        if properties.values:
            values = properties.values
            value = values[0]
            attributes += self.fetch_attributes_with_partial_key_parsing(value, stix2misp_mapping._regkey_value_mapping)
        if len(attributes) in (2,3):
            d_regkey = {key: value for (_, value, key) in attributes}
            if 'hive' in d_regkey and 'key' in d_regkey:
                regkey = "{}\\{}".format(d_regkey['hive'], d_regkey['key'])
                if 'data' in d_regkey:
                    return "regkey|value", "{} | {}".format(regkey, d_regkey['data']), ""
                return "regkey", regkey, ""
        return "registry-key", self.return_attributes(attributes), ""

    @staticmethod
    def handle_socket(attributes, socket, s_type):
        for prop, mapping in stix2misp_mapping._socket_mapping.items():
            if getattr(socket, prop):
                attribute_type, properties_key, relation = mapping
                attribute_type, relation = [elem.format(s_type) for elem in (attribute_type, relation)]
                attributes.append([attribute_type, attrgetter('{}.{}.value'.format(prop, properties_key))(socket), relation])

    # Parse a socket address object in order to return type & value
    # of a composite attribute ip|port or hostname|port
    def handle_socket_address(self, properties):
        if properties.ip_address:
            type1, value1, _ = self.handle_address(properties.ip_address)
        elif properties.hostname:
            type1 = "hostname"
            value1 = properties.hostname.hostname_value.value
        return "{}|port".format(type1), "{}|{}".format(value1, properties.port.port_value.value), ""

    # Parse a system object to extract a mac-address attribute
    @staticmethod
    def handle_system(properties):
        if properties.network_interface_list:
            return "mac-address", str(properties.network_interface_list[0].mac), ""

    # Parse a whois object:
    # Return type & attributes of a whois object if we have the required fields
    # Otherwise create attributes and return type & value of the last attribute to avoid crashing the parent function
    def handle_whois(self, properties):
        attributes = self.fetch_attributes_with_key_parsing(properties, stix2misp_mapping._whois_mapping)
        required_one_of = True if attributes else False
        if properties.registrants:
            registrant = properties.registrants[0]
            attributes += self.fetch_attributes_with_key_parsing(registrant, stix2misp_mapping._whois_registrant_mapping)
        if properties.creation_date:
            attributes.append(["datetime", properties.creation_date.value.strftime('%Y-%m-%d'), "creation-date"])
            required_one_of = True
        if properties.updated_date:
            attributes.append(["datetime", properties.updated_date.value.strftime('%Y-%m-%d'), "modification-date"])
        if properties.expiration_date:
            attributes.append(["datetime", properties.expiration_date.value.strftime('%Y-%m-%d'), "expiration-date"])
        if properties.nameservers:
            for nameserver in properties.nameservers:
                attributes.append(["hostname", nameserver.value.value, "nameserver"])
        if properties.remarks:
            attribute_type = "text"
            relation = "comment" if attributes else attribute_type
            attributes.append([attribute_type, properties.remarks.value, relation])
            required_one_of = True
        # Testing if we have the required attribute types for Object whois
        if required_one_of:
            # if yes, we return the object type and the attributes
            return "whois", self.return_attributes(attributes), ""
        # otherwise, attributes are added in the event, and one attribute is returned to not make the function crash
        if len(attributes) == 1:
            return attributes[0]
        last_attribute = attributes.pop(-1)
        for attribute in attributes:
            attribute_type, attribute_value, attribute_relation = attribute
            misp_attributes = {"comment": "Whois {}".format(attribute_relation)}
            self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attributes)
        return last_attribute

    # Return type & value of a windows service object
    @staticmethod
    def handle_windows_service(properties):
        if properties.name:
            return "windows-service-name", properties.name.value, ""

    def handle_x509(self, properties):
        attributes = self.handle_x509_certificate(properties.certificate) if properties.certificate else []
        if properties.raw_certificate:
            raw = properties.raw_certificate.value
            try:
                relation = "raw-base64" if raw == base64.b64encode(base64.b64decode(raw)).strip() else "pem"
            except Exception:
                relation = "pem"
            attributes.append(["text", raw, relation])
        if properties.certificate_signature:
            signature = properties.certificate_signature
            attribute_type = "x509-fingerprint-{}".format(signature.signature_algorithm.value.lower())
            attributes.append([attribute_type, signature.signature.value, attribute_type])
        return "x509", self.return_attributes(attributes), ""

    @staticmethod
    def handle_x509_certificate(certificate):
        attributes = []
        if certificate.validity:
            validity = certificate.validity
            for prop in stix2misp_mapping._x509_datetime_types:
                if getattr(validity, prop):
                    attributes.append(['datetime', attrgetter('{}.value'.format(prop))(validity), 'validity-{}'.format(prop.replace('_', '-'))])
        if certificate.subject_public_key:
            subject_pubkey = certificate.subject_public_key
            if subject_pubkey.rsa_public_key:
                rsa_pubkey = subject_pubkey.rsa_public_key
                for prop in stix2misp_mapping._x509__x509_pubkey_types:
                    if getattr(rsa_pubkey, prop):
                        attributes.append(['text', attrgetter('{}.value'.format(prop))(rsa_pubkey), 'pubkey-info-{}'.format(prop)])
            if subject_pubkey.public_key_algorithm:
                attributes.append(["text", subject_pubkey.public_key_algorithm.value, "pubkey-info-algorithm"])
        for prop in stix2misp_mapping._x509_certificate_types:
            if getattr(certificate, prop):
                attributes.append(['text', attrgetter('{}.value'.format(prop))(certificate), prop.replace('_', '-')])
        return attributes

    # Return type & attributes of the file defining a portable executable object
    def handle_pe(self, properties):
        pe_uuid = self.parse_pe(properties)
        file_type, file_value, _ = self.handle_file(properties, False)
        return file_type, file_value, pe_uuid

    # Parse attributes of a portable executable, create the corresponding object,
    # and return its uuid to build the reference for the file object generated at the same time
    def parse_pe(self, properties):
        misp_object = MISPObject('pe')
        filename = properties.file_name.value
        for attr in ('internal-filename', 'original-filename'):
            misp_object.add_attribute(**dict(zip(('type', 'value', 'object_relation'),('filename', filename, attr))))
        if properties.headers:
            headers = properties.headers
            header_object = MISPObject('pe-section')
            if headers.entropy:
                header_object.add_attribute(**{"type": "float", "object_relation": "entropy",
                                               "value": headers.entropy.value.value})
            file_header = headers.file_header
            misp_object.add_attribute(**{"type": "counter", "object_relation": "number-sections",
                                         "value": file_header.number_of_sections.value})
            for h in file_header.hashes:
                hash_type, hash_value, hash_relation = self.handle_hashes_attribute(h)
                header_object.add_attribute(**{"type": hash_type, "value": hash_value, "object_relation": hash_relation})
            if file_header.size_of_optional_header:
                header_object.add_attribute(**{"type": "size-in-bytes", "object_relation": "size-in-bytes",
                                               "value": file_header.size_of_optional_header.value})
            self.misp_event.add_object(**header_object)
            misp_object.add_reference(header_object.uuid, 'header-of')
        if properties.sections:
            for section in properties.sections:
                section_uuid = self.parse_pe_section(section)
                misp_object.add_reference(section_uuid, 'included-in')
        self.misp_event.add_object(**misp_object)
        return {"pe_uuid": misp_object.uuid}

    # Parse attributes of a portable executable section, create the corresponding object,
    # and return its uuid to build the reference for the pe object generated at the same time
    def parse_pe_section(self, section):
        section_object = MISPObject('pe-section')
        header_hashes = section.header_hashes
        for h in header_hashes:
            hash_type, hash_value, hash_relation = self.handle_hashes_attribute(h)
            section_object.add_attribute(**{"type": hash_type, "value": hash_value, "object_relation": hash_relation})
        if section.entropy:
            section_object.add_attribute(**{"type": "float", "object_relation": "entropy",
                                            "value": section.entropy.value.value})
        if section.section_header:
            section_header = section.section_header
            section_object.add_attribute(**{"type": "text", "object_relation": "name",
                                            "value": section_header.name.value})
            section_object.add_attribute(**{"type": "size-in-bytes", "object_relation": "size-in-bytes",
                                            "value": section_header.size_of_raw_data.value})
        self.misp_event.add_object(**section_object)
        return section_object.uuid

    # Parse STIX object that we know will give MISP objects
    def parse_misp_object_indicator(self, indicator):
        object_type = str(indicator.relationship)
        item = indicator.item
        name = item.title.split(' ')[0]
        if name not in ('passive-dns'):
            self.fill_misp_object(item, name, to_ids=True)
        else:
            if object_type != "misc":
                print("Unparsed Object type: {}".format(name))

    def parse_misp_object_observable(self, observable):
        object_type = str(observable.relationship)
        observable = observable.item
        observable_id = observable.id_
        if object_type == "file":
            name = "registry-key" if "WinRegistryKey" in observable_id else "file"
        elif object_type == "network":
            if "Custom" in observable_id:
                name = observable_id.split("Custom")[0].split(":")[1]
            elif "ObservableComposition" in observable_id:
                name = observable_id.split("_")[0].split(":")[1]
            else:
                name = cybox_to_misp_object[observable_id.split('-')[0].split(':')[1]]
        else:
            name = cybox_to_misp_object[observable_id.split('-')[0].split(':')[1]]
        try:
            self.fill_misp_object(observable, name)
        except Exception:
            print("Unparsed Object type: {}".format(observable.to_json()))

    # Create a MISP object, its attributes, and add it in the MISP event
    def fill_misp_object(self, item, name, to_ids=False):
        try:
            misp_object = MISPObject(name)
            if to_ids:
                observables = item.observable.observable_composition.observables
                misp_object.timestamp = self.getTimestampfromDate(item.timestamp)
            else:
                observables = item.observable_composition.observables
            for observable in observables:
                properties = observable.object_.properties
                misp_attribute = MISPAttribute()
                misp_attribute.type, misp_attribute.value, misp_attribute.object_relation = self.handle_attribute_type(properties, is_object=True, observable_id=observable.id_)
                misp_attribute.to_ids = to_ids
                misp_object.add_attribute(**misp_attribute)
            self.misp_event.add_object(**misp_object)
        except AttributeError:
            properties = item.observable.object_.properties if to_ids else item.object_.properties
            self.parse_observable(properties, to_ids)

    # Create a MISP attribute and add it in its MISP object
    def parse_observable(self, properties, to_ids):
        attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
        if isinstance(attribute_value, (str, int)):
            attribute = {'to_ids': to_ids}
            self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
        else:
            self.handle_object_case(attribute_type, attribute_value, compl_data, to_ids=to_ids)

    # Parse indicators of an external STIX document
    def parse_external_indicator(self, indicators):
        for indicator in indicators:
            try:
                properties = indicator.observable.object_.properties
            except AttributeError:
                self.parse_description(indicator)
                continue
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                if isinstance(attribute_value, (str, int)):
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': True}
                    if indicator.timestamp:
                        attribute['timestamp'] = self.getTimestampfromDate(indicator.timestamp)
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    # otherwise, it is a dictionary of attributes, so we build an object
                    self.handle_object_case(attribute_type, attribute_value, compl_data, to_ids=True)

    # Parse observables of an external STIX document
    def parse_external_observable(self, observables):
        for observable in observables:
            title = observable.title
            observable_object = observable.object_
            try:
                properties = observable_object.properties
            except AttributeError:
                self.parse_description(observable)
                continue
            if properties:
                try:
                    attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties, title=title)
                except KeyError:
                    # print("Error with an object of type: {}\n{}".format(properties._XSI_TYPE, observable.to_json()))
                    continue
                object_uuid = self.fetch_uuid(observable_object.id_)
                if isinstance(attribute_value, (str, int)):
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': False, 'uuid': object_uuid}
                    if observable_object.related_objects:
                        related_objects = observable_object.related_objects
                        if attribute_type == "url" and len(related_objects) == 1 and related_objects[0].relationship.value == "Resolved_To":
                            related_ip = self.fetch_uuid(related_objects[0].idref)
                            self.dns_objects['domain'][object_uuid] = {"related": related_ip,
                                                                       "data": {"type": "text", "value": attribute_value}}
                            if related_ip not in self.dns_ips:
                                self.dns_ips.append(related_ip)
                            continue
                    if attribute_type in ('ip-src', 'ip-dst'):
                        attribute['type'] = attribute_type
                        attribute['value'] = attribute_value
                        self.dns_objects['ip'][object_uuid] = attribute
                        continue
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    # otherwise, it is a dictionary of attributes, so we build an object
                    if attribute_value:
                        self.handle_object_case(attribute_type, attribute_value, compl_data, object_uuid=object_uuid)
                    if observable_object.related_objects:
                        for related_object in observable_object.related_objects:
                            relationship = related_object.relationship.value.lower().replace('_', '-')
                            self.references[object_uuid].append({"idref": self.fetch_uuid(related_object.idref),
                                                                 "relationship": relationship})

    # Parse description of an external indicator or observable and add it in the MISP event as an attribute
    def parse_description(self, stix_object):
        if stix_object.description:
            misp_attribute = {}
            if stix_object.timestamp:
                misp_attribute['timestamp'] = self.getTimestampfromDate(stix_object.timestamp)
            self.misp_event.add_attribute("text", stix_object.description.value, **misp_attribute)

    # The value returned by the indicators or observables parser is of type str or int
    # Thus we can add an attribute in the MISP event with the type & value
    def handle_attribute_case(self, attribute_type, attribute_value, data, attribute):
        if attribute_type == 'attachment':
            attribute['data'] = data
        self.misp_event.add_attribute(attribute_type, attribute_value, **attribute)

    # The value returned by the indicators or observables parser is a list of dictionaries
    # These dictionaries are the attributes we add in an object, itself added in the MISP event
    def handle_object_case(self, attribute_type, attribute_value, compl_data, to_ids=False, object_uuid=None):
        misp_object = MISPObject(attribute_type)
        if object_uuid:
            misp_object.uuid = object_uuid
        for attribute in attribute_value:
            attribute['to_ids'] = to_ids
            misp_object.add_attribute(**attribute)
        if isinstance(compl_data, dict):
            # if some complementary data is a dictionary containing an uuid,
            # it means we are using it to add an object reference
            if "pe_uuid" in compl_data:
                misp_object.add_reference(compl_data['pe_uuid'], 'included-in')
            if "process_uuid" in compl_data:
                for uuid in compl_data["process_uuid"]:
                    misp_object.add_reference(uuid, 'connected-to')
        self.misp_event.add_object(**misp_object)

    def fetch_attributes_from_sockets(self, properties, mapping_dict):
        attributes = []
        for prop, s_type in zip(mapping_dict, stix2misp_mapping._s_types):
            address_property = getattr(properties, prop)
            if address_property:
                self.handle_socket(attributes, address_property, s_type)
        return attributes

    @staticmethod
    def fetch_attributes_with_keys(properties, mapping_dict):
        attributes = []
        for prop, mapping in mapping_dict.items():
            if getattr(properties,prop):
                attribute_type, properties_key, relation = mapping
                attributes.append([attribute_type, attrgetter(properties_key)(properties), relation])
        return attributes

    @staticmethod
    def fetch_attributes_with_key_parsing(properties, mapping_dict):
        attributes = []
        for prop, mapping in mapping_dict.items():
            if getattr(properties, prop):
                attribute_type, properties_key, relation = mapping
                attributes.append([attribute_type, attrgetter('{}.{}'.format(prop, properties_key))(properties), relation])
        return attributes

    @staticmethod
    def fetch_attributes_with_partial_key_parsing(properties, mapping_dict):
        attributes = []
        for prop, mapping in mapping_dict.items():
            if getattr(properties, prop):
                attribute_type, relation = mapping
                attributes.append([attribute_type, attrgetter('{}.value'.format(prop))(properties), relation])
        return attributes

    # Extract the uuid from a stix id
    @staticmethod
    def fetch_uuid(object_id):
        try:
            identifier = object_id.split(':')[1]
            return_id = ""
            for part in identifier.split('-')[1:]:
                return_id += "{}-".format(part)
            return return_id[:-1]
        except Exception:
            return str(uuid.uuid4())

    # Parse the ttps field of an external STIX document
    def parse_ttps(self, ttps):
        for ttp in ttps:
            if ttp.behavior and ttp.behavior.malware_instances:
                mi = ttp.behavior.malware_instances[0]
                if mi.types:
                    mi_type = mi.types[0].value
                    galaxy = {'type': mi_type}
                    cluster = defaultdict(dict)
                    cluster['type'] = mi_type
                    if mi.description:
                        cluster['description'] = mi.description.value
                    cluster['value'] = ttp.title
                    if mi.names:
                        synonyms = []
                        for name in mi.names:
                            synonyms.append(name.value)
                        cluster['meta']['synonyms'] = synonyms
                    galaxy['GalaxyCluster'] = [cluster]
                    self.misp_event['Galaxy'].append(galaxy)

    # Parse the courses of action field of an external STIX document
    def parse_coa(self, courses_of_action):
        for coa in courses_of_action:
            misp_object = MISPObject('course-of-action')
            if coa.title:
                attribute = {'type': 'text', 'object_relation': 'name',
                             'value': coa.title}
                misp_object.add_attribute(**attribute)
            for prop, properties_key in stix2misp_mapping._coa_mapping.items():
                if getattr(coa, prop):
                    attribute = {'type': 'text', 'object_relation': prop.replace('_', ''),
                                 'value': attrgetter('{}.{}'.format(prop, properties_key))(coa)}
                    misp_object.add_attribute(**attribute)
            if coa.parameter_observables:
                for observable in coa.parameter_observables.observables:
                    properties = observable.object_.properties
                    attribute = MISPAttribute()
                    attribute.type, attribute.value, _ = self.handle_attribute_type(properties)
                    referenced_uuid = str(uuid.uuid4())
                    attribute.uuid = referenced_uuid
                    self.misp_event.add_attribute(**attribute)
                    misp_object.add_reference(referenced_uuid, 'observable', None, **attribute)
            self.misp_event.add_object(**misp_object)

    # Return the attributes that will be added in a MISP object as a list of dictionaries
    @staticmethod
    def return_attributes(attributes):
        return_attributes = []
        for attribute in attributes:
            return_attributes.append(dict(zip(('type', 'value', 'object_relation'), attribute)))
        return return_attributes

    # Convert the MISP event we create from the STIX document into json format
    # and write it in the output file
    def saveFile(self):
        eventDict = self.misp_event.to_json()
        with open(self.outputname, 'w') as f:
            f.write(eventDict)

def main(args):
    stix_parser = StixParser()
    stix_parser.load(args)
    stix_parser.handler()
    stix_parser.saveFile()
    print(1)

if __name__ == "__main__":
    main(sys.argv)
