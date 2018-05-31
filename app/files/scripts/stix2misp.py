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

import sys, json, os, time, uuid
import mixbox.namespaces as mixbox_ns
from pymisp import MISPEvent, MISPObject, MISPAttribute, __path__
from stix.core import STIXPackage
from collections import defaultdict

file_object_type = {"type": "filename", "relation": "filename"}

eventTypes = {"ArtifactObjectType": {"type": "attachment", "relation": "attachment"},
              "DomainNameObjectType": {"type": "domain", "relation": "domain"},
              "FileObjectType": file_object_type,
              "HostnameObjectType": {"type": "hostname", "relation": "host"},
              "MutexObjectType": {"type": "mutex", "relation": "mutex"},
              "PDFFileObjectType": file_object_type,
              "PortObjectType": {"type": "port", "relation": "port"},
              "URIObjectType": {"type": "url", "relation": "url"},
              "WindowsExecutableFileObjectType": file_object_type,
              "WindowsRegistryKeyObjectType": {"type": "regkey", "relation": ""}}

cybox_to_misp_object = {"EmailMessage": "email", "NetworkConnection": "network-connection",
                        "NetworkSocket": "network-socket", "Process": "process",
                        "x509Certificate": "x509"}

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
    def load(self, args, pathname):
        try:
            filename = '{}/tmp/{}'.format(pathname, args[1])
            event = self.load_event(filename)
            title = event.stix_header.title
            if title is not None and "Export from " in title and "MISP" in title:
                fromMISP = True
            else:
                fromMISP = False
            if fromMISP:
                package = event.related_packages.related_package[0].item
                self.event = package.incidents[0]
                self.ttps = package.ttps.ttps
            else:
                self.event = event
            self.fromMISP = fromMISP
            self.filename = filename
            self.load_mapping()
        except:
            print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
            sys.exit(0)

    # Event loading function, recursively itterating as long as namespace errors appear
    def load_event(self, filename):
        try:
            return STIXPackage.from_xml(filename)
        except Exception as ns_error:
            if ns_error.__str__().startswith('Namespace not found:'):
                ns_value = ns_error.ns_uri
                prefix = ns_value.split('/')[-1]
                ns = mixbox_ns.Namespace(ns_value, prefix, '')
                mixbox_ns.register_namespace(ns)
                return self.load_event(filename)
            else:
                return None

    # Load the mapping dictionary for STIX object types
    def load_mapping(self):
        self.attribute_types_mapping = {
            'AddressObjectType': self.handle_address,
            "ArtifactObjectType": self.handle_attachment,
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
            entry_type, entry_value = journal_entry.split(': ')
            if entry_type.startswith('attribute['):
                _, category, attribute_type = entry_type.split('[')
                self.misp_event.add_attribute(**{'type': attribute_type[:-1], 'category': category[:-1], 'value': entry_value})
            elif entry_type == "Event Threat Level":
                self.misp_event.threat_level_id = threat_level_mapping[entry_value]

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
        for domain in self.dns_objects['domain']:
            domain_object = self.dns_objects['domain'][domain]
            ip_reference = domain_object['related']
            domain_attribute = domain_object['data']
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
        for ip in self.dns_objects['ip']:
            if ip not in self.dns_ips:
                self.misp_event.add_attribute(**self.dns_objects['ip'][ip])

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
                d = int(time.mktime(time.strptime(dt, "%Y-%m-%dT%H:%M:%S")))
            except:
                dt = date.split('.')[0]
                d = int(time.mktime(time.strptime(dt, "%Y-%m-%dT%H:%M:%S")))
        except AttributeError:
            d = int(time.mktime(date.timetuple()))
        return d

    # Set info & title values in the new MISP event
    def eventInfo(self):
        info = "Imported from external STIX event"
        try:
            try:
                title = self.event.stix_header.title
            except:
                title = self.event.title
            if title:
                info = title
        except:
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
        misp_attribute = {'category': str(indicator.relationship)}
        item = indicator.item
        misp_attribute['timestamp'] = self.getTimestampfromDate(item.timestamp)
        if item.observable:
            observable = item.observable
            self.parse_misp_attribute(observable, misp_attribute)

    def parse_misp_attribute_observable(self, observable):
        misp_attribute = {'category': str(observable.relationship)}
        if observable.item:
            self.parse_misp_attribute(observable.item, misp_attribute)

    def parse_misp_attribute(self, observable, misp_attribute):
        try:
            properties = observable.object_.properties
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                if type(attribute_value) in (str, int):
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, misp_attribute)
                else:
                    self.handle_object_case(attribute_type, attribute_value, compl_data)
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
        try:
            args = [properties]
            if xsi_type in ("FileObjectType", "PDFFileObjectType"):
                args.append(is_object)
            elif xsi_type == "ArtifactObjectType":
                args.append(title)
            return self.attribute_types_mapping[xsi_type](*args)
        except AttributeError:
            # ATM USED TO TEST TYPES
            print("Unparsed type: {}".format(xsi_type))
            sys.exit(1)

    # Return type & value of an ip address attribute
    @staticmethod
    def handle_address(properties):
        if properties.is_source:
            ip_type = "ip-src"
        else:
            ip_type = "ip-dst"
        return ip_type, properties.address_value.value, "ip"

    # Return type & value of an attachment attribute
    @staticmethod
    def handle_attachment(properties, title):
        return eventTypes[properties._XSI_TYPE]['type'], title, properties.raw_artifact.value

    # Return type & attributes (or value) of a Custom Object
    def handle_custom(self, properties):
        custom_properties = properties.custom_properties
        # if the stix file is coming from MISP, we import a MISP object from it
        if self.fromMISP:
            attributes = []
            for property in custom_properties:
                attribute_type, relation = property.name.split(': ')
                attribute_type = attribute_type.split(' ')[1]
                attributes.append([attribute_type, property.value, relation])
            if len(attributes) > 1:
                name = custom_properties[0].name.split(' ')[0]
                return name, self.return_attributes(attributes), ""
            return attributes[0]
        # otherwise, each property is imported as text
        if len(custom_properties) > 1:
            for property in custom_properties[:-1]:
                misp_attribute = {'type': 'text', 'value': property.value, 'comment': property.name}
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
        event_types = eventTypes[properties._XSI_TYPE]
        return event_types['type'], properties.value.value, event_types['relation']

    # Return type & value of an email attribute
    def handle_email_attribute(self, properties):
        try:
            if properties.from_:
                return "email-src", properties.from_.address_value.value, "from"
        except:
            pass
        try:
            if properties.to:
                return "email-dst", properties.to[0].address_value.value, "to"
        except:
            pass
        try:
            if properties.subject:
                return "email-subject", properties.subject.value, "subject"
        except:
            pass
        try:
            if properties.attachments:
                return self.handle_email_attachment(properties.parent)
        except:
            pass
        try:
            if properties.header:
                header = properties.header
                if header.reply_to:
                    return "email-reply-to", header.reply_to.address_value.value, "reply-to"
        except:
            pass
        # ATM USED TO TEST EMAIL PROPERTIES
        print("Unsupported Email property")
        print(properties.to_json())
        sys.exit(1)

    # Return type & value of an email attachment
    @staticmethod
    def handle_email_attachment(indicator_object):
        properties = indicator_object.related_objects[0].properties
        return "email-attachment", properties.file_name.value, "attachment"

    # Return type & attributes of a file object
    def handle_file(self, properties, is_object):
        b_hash, b_file = False, False
        attributes = []
        if properties.hashes:
            b_hash = True
            for h in properties.hashes:
                attributes.append(self.handle_hashes_attribute(h))
        if properties.file_format and properties.file_format.value:
            attributes.append(["mime-type", properties.file_format.value, "mimetype"])
        if properties.file_name:
            value = properties.file_name.value
            if value:
                b_file = True
                event_types = eventTypes[properties._XSI_TYPE]
                attributes.append([event_types['type'], value, event_types['relation']])
        if properties.file_path:
            value = properties.file_path.value
            if value:
                attributes.append(['text', value, 'path'])
        if properties.byte_runs:
            attribute_type = "pattern-in-file"
            attributes.append([attribute_type, properties.byte_runs[0].byte_run_data, attribute_type])
        if properties.size_in_bytes and properties.size_in_bytes.value:
            attribute_type = "size-in-bytes"
            attributes.append([attribute_type, properties.size_in_bytes.value, attribute_type])
        if properties.peak_entropy and properties.peak_entropy.value:
            attributes.append(["float", properties.peak_entropy.value, "entropy"])
        if len(attributes) == 1:
            return attributes[0]
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
        else:
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
        event_types = eventTypes[properties._XSI_TYPE]
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
        event_types = eventTypes[properties._XSI_TYPE]
        return event_types['type'], properties.name.value, event_types['relation']

    # Return type & attributes of a network connection object
    def handle_network_connection(self, properties):
        attributes = []
        if properties.source_socket_address:
            self.handle_socket(attributes, properties.source_socket_address, "src")
        if properties.destination_socket_address:
            self.handle_socket(attributes, properties.destination_socket_address, "dst")
        if properties.layer3_protocol:
            attributes.append(["text", properties.layer3_protocol.value, "layer3-protocol"])
        if properties.layer4_protocol:
            attributes.append(["text", properties.layer4_protocol.value, "layer4-protocol"])
        if properties.layer7_protocol:
            attributes.append(["text", properties.layer7_protocol.value, "layer7-protocol"])
        if attributes:
            return "network-connection", self.return_attributes(attributes), ""

    # Return type & attributes of a network socket objet
    def handle_network_socket(self, properties):
        attributes = []
        if properties.local_address:
            self.handle_socket(attributes, properties.local_address, "src")
        if properties.remote_address:
            self.handle_socket(attributes, properties.remote_address, "dst")
        if properties.protocol:
            attributes.append(["text", properties.protocol.value, "protocol"])
        if properties.is_listening:
            attributes.append(["text", "listening", "state"])
        if properties.is_blocking:
            attributes.append(["text", "blocking", "state"])
        if properties.address_family:
            attributes.append(["text", properties.address_family.value, "address-family"])
        if properties.domain:
            attributes.append(["text", properties.domain.value, "domain-family"])
        if attributes:
            return "network-socket", self.return_attributes(attributes), ""

    # Return type & value of a port attribute
    @staticmethod
    def handle_port(*kwargs):
        properties = kwargs[0]
        event_types = eventTypes[properties._XSI_TYPE]
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
        attributes = []
        if properties.creation_time:
            attributes.append(["datetime", properties.creation_time.value, "creation-time"])
        if properties.start_time:
            attributes.append(["datetime", properties.creation_time.value, "start-time"])
        attribute_type = "text"
        if properties.name:
            attributes.append([attribute_type, properties.name.value, "name"])
        if properties.pid:
            attributes.append([attribute_type, properties.pid.value, "pid"])
        if properties.parent_pid:
            attributes.append([attribute_type, properties.parent_pid.value, "parent-pid"])
        if properties.child_pid_list:
            for child in properties.child_pid_list:
                attributes.append([attribute_type, child.value, "child-pid"])
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
        attributes = []
        if properties.hive:
            attributes.append(["text", properties.hive.value, "hive"])
        if properties.key:
            attributes.append(["regkey", properties.key.value, "key"])
        if properties.values:
            values = properties.values
            value = values[0]
            if value.data:
                attributes.append(["text", value.data.value, "data"])
            if value.datatype:
                attributes.append(["text", value.datatype.value, "data-type"])
            if value.name:
                attributes.append(["text", value.name.value, "name"])
        return "registry-key", self.return_attributes(attributes), ""

    # Parse a socket address object into a network connection or socket object,
    # in order to add its attributes
    @staticmethod
    def handle_socket(attributes, socket, s_type):
        if socket.ip_address:
            ip_type = "ip-{}".format(s_type)
            attributes.append([ip_type, socket.ip_address.address_value.value, ip_type])
        if socket.port:
            attributes.append(["port", socket.port.port_value.value, "{}-port".format(s_type)])
        if socket.hostname:
            attributes.append(["hostname", socket.hostname.hostname_value.value, "hostname-{}".format(s_type)])

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
        required_one_of = False
        attributes = []
        if properties.registrar_info:
            attribute_type = "whois-registrar"
            attributes.append([attribute_type, properties.registrar_info.value, attribute_type])
            required_one_of = True
        if properties.registrants:
            registrant = properties.registrants[0]
            if registrant.email_address:
                attributes.append(["whois-registrant-email", registrant.email_address.address_value.value, "registrant-email"])
            if registrant.name:
                attributes.append(["whois-registrant-name", registrant.name.value, "registrant-name"])
            if registrant.phone_number:
                attributes.append(["whois-registrant-phone", registrant.phone_number.value, "registrant-phone"])
            if registrant.organization:
                attributes.append(["whois-registrant-org", registrant.organization.value, "registrant-org"])
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
        if properties.ip_address:
            attributes.append(["ip-src", properties.ip_address.address_value.value, "ip-address"])
            required_one_of = True
        if properties.domain_name:
            attribute_type = "domain"
            attributes.append([attribute_type, properties.domain_name.value.value, attribute_type])
            required_one_of = True
        if properties.remarks:
            attribute_type = "text"
            relation = "comment" if attributes else attribute_type
            attributes.append([attribute_type, properties.remarks.value, relation])
            required_one_of = True
        # Testing if we have the required attribute types for Object whois
        if required_one_of:
            # if yes, we return the object type and the attributes
            return "whois", self.return_attributes(attributes), ""
        else:
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
        attributes = []
        if properties.certificate:
            certificate = properties.certificate
            if certificate.validity:
                validity = certificate.validity
                if validity.not_before:
                    attributes.append(["datetime", validity.not_before.value, "validity-not-before"])
                if validity.not_after:
                    attributes.append(["datetime", validity.not_after.value, "validity-not-after"])
            if certificate.subject_public_key:
                subject_pubkey = certificate.subject_public_key
                if subject_pubkey.rsa_public_key:
                    rsa_pubkey = subject_pubkey.rsa_public_key
                    if rsa_pubkey.exponent:
                        attributes.append(["text", rsa_pubkey.exponent.value, "pubkey-info-exponent"])
                    if rsa_pubkey.modulus:
                        attributes.append(["text", rsa_pubkey.modulus.value, "pubkey-info-modulus"])
                if subject_pubkey.public_key_algorithm:
                    attributes.append(["text", subject_pubkey.public_key_algorithm.value, "pubkey-info-algorithm"])
            if certificate.version:
                attributes.append(["text", certificate.version.value, "version"])
            if certificate.serial_number:
                attributes.append(["text", certificate.serial_number.value, "serial-number"])
            if certificate.issuer:
                attributes.append(["text", certificate.issuer.value, "issuer"])
            if certificate.subject:
                attributes.append(["text", certificate.subject.value, "subject"])
        if properties.raw_certificate:
            raw = properties.raw_certificate
            print(raw.to_json())
        if properties.certificate_signature:
            signature = properties.certificate_signature
            attribute_type = "x509-fingerprint-{}".format(signature.signature_algorithm.value.lower())
            attributes.append([attribute_type, signature.signature.value, attribute_type])
        return "x509", self.return_attributes(attributes), ""

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
            misp_object.add_reference(header_object.uuid, 'included-in')
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
        except:
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
                misp_object.add_attribute(**misp_attribute)
                self.misp_event.add_object(**misp_object)
        except AttributeError:
            properties = item.observable.object_.properties if to_ids else item.object_.properties
            self.parse_observable(properties, to_ids)

    # Create a MISP attribute and add it in its MISP object
    def parse_observable(self, properties, to_ids):
        attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
        if type(attribute_value) in (str, int):
            attribute = {'to_ids': to_ids}
            self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
        else:
            self.handle_object_case(attribute_type, attribute_value, compl_data)

    # Parse indicators of an external STIX document
    def parse_external_indicator(self, indicators):
        for indicator in indicators:
            try:
                properties = indicator.observable.object_.properties
            except:
                self.parse_description(indicator)
                continue
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                if type(attribute_value) in (str, int):
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': True}
                    if indicator.timestamp:
                        attribute['timestamp'] = self.getTimestampfromDate(indicator.timestamp)
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    # otherwise, it is a dictionary of attributes, so we build an object
                    self.handle_object_case(attribute_type, attribute_value, compl_data)

    # Parse observables of an external STIX document
    def parse_external_observable(self, observables):
        for observable in observables:
            title = observable.title
            observable_object = observable.object_
            try:
                properties = observable_object.properties
            except:
                self.parse_description(observable)
                continue
            if properties:
                try:
                    attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties, title=title)
                except KeyError:
                    # print("Error with an object of type: {}\n{}".format(properties._XSI_TYPE, observable.to_json()))
                    continue
                object_uuid = self.fetch_uuid(observable_object.id_)
                attr_type = type(attribute_value)
                if attr_type in (str, int):
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
                        self.dns_objects['ip'][object_uuid] = {"type": attribute_type, "value": attribute_value}
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
    def handle_object_case(self, attribute_type, attribute_value, compl_data, object_uuid=None):
        misp_object = MISPObject(attribute_type)
        if object_uuid:
            misp_object.uuid = object_uuid
        for attribute in attribute_value:
            misp_object.add_attribute(**attribute)
        if type(compl_data) is dict:
            # if some complementary data is a dictionary containing an uuid,
            # it means we are using it to add an object reference
            if "pe_uuid" in compl_data:
                misp_object.add_reference(compl_data['pe_uuid'], 'included-in')
            if "process_uuid" in compl_data:
                for uuid in compl_data["process_uuid"]:
                    misp_object.add_reference(uuid, 'connected-to')
        self.misp_event.add_object(**misp_object)

    # Extract the uuid from a stix id
    @staticmethod
    def fetch_uuid(object_id):
        try:
            identifier = object_id.split(':')[1]
            return_id = ""
            for part in identifier.split('-')[1:]:
                return_id += "{}-".format(part)
            return return_id[:-1]
        except:
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
            if coa.type_:
                attribute = {'type': 'text', 'object_relation': 'type',
                             'value': coa.type_.value}
                misp_object.add_attribute(**attribute)
            if coa.stage:
                attribute = {'type': 'text', 'object_relation': 'stage',
                             'value': coa.stage.value}
                misp_object.add_attribute(**attribute)
            if coa.description:
                attribute = {'type': 'text', 'object_relation': 'description',
                             'value': coa.description.value} # POSSIBLE ISSUE HERE, need example to test
                misp_object.add_attribute(**attribute)
            if coa.objective:
                attribute = {'type': 'text', 'object_relation': 'objective',
                             'value': coa.objective.description.value}
                misp_object.add_attribute(**attribute)
            if coa.cost:
                attribute = {'type': 'text', 'object_relation': 'cost',
                             'value': coa.cost.value.value}
                misp_object.add_attribute(**attribute)
            if coa.efficacy:
                attribute = {'type': 'text', 'object_relation': 'efficacy',
                             'value': coa.efficacy.value.value}
                misp_object.add_attribute(**attribute)
            if coa.impact:
                attribute = {'type': 'text', 'object_relation': 'impact',
                             'value': coa.impact.value.value}
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
    pathname = os.path.dirname(args[0])
    stix_parser = StixParser()
    stix_parser.load(args, pathname)
    stix_parser.handler()
    stix_parser.saveFile()
    print(1)

if __name__ == "__main__":
    main(sys.argv)
