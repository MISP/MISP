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
import pymisp
import traceback
import stix2misp_mapping
from operator import attrgetter
from collections import defaultdict
from pathlib import Path

import importlib
MODULE_TO_DIRECTORY = {
    "stix2": "cti-python-stix2",
    "stix": "python-stix",
    "cybox": "python-cybox",
    "mixbox": "mixbox",
    "misp_stix_converter": "misp-stix",
    "maec": "python-maec",
}
_CURRENT_PATH = Path(__file__).resolve().parent
_CURRENT_PATH_IDX = 0
for module_name, dir_path in MODULE_TO_DIRECTORY.items():
    try:
        importlib.import_module(module_name)
    except ImportError:
        sys.path.insert(_CURRENT_PATH_IDX, str(_CURRENT_PATH / dir_path))
        _CURRENT_PATH_IDX += 1
import stix.extensions.marking.ais
from mixbox.namespaces import NamespaceNotFoundError
from stix.core import STIXPackage
try:
    import stix_edh
except ImportError:
    pass

_MISP_dir = "/".join([p for p in os.path.dirname(os.path.realpath(__file__)).split('/')[:-3]])
_MISP_objects_path = '{_MISP_dir}/app/files/misp-objects/objects'.format(_MISP_dir=_MISP_dir)
_RFC_UUID_VERSIONS = (1, 3, 4, 5)
_UUIDv4 = uuid.UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')

from pymisp.mispevent import MISPEvent, MISPObject, MISPAttribute

categories = pymisp.AbstractMISP().describe_types.get('categories')


class StixParser():
    def __init__(self):
        super(StixParser, self).__init__()
        self.misp_event = MISPEvent()
        self.references = defaultdict(list)
        self.galaxies = set()

    ################################################################################
    ##            LOADING & UTILITY FUNCTIONS USED BY BOTH SUBCLASSES.            ##
    ################################################################################

    # Load data from STIX document, and other useful data
    def load_event(self, args, filename, from_misp, stix_version):
        self.outputname = '{}.json'.format(filename)
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
            elif not isinstance(attribute_distribution, int):
                attribute_distribution = int(attribute_distribution) if attribute_distribution.isdigit() else 5
        except IndexError:
            attribute_distribution = 5
        synonyms_to_tag_names = args[2] if len(args) > 2 else '/var/www/MISP/app/files/scripts/synonymsToTagNames.json'
        with open(synonyms_to_tag_names, 'rt', encoding='utf-8') as f:
            self.synonyms_to_tag_names = json.loads(f.read())
        self.misp_event.distribution = event_distribution
        self.__attribute_distribution = attribute_distribution
        self.from_misp = from_misp

    def build_misp_event(self, event):
        self.build_misp_dict(event)
        if self.references:
            self.build_references()
        if self.galaxies:
            for galaxy in self.galaxies:
                self.misp_event.add_tag(galaxy)

    # Convert the MISP event we create from the STIX document into json format
    # and write it in the output file
    def save_to_file(self):
        for attribute in self.misp_event.attributes:
            attribute_uuid = uuid.UUID(attribute.uuid) if isinstance(attribute.uuid, str) else attribute.uuid
            if attribute_uuid.version not in _RFC_UUID_VERSIONS:
                attribute.uuid = self._sanitize_uuid(attribute)
        for misp_object in self.misp_event.objects:
            object_uuid = uuid.UUID(misp_object.uuid) if isinstance(misp_object.uuid, str) else misp_object.uuid
            if object_uuid.version not in _RFC_UUID_VERSIONS:
                misp_object.uuid = self._sanitize_uuid(misp_object)
                for reference in misp_object.references:
                    reference.object_uuid = misp_object.uuid
                    if reference.referenced_uuid.version not in _RFC_UUID_VERSIONS:
                        reference.referenced_uuid = uuid.uuid5(_UUIDv4, str(reference.referenced_uuid))
                for attribute in misp_object.attributes:
                    if attribute.uuid.version not in _RFC_UUID_VERSIONS:
                        attribute.uuid = self._sanitize_uuid(attribute)
        eventDict = self.misp_event.to_json()
        with open(self.outputname, 'wt', encoding='utf-8') as f:
            f.write(eventDict)

    @staticmethod
    def _sanitize_uuid(misp_feature):
        comment = f'Original UUID was: {misp_feature.uuid}'
        misp_feature.comment = f'{misp_feature.comment} - {comment}' if hasattr(misp_feature, 'comment') else comment
        return uuid.uuid5(_UUIDv4, str(misp_feature.uuid))

    def parse_marking(self, handling):
        tags = []
        if hasattr(handling, 'marking_structures') and handling.marking_structures:
            for marking in handling.marking_structures:
                try:
                    tags.extend(getattr(self, stix2misp_mapping.marking_mapping[marking._XSI_TYPE])(marking))
                except KeyError:
                    print(marking._XSI_TYPE, file=sys.stderr)
                    continue
        return tags

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

    # Set info & title values in the new MISP event
    def get_event_info(self):
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
        return info

    # Get timestamp & date values in the new MISP event
    def get_timestamp_and_date(self):
        stix_date = self.event.timestamp
        try:
            date = stix_date.split("T")[0]
        except AttributeError:
            date = stix_date
        return date, self.getTimestampfromDate(stix_date)

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

    ################################################################################
    ##           STIX OBJECTS PARSING FUNCTIONS USED BY BOTH SUBCLASSES           ##
    ################################################################################

    # Define type & value of an attribute or object in MISP
    def handle_attribute_type(self, properties, is_object=False, title=None, observable_id=None):
        xsi_type = properties._XSI_TYPE
        args = [properties]
        if xsi_type in ("FileObjectType", "PDFFileObjectType", "WindowsFileObjectType"):
            args.append(is_object)
        elif xsi_type == "ArtifactObjectType":
            args.append(title)
        return getattr(self, stix2misp_mapping.attribute_types_mapping[xsi_type])(*args)

    # Return type & value of an ip address attribute
    @staticmethod
    def handle_address(properties):
        if properties.category == 'e-mail':
            attribute_type = 'email-src'
            relation = 'from'
        else:
            attribute_type = "ip-src" if properties.is_source else "ip-dst"
            relation = 'ip'
        return attribute_type, properties.address_value.value, relation

    def handle_as(self, properties):
        attributes = self.fetch_attributes_with_partial_key_parsing(properties, stix2misp_mapping._as_mapping)
        return attributes[0] if len(attributes) == 1 else ('asn', self.return_attributes(attributes), '')

    # Return type & value of an attachment attribute
    @staticmethod
    def handle_attachment(properties, title):
        if properties.hashes:
            return "malware-sample", "{}|{}".format(title, properties.hashes[0]), properties.raw_artifact.value
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
                ip = relation[1][1]
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
            attributes.extend(self.handle_email_attachment(properties))
        return attributes[0] if len(attributes) == 1 else ("email", self.return_attributes(attributes), "")

    # Return type & value of an email attachment
    def handle_email_attachment(self, properties):
        attributes = []
        related_objects = {}
        if properties.parent.related_objects:
            related_objects = {related.id_: related.properties for related in properties.parent.related_objects}
        for attachment in (attachment.object_reference for attachment in properties.attachments):
            if attachment in related_objects:
                attributes.append(["email-attachment", related_objects[attachment].file_name.value, "attachment"])
            else:
                parent_id = self.fetch_uuid(properties.parent.id_)
                referenced_id = self.fetch_uuid(attachment)
                self.references[parent_id].append({'idref': referenced_id,
                                                   'relationship': 'attachment'})
        return attributes

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
            return attribute[0] if attribute[2] != "fullpath" else "filename", attribute[1], ""
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

    # Return type & value of a link attribute
    @staticmethod
    def handle_link(properties):
        return "link", properties.value.value, "link"

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

    # Return type & value of a names pipe attribute
    @staticmethod
    def handle_pipe(properties):
        return "named pipe", properties.name.value, ""

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
        if properties.port_list:
            for port in properties.port_list:
                attributes.append(["port", port.port_value.value, "port"])
        if properties.image_info:
            if properties.image_info.file_name:
                attributes.append(["filename", properties.image_info.file_name.value, "image"])
            if properties.image_info.command_line:
                attributes.append(["text", properties.image_info.command_line.value, "command-line"])
        if properties.network_connection_list:
            references = []
            for connection in properties.network_connection_list:
                object_name, object_attributes, _ = self.handle_network_connection(connection)
                object_uuid = str(uuid.uuid4())
                misp_object = MISPObject(object_name, misp_objects_path_custom=_MISP_objects_path)
                misp_object.uuid = object_uuid
                for attribute in object_attributes:
                    misp_object.add_attribute(**attribute)
                self.misp_event.add_object(**misp_object)
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
        if properties.port:
            return "{}|port".format(type1), "{}|{}".format(value1, properties.port.port_value.value), ""
        return type1, value1, ''

    # Parse a system object to extract a mac-address attribute
    @staticmethod
    def handle_system(properties):
        if properties.network_interface_list:
            return "mac-address", str(properties.network_interface_list[0].mac), ""

    # Parse a user account object
    def handle_user(self, properties):
        attributes = self.fill_user_account_object(properties)
        return 'user-account', self.return_attributes(attributes), ''

    # Parse a UNIX user account object
    def handle_unix_user(self, properties):
        attributes = []
        if properties.user_id:
            attributes.append(['text', properties.user_id.value, 'user-id'])
        if properties.group_id:
            attributes.append(['text', properties.group_id.value, 'group-id'])
        attributes.extend(self.fill_user_account_object(properties))
        return 'user-account', self.return_attributes(attributes), ''

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

    # Parse a windows user account object
    def handle_windows_user(self, properties):
        attributes = ['text', properties.security_id.value, 'user-id'] if properties.security_id else []
        attributes.extend(self.fill_user_account_object(properties))
        return 'user-account', self.return_attributes(attributes), ''

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
                for prop in stix2misp_mapping._x509_pubkey_types:
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

    # Parse a course of action and add a MISP object to the event
    def parse_course_of_action(self, course_of_action):
        misp_object = MISPObject('course-of-action', misp_objects_path_custom=_MISP_objects_path)
        misp_object.uuid = self.fetch_uuid(course_of_action.id_)
        if course_of_action.title:
            attribute = {'type': 'text', 'object_relation': 'name',
                         'value': course_of_action.title}
            misp_object.add_attribute(**attribute)
        for prop, properties_key in stix2misp_mapping._coa_mapping.items():
            if getattr(course_of_action, prop):
                attribute = {'type': 'text', 'object_relation': prop.replace('_', ''),
                             'value': attrgetter('{}.{}'.format(prop, properties_key))(course_of_action)}
                misp_object.add_attribute(**attribute)
        if course_of_action.parameter_observables:
            for observable in course_of_action.parameter_observables.observables:
                properties = observable.object_.properties
                attribute = MISPAttribute()
                attribute.type, attribute.value, _ = self.handle_attribute_type(properties)
                referenced_uuid = str(uuid.uuid4())
                attribute.uuid = referenced_uuid
                self.misp_event.add_attribute(**attribute)
                misp_object.add_reference(referenced_uuid, 'observable', None, **attribute)
        self.misp_event.add_object(misp_object)

    # Parse attributes of a portable executable, create the corresponding object,
    # and return its uuid to build the reference for the file object generated at the same time
    def parse_pe(self, properties):
        misp_object = MISPObject('pe', misp_objects_path_custom=_MISP_objects_path)
        filename = properties.file_name.value
        for attr in ('internal-filename', 'original-filename'):
            misp_object.add_attribute(**dict(zip(('type', 'value', 'object_relation'),('filename', filename, attr))))
        if properties.headers:
            headers = properties.headers
            header_object = MISPObject('pe-section', misp_objects_path_custom=_MISP_objects_path)
            if headers.entropy:
                header_object.add_attribute(**{"type": "float", "object_relation": "entropy",
                                               "value": headers.entropy.value.value})
            file_header = headers.file_header
            misp_object.add_attribute(**{"type": "counter", "object_relation": "number-sections",
                                         "value": file_header.number_of_sections.value})
            if file_header.hashes:
                for h in file_header.hashes:
                    hash_type, hash_value, hash_relation = self.handle_hashes_attribute(h)
                    header_object.add_attribute(**{"type": hash_type, "value": hash_value, "object_relation": hash_relation})
            if file_header.size_of_optional_header:
                header_object.add_attribute(**{"type": "size-in-bytes", "object_relation": "size-in-bytes",
                                               "value": file_header.size_of_optional_header.value})
            self.misp_event.add_object(header_object)
            misp_object.add_reference(header_object.uuid, 'header-of')
        if properties.sections:
            for section in properties.sections:
                section_uuid = self.parse_pe_section(section)
                misp_object.add_reference(section_uuid, 'includes')
        self.misp_event.add_object(misp_object)
        return {"pe_uuid": misp_object.uuid}

    # Parse attributes of a portable executable section, create the corresponding object,
    # and return its uuid to build the reference for the pe object generated at the same time
    def parse_pe_section(self, section):
        section_object = MISPObject('pe-section', misp_objects_path_custom=_MISP_objects_path)
        header_hashes = section.header_hashes
        if header_hashes is None:
            header_hashes = section.data_hashes
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

    ################################################################################
    ##             MARKINGS PARSING FUNCTIONS USED BY BOTH SUBCLASSES             ##
    ################################################################################

    def parse_AIS_marking(self, marking):
        tags = []
        if hasattr(marking, 'is_proprietary') and marking.is_proprietary:
            proprietary = "Is"
            marking = marking.is_proprietary
        elif hasattr(marking, 'not_proprietary') and marking.not_proprietary:
            proprietary = "Not"
            marking = marking.not_proprietary
        else:
            return
        mapping = stix2misp_mapping._AIS_marking_mapping
        prefix = mapping['prefix']
        tags.append('{}{}'.format(prefix, mapping['proprietary'].format(proprietary)))
        if hasattr(marking, 'cisa_proprietary'):
            try:
                cisa_proprietary = marking.cisa_proprietary.numerator
                cisa_proprietary = 'true' if cisa_proprietary == 1 else 'false'
                tags.append('{}{}'.format(prefix, mapping['cisa_proprietary'].format(cisa_proprietary)))
            except AttributeError:
                pass
        for ais_field in ('ais_consent', 'tlp_marking'):
            if hasattr(marking, ais_field) and getattr(marking, ais_field):
                key, tag = mapping[ais_field]
                tags.append('{}{}'.format(prefix, tag.format(getattr(getattr(marking, ais_field), key))))
        return tags

    def parse_TLP_marking(self, marking):
        return ['tlp:{}'.format(marking.color.lower())]

    ################################################################################
    ##          FUNCTIONS HANDLING PARSED DATA, USED BY BOTH SUBCLASSES.          ##
    ################################################################################

    # The value returned by the indicators or observables parser is of type str or int
    # Thus we can add an attribute in the MISP event with the type & value
    def handle_attribute_case(self, attribute_type, attribute_value, data, attribute):
        if attribute_type in ('attachment', 'malware-sample'):
            attribute['data'] = data
        elif attribute_type == 'text':
            attribute['comment'] = data
        self.misp_event.add_attribute(attribute_type, attribute_value, **attribute)

    # The value returned by the indicators or observables parser is a list of dictionaries
    # These dictionaries are the attributes we add in an object, itself added in the MISP event
    def handle_object_case(self, name, attribute_value, compl_data, to_ids=False, object_uuid=None, test_mechanisms=[]):
        misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
        if object_uuid:
            misp_object.uuid = object_uuid
        for attribute in attribute_value:
            attribute['to_ids'] = to_ids
            misp_object.add_attribute(**attribute)
        if isinstance(compl_data, dict):
            # if some complementary data is a dictionary containing an uuid,
            # it means we are using it to add an object reference
            if "pe_uuid" in compl_data:
                misp_object.add_reference(compl_data['pe_uuid'], 'includes')
            if "process_uuid" in compl_data:
                for uuid in compl_data["process_uuid"]:
                    misp_object.add_reference(uuid, 'connected-to')
        if test_mechanisms:
            for test_mechanism in test_mechanisms:
                misp_object.add_reference(test_mechanism, 'detected-with')
        self.misp_event.add_object(misp_object)

    ################################################################################
    ##              GALAXY PARSING FUNCTIONS USED BY BOTH SUBCLASSES              ##
    ################################################################################

    @staticmethod
    def _get_galaxy_name(galaxy, feature):
        if hasattr(galaxy, feature) and getattr(galaxy, feature):
            return getattr(galaxy, feature)
        for name in ('name', 'names'):
            if hasattr(galaxy, name) and getattr(galaxy, name):
                return list(value.value for value in getattr(galaxy, name))
        return

    def _parse_courses_of_action(self, courses_of_action):
        for course_of_action in courses_of_action:
            self.parse_galaxy(course_of_action, 'title', 'mitre-course-of-action')

    def _resolve_galaxy(self, galaxy_name, default_value):
        if galaxy_name in self.synonyms_to_tag_names:
            return self.synonyms_to_tag_names[galaxy_name]
        for identifier in galaxy_name.split(' - '):
            if identifier[0].isalpha() and any(character.isdecimal() for character in identifier[1:]):
                for name, tag_names in self.synonyms_to_tag_names.items():
                    if identifier in name:
                        return tag_names
        return [f'misp-galaxy:{default_value}="{galaxy_name}"']

    ################################################################################
    ##              UTILITY FUNCTIONS USED BY PARSING FUNCTION ABOVE              ##
    ################################################################################

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
            return uuid.UUID('-'.join(object_id.split("-")[1:]))
        except Exception:
            return str(uuid.uuid4())

    @staticmethod
    def fill_user_account_object(properties):
        attributes = []
        for feature, mapping in stix2misp_mapping._user_account_object_mapping.items():
            if getattr(properties, feature):
                attribute_type, relation = mapping
                attributes.append([attribute_type, getattr(properties, feature).value, relation])
        return attributes

    # Return the attributes that will be added in a MISP object as a list of dictionaries
    @staticmethod
    def return_attributes(attributes):
        return_attributes = []
        for attribute in attributes:
            return_attributes.append(dict(zip(('type', 'value', 'object_relation'), attribute)))
        return return_attributes


class StixFromMISPParser(StixParser):
    def __init__(self):
        super(StixFromMISPParser, self).__init__()
        self.dates = set()
        self.timestamps = set()
        self.titles = set()

    def build_misp_dict(self, event):
        for item in event.related_packages.related_package:
            package = item.item
            self.event = package.incidents[0]
            self.parse_related_galaxies()
            self.fetch_timestamp_and_date()
            self.fetch_event_info()
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
            if package.courses_of_action:
                self._parse_courses_of_action(package.courses_of_action)
            if package.threat_actors:
                self._parse_threat_actors(package.threat_actors)
            if package.ttps:
                for ttp in package.ttps.ttp:
                    ttp_id = '-'.join((part for part in ttp.id_.split('-')[-5:]))
                    ttp_type = 'object' if ttp_id in self.object_references else 'galaxy'
                    self.parse_ttp(ttp, ttp_type, ttp_id)
                    # if ttp.handling:
                    #     self.parse_tlp_marking(ttp.handling)
        self.set_event_fields()

    def parse_galaxy(self, galaxy, feature, default_value):
        names = self._get_galaxy_name(galaxy, feature)
        if names:
            if isinstance(names, list):
                for name in names:
                    self.galaxies.update(self._resolve_galaxy(name, default_value))
            else:
                self.galaxies.update(self._resolve_galaxy(names, default_value))

    def parse_ttp(self, ttp, ttp_type, ttp_id):
        if ttp_type == 'object':
            if ttp.behavior:
                if ttp.behavior.attack_patterns:
                    for attack_pattern in ttp.behavior.attack_patterns:
                        self.parse_attack_pattern_object(attack_pattern, ttp_id)
            elif ttp.exploit_targets and ttp.exploit_targets.exploit_target:
                for exploit_target in ttp.exploit_targets.exploit_target:
                    if exploit_target.item.vulnerabilities:
                        for vulnerability in exploit_target.item.vulnerabilities:
                            self.parse_vulnerability_object(vulnerability, ttp_id)
                    if exploit_target.item.weaknesses:
                        for weakness in exploit_target.item.weaknesses:
                            self.parse_weakness_object(weakness, ttp_id)
        else:
            self._parse_ttp(ttp)

    def parse_attack_pattern_object(self, attack_pattern, uuid):
        attribute_type = 'text'
        attributes = []
        for key, relation in stix2misp_mapping._attack_pattern_object_mapping.items():
            value = getattr(attack_pattern, key)
            if value:
                attributes.append({'type': attribute_type, 'object_relation': relation,
                                   'value': value if isinstance(value, str) else value.value})
        if attributes:
            attack_pattern_object = MISPObject('attack-pattern')
            attack_pattern_object.uuid = uuid
            for attribute in attributes:
                attack_pattern_object.add_attribute(**attribute)
            self.misp_event.add_object(**attack_pattern_object)

    def _parse_threat_actors(self, threat_actors):
        for threat_actor in threat_actors:
            self.parse_galaxy(threat_actor, 'title', 'threat-actor')

    def _parse_ttp(self, ttp):
        if ttp.behavior:
            if ttp.behavior.attack_patterns:
                for attack_pattern in ttp.behavior.attack_patterns:
                    self.parse_galaxy(attack_pattern, 'title', 'misp-attack-pattern')
            if ttp.behavior.malware_instances:
                for malware_instance in ttp.behavior.malware_instances:
                    if not malware_instance._XSI_TYPE or 'stix-maec' not in malware_instance._XSI_TYPE:
                        self.parse_galaxy(malware_instance, 'title', 'ransomware')
        elif ttp.exploit_targets:
            if ttp.exploit_targets.exploit_target:
                for exploit_target in ttp.exploit_targets.exploit_target:
                    if exploit_target.item.vulnerabilities:
                        for vulnerability in exploit_target.item.vulnerabilities:
                            self.parse_galaxy(vulnerability, 'title', 'branded-vulnerability')
        elif ttp.resources:
            if ttp.resources.tools:
                for tool in ttp.resources.tools:
                    self.parse_galaxy(tool, 'name', 'tool')

    def parse_vulnerability_object(self, vulnerability, uuid):
        attributes = []
        for key, mapping in stix2misp_mapping._vulnerability_object_mapping.items():
            value = getattr(vulnerability, key)
            if value:
                attribute_type, relation = mapping
                attributes.append({'type': attribute_type, 'object_relation': relation,
                                   'value': value if isinstance(value, str) else value.value})
        if attributes:
            if len(attributes) == 1 and attributes[0]['object_relation'] == 'id':
                attributes = attributes[0]
                attributes['uuid'] = uuid
                attributes['type'] = 'vulnerability'
                self.misp_event.add_attribute(**attributes)
            else:
                vulnerability_object = MISPObject('vulnerability')
                vulnerability_object.uuid = uuid
                for attribute in attributes:
                    vulnerability_object.add_attribute(**attribute)
                self.misp_event.add_object(**vulnerability_object)

    def parse_weakness_object(self, weakness, uuid):
        attribute_type = 'text'
        attributes = []
        for key, relation in stix2misp_mapping._weakness_object_mapping.items():
            value = getattr(weakness, key)
            if value:
                attributes.append({'type': attribute_type, 'object_relation': relation,
                                   'value': value if isinstance(value, str) else value.value})
        if attributes:
            weakness_object = MISPObject('weakness')
            weakness_object.uuid = uuid
            for attribute in attributes:
                weakness_object.add_attribute(**attribute)
            self.misp_event.add_object(**weakness_object)

    # Return type & attributes (or value) of a Custom Object
    def handle_custom(self, properties):
        custom_properties = properties.custom_properties
        attributes = []
        for prop in custom_properties:
            attribute_type, relation = prop.name.split(': ')
            attribute_type = attribute_type.split(' ')[1]
            attributes.append([attribute_type, prop.value, relation])
        if len(attributes) > 1:
            name = custom_properties[0].name.split(' ')[0]
            return name, self.return_attributes(attributes), ""
        return attributes[0]

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
                    self.misp_event.threat_level_id = stix2misp_mapping.threat_level_mapping[entry_value]
            except ValueError:
                continue

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
        item = indicator.item
        misp_attribute = {'to_ids': True, 'category': str(indicator.relationship),
                          'uuid': self.fetch_uuid(item.id_)}
        misp_attribute['timestamp'] = self.getTimestampfromDate(item.timestamp)
        if item.observable:
            observable = item.observable
            self.parse_misp_attribute(observable, misp_attribute, to_ids=True)

    def parse_misp_attribute_observable(self, observable):
        if observable.item:
            misp_attribute = {'to_ids': False, 'category': str(observable.relationship),
                              'uuid': self.fetch_uuid(observable.item.id_)}
            self.parse_misp_attribute(observable.item, misp_attribute)

    def parse_misp_attribute(self, observable, misp_attribute, to_ids=False):
        try:
            properties = observable.object_.properties
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties, title=observable.title)
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

    # Parse STIX object that we know will give MISP objects
    def parse_misp_object_indicator(self, indicator):
        name = self._define_name(indicator.item.observable, indicator.relationship)
        if name not in ('passive-dns'):
            self.fill_misp_object(indicator.item, name, to_ids=True)
        else:
            if str(indicator.relationship) != "misc":
                print(f"Unparsed Object type: {name}\n{indicator.to_json()}", file=sys.stderr)

    def parse_misp_object_observable(self, observable):
        name = self._define_name(observable.item, observable.relationship)
        try:
            self.fill_misp_object(observable, name)
        except Exception:
            print("Unparsed Object type: {}".format(observable.to_json()), file=sys.stderr)

    # Create a MISP object, its attributes, and add it in the MISP event
    def fill_misp_object(self, item, name, to_ids=False):
        uuid = self.fetch_uuid(item.id_)
        if any(((hasattr(item, 'observable') and hasattr(item.observable, 'observable_composition') and item.observable.observable_composition),
                (hasattr(item, 'observable_composition') and item.observable_composition))):
            misp_object = MISPObject(name, misp_objects_path_custom=_MISP_objects_path)
            misp_object.uuid = uuid
            if to_ids:
                observables = item.observable.observable_composition.observables
                misp_object.timestamp = self.getTimestampfromDate(item.timestamp)
            else:
                observables = item.observable_composition.observables
            args = (misp_object, observables, to_ids)
            self.handle_file_composition(*args) if name == 'file' else self.handle_composition(*args)
            self.misp_event.add_object(**misp_object)
        else:
            properties = item.observable.object_.properties if to_ids else item.object_.properties
            self.parse_observable(properties, to_ids, uuid)

    def  handle_file_composition(self, misp_object, observables, to_ids):
        for observable in observables:
            attribute_type, attribute_value, compl_data = self.handle_attribute_type(observable.object_.properties, title=observable.title)
            if isinstance(attribute_value, str):
                misp_object.add_attribute(**{'type': attribute_type, 'value': attribute_value,
                                             'object_relation': attribute_type, 'to_ids': to_ids,
                                             'data': compl_data})
            else:
                for attribute in attribute_value:
                    attribute['to_ids'] = to_ids
                    misp_object.add_attribute(**attribute)
        return misp_object

    def handle_composition(self, misp_object, observables, to_ids):
        for observable in observables:
            properties = observable.object_.properties
            attribute = MISPAttribute()
            attribute.type, attribute.value, attribute.object_relation = self.handle_attribute_type(properties)
            if 'Port' in observable.id_:
                attribute.object_relation = f"{observable.id_.split('-')[0].split(':')[1][:3]}-{attribute.object_relation}"
            attribute.to_ids = to_ids
            misp_object.add_attribute(**attribute)
        return misp_object

    # Create a MISP attribute and add it in its MISP object
    def parse_observable(self, properties, to_ids, uuid):
        attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
        if isinstance(attribute_value, (str, int)):
            attribute = {'to_ids': to_ids, 'uuid': uuid}
            self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
        else:
            self.handle_object_case(attribute_type, attribute_value, compl_data, to_ids=to_ids, object_uuid=uuid)

    def parse_tag(self, entry):
        self.misp_event.add_tag(entry)

    def parse_vulnerability(self, exploit_targets):
        for exploit_target in exploit_targets:
            if exploit_target.item:
                for vulnerability in exploit_target.item.vulnerabilities:
                    self.misp_event.add_attribute(**{'type': 'vulnerability', 'value': vulnerability.cve_id})

    def parse_related_galaxies(self):
        object_references = []
        for coa_taken in self.event.coa_taken:
            self.parse_course_of_action(coa_taken.course_of_action)
        if self.event.attributed_threat_actors:
            object_references.extend([ta.item.idref for ta in self.event.attributed_threat_actors.threat_actor])
        if self.event.leveraged_ttps and self.event.leveraged_ttps.ttp:
            object_references.extend([ttp.item.idref for ttp in self.event.leveraged_ttps.ttp])
        self.object_references = tuple('-'.join((r for r in ref.split('-')[-5:])) for ref in object_references if ref is not None)

    @staticmethod
    def _define_name(observable, relationship):
        observable_id = observable.id_
        if relationship == "file":
            return "registry-key" if "WinRegistryKey" in observable_id else "file"
        if "Custom" in observable_id:
            return observable_id.split("Custom")[0].split(":")[1]
        if relationship == "network":
            if "ObservableComposition" in observable_id:
                return observable_id.split("_")[0].split(":")[1]
            return stix2misp_mapping.cybox_to_misp_object[observable_id.split('-')[0].split(':')[1]]
        return stix2misp_mapping.cybox_to_misp_object[observable_id.split('-')[0].split(':')[1]]

    def fetch_event_info(self):
        info = self.get_event_info()
        self.titles.add(info)

    def fetch_timestamp_and_date(self):
        if self.event.timestamp:
            date, timestamp = self.get_timestamp_and_date()
            self.dates.add(date)
            self.timestamps.add(timestamp)

    def set_event_fields(self):
        self.set_distribution()
        for field, misp_field in zip(['titles', 'dates', 'timestamps'], ['info', 'date', 'timestamp']):
            attribute = list(getattr(self, field))
            if len(attribute) == 1:
                setattr(self.misp_event, misp_field, attribute[0])


class ExternalStixParser(StixParser):
    def __init__(self):
        super(ExternalStixParser, self).__init__()
        self.dns_objects = defaultdict(dict)
        self.dns_ips = []

    def build_misp_dict(self, event):
        self.event = event
        self.set_timestamp_and_date()
        self.set_event_info()
        header = self.event.stix_header
        if hasattr(header, 'description') and hasattr(header.description, 'value') and header.description.value:
            self.misp_event.add_attribute(**{'type': 'comment', 'value': header.description.value,
                                             'comment': 'Imported from STIX header description'})
        if hasattr(header, 'handling') and header.handling:
            for handling in header.handling:
                tags = self.parse_marking(handling)
                for tag in  tags:
                    self.misp_event.add_tag(tag)
        if self.event.indicators:
            self.parse_external_indicators(self.event.indicators)
        if self.event.observables:
            self.parse_external_observable(self.event.observables.observables)
        if any(getattr(self.event, feature) for feature in ('ttps', 'courses_of_action', 'threat_actors')):
            if self.event.ttps:
                self.parse_ttps(self.event.ttps.ttp)
            if self.event.courses_of_action:
                self.parse_coa(self.event.courses_of_action)
            if self.event.threat_actors:
                self._parse_threat_actors(self.event.threat_actors)
        if self.dns_objects:
            self.resolve_dns_objects()
        self.set_distribution()

    def set_event_info(self):
        info =  self.get_event_info()
        self.misp_event.info = str(info)

    def set_timestamp_and_date(self):
        if self.event.timestamp:
            date, timestamp = self.get_timestamp_and_date()
            self.misp_event.date = date
            self.misp_event.timestamp = timestamp

    # Return type & attributes (or value) of a Custom Object
    def handle_custom(self, properties):
        custom_properties = properties.custom_properties
        if len(custom_properties) > 1:
            for prop in custom_properties[:-1]:
                misp_attribute = {'type': 'text', 'value': prop.value, 'comment': prop.name}
                self.misp_event.add_attribute(**misp_attribute)
        to_return = custom_properties[-1]
        return 'text', to_return.value, to_return.name

    # Parse the courses of action field of an external STIX document
    def parse_coa(self, courses_of_action):
        for coa in courses_of_action:
            self.parse_course_of_action(coa)

    # Parse description of an external indicator or observable and add it in the MISP event as an attribute
    def parse_description(self, stix_object):
        if stix_object.description:
            misp_attribute = {}
            if stix_object.timestamp:
                misp_attribute['timestamp'] = self.getTimestampfromDate(stix_object.timestamp)
            self.misp_event.add_attribute("text", stix_object.description.value, **misp_attribute)

    # Parse indicators of an external STIX document
    def parse_external_indicators(self, indicators):
        for indicator in indicators:
            if hasattr(indicator, 'related_indicators') and indicator.related_indicators:
                for related_indicator in indicator.related_indicators:
                    self.parse_external_single_indicator(related_indicator)
            else:
                self.parse_external_single_indicator(indicator)

    def parse_external_single_indicator(self, indicator):
        test_mechanisms = []
        if hasattr(indicator, 'test_mechanisms') and indicator.test_mechanisms:
            for test_mechanism in indicator.test_mechanisms:
                try:
                    attribute_type = stix2misp_mapping.test_mechanisms_mapping[test_mechanism._XSI_TYPE]
                except KeyError:
                    print(f'Unknown Test Mechanism type: {test_mechanism._XSI_TYPE}', file=sys.stderr)
                    continue
                if test_mechanism.rule.value is None:
                    continue
                attribute = MISPAttribute()
                attribute.from_dict(**{
                    'type': attribute_type,
                    'value': test_mechanism.rule.value
                })
                self.misp_event.add_attribute(**attribute)
                test_mechanisms.append(attribute.uuid)
        if hasattr(indicator, 'observable') and indicator.observable:
            observable = indicator.observable
            if self._has_properties(observable):
                properties = observable.object_.properties
                uuid = self.fetch_uuid(observable.object_.id_)
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                if isinstance(attribute_value, (str, int)):
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': True, 'uuid': uuid}
                    if indicator.timestamp:
                        attribute['timestamp'] = self.getTimestampfromDate(indicator.timestamp)
                    if hasattr(observable, 'handling') and observable.handling:
                        attribute['Tag'] = []
                        for handling in observable.handling:
                            attribute['Tag'].extend(self.parse_marking(handling))
                    parsed = self.special_parsing(observable.object_, attribute_type, attribute_value, attribute, uuid)
                    if parsed is not None:
                        return
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    if attribute_value:
                        if all(isinstance(value, dict) for value in attribute_value):
                            # it is a list of attributes, so we build an object
                            self.handle_object_case(
                                attribute_type,
                                attribute_value,
                                compl_data,
                                to_ids=True,
                                object_uuid=uuid,
                                test_mechanisms=test_mechanisms
                            )
                        else:
                            # it is a list of attribute values, so we add single attributes
                            for value in attribute_value:
                                self.misp_event.add_attribute(**{'type': attribute_type, 'value': value, 'to_ids': True})
            elif hasattr(observable, 'observable_composition') and observable.observable_composition:
                self.parse_external_observable(observable.observable_composition.observables, to_ids=True)
            else:
                self.parse_description(indicator)

    # Parse observables of an external STIX document
    def parse_external_observable(self, observables, to_ids=False):
        for observable in observables:
            if self._has_properties(observable):
                observable_object = observable.object_
                properties = observable_object.properties
                try:
                    attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties, title=observable.title)
                except Exception:
                    print(f'Error with the following {properties._XSI_TYPE} object:\n{observable.to_json()}', file=sys.stderr)
                    continue
                object_uuid = self.fetch_uuid(observable_object.id_)
                if isinstance(attribute_value, (str, int)):
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': to_ids, 'uuid': object_uuid}
                    if hasattr(observable, 'handling') and observable.handling:
                        attribute['Tag'] = []
                        for handling in observable.handling:
                            attribute['Tag'].extend(self.parse_marking(handling))
                    parsed = self.special_parsing(observable_object, attribute_type, attribute_value, attribute, object_uuid)
                    if parsed is not None:
                        continue
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    if attribute_value:
                        if all(isinstance(value, dict) for value in attribute_value):
                            # it is a list of attributes, so we build an object
                            self.handle_object_case(attribute_type, attribute_value, compl_data, object_uuid=object_uuid)
                        else:
                            # it is a list of attribute values, so we add single attributes
                            for value in attribute_value:
                                self.misp_event.add_attribute(**{'type': attribute_type, 'value': value, 'to_ids': False})
                    if observable_object.related_objects:
                        for related_object in observable_object.related_objects:
                            relationship = related_object.relationship.value.lower().replace('_', '-')
                            self.references[object_uuid].append({"idref": self.fetch_uuid(related_object.idref),
                                                                 "relationship": relationship})
            else:
                self.parse_description(observable)

    def parse_galaxy(self, galaxy, feature, default_value):
        names = self._get_galaxy_name(galaxy, feature)
        if names:
            if isinstance(names, list):
                galaxies = []
                for name in names:
                    galaxies.extend(self._resolve_galaxy(name, default_value))
                return galaxies
            return self._resolve_galaxy(names, default_value)

    def _parse_threat_actors(self, threat_actors):
        for threat_actor in threat_actors:
            if hasattr(threat_actor, 'title') and threat_actor.title:
                self.galaxies.update(self.parse_galaxy(threat_actor, 'title', 'threat-actor'))
            else:
                if hasattr(threat_actor, 'identity') and threat_actor.identity:
                    identity = threat_actor.identity
                    if hasattr(identity, 'name') and identity.name:
                        self.galaxies.update(self._resolve_galaxy(identity.name, 'threat-actor'))
                    elif hasattr(identity, 'specification') and hasattr(identity.specification, 'party_name') and identity.specification.party_name:
                        party_name = identity.specification.party_name
                        if hasattr(party_name, 'person_names') and party_name.person_names:
                            for person_name in party_name.person_names:
                                self.galaxies.update(self._resolve_galaxy(person_name.name_elements[0].value, 'threat-actor'))
                        elif hasattr(party_name, 'organisation_names') and party_name.organisation_names:
                            for organisation_name in party_name.organisation_names:
                                self.galaxies.update(self._resolve_galaxy(organisation_name.name_elements[0].value, 'threat-actor'))

    # Parse the ttps field of an external STIX document
    def parse_ttps(self, ttps):
        for ttp in ttps:
            _has_infrastructure = ttp.resources is not None and ttp.resources.infrastructure is not None
            _has_exploit_target = ttp.exploit_targets is not None and ttp.exploit_targets.exploit_target is not None
            _has_vulnerability = self._has_vulnerability(ttp.exploit_targets.exploit_target) if _has_exploit_target else False
            galaxies = self.parse_galaxies_from_ttp(ttp)
            if _has_infrastructure or _has_vulnerability:
                attributes = self.parse_attributes_from_ttp(ttp, galaxies)
                if attributes:
                    for attribute in attributes:
                        misp_attribute = MISPAttribute()
                        misp_attribute.from_dict(**attribute)
                        for galaxy in galaxies:
                            misp_attribute.add_tag(galaxy)
                        self.misp_event.add_attribute(**misp_attribute)
                    continue
            self.galaxies.update(galaxies)

    # Parse ttps that could give attributes
    def parse_attributes_from_ttp(self, ttp, galaxies):
        attributes = []
        if ttp.resources and ttp.resources.infrastructure and ttp.resources.infrastructure.observable_characterization:
            observables = ttp.resources.infrastructure.observable_characterization
            if observables.observables:
                for observable in observables.observables:
                    if self._has_properties(observable):
                        properties = observable.object_.properties
                        try:
                            attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                        except Exception as e:
                            print(f'Error with the following {properties._XSI_TYPE} object:\n{observable.to_json()}', file=sys.stderr)
                            continue
                        if isinstance(attribute_value, list):
                            attributes.extend([{'type': attribute_type, 'value': value, 'to_ids': False} for value in attribute_value])
                        else:
                            attributes.append({'type': attribute_type, 'value': attribute_value, 'to_ids': False})
        if ttp.exploit_targets and ttp.exploit_targets.exploit_target:
            for exploit_target in ttp.exploit_targets.exploit_target:
                if exploit_target.item.vulnerabilities:
                    for vulnerability in exploit_target.item.vulnerabilities:
                        if vulnerability.cve_id:
                            attributes.append({'type': 'vulnerability', 'value': vulnerability.cve_id})
                        elif vulnerability.title:
                            title = vulnerability.title
                            if title in self.synonyms_to_tag_names:
                                galaxies.update(self.synonyms_to_tag_names[title])
                            else:
                                galaxies.add(f'misp-galaxy:branded-vulnerability="{title}"')
        if len(attributes) == 1:
            attributes[0]['uuid'] = '-'.join((part for part in ttp.id_.split('-')[-5:]))
        return attributes

    # Parse ttps that are always turned into galaxies and return the tag names
    def parse_galaxies_from_ttp(self, ttp):
        galaxies = set()
        if ttp.behavior:
            if ttp.behavior.attack_patterns:
                for attack_pattern in ttp.behavior.attack_patterns:
                    try:
                        galaxies.update(self.parse_galaxy(attack_pattern, 'title', 'misp-attack-pattern'))
                    except TypeError:
                        print(f'No valuable data to parse in the following attack-pattern: {attack_pattern.to_json()}', file=sys.stderr)
            if ttp.behavior.malware_instances:
                for malware_instance in ttp.behavior.malware_instances:
                    try:
                        galaxies.update(self.parse_galaxy(malware_instance, 'title', 'ransomware'))
                    except TypeError:
                        print(f'No valuable data to parse in the following malware instance: {malware_instance.to_json()}', file=sys.stderr)
        if ttp.resources:
            if ttp.resources.tools:
                for tool in ttp.resources.tools:
                    try:
                        galaxies.update(self.parse_galaxy(tool, 'name', 'tool'))
                    except TypeError:
                        print(f'No valuable data to parse in the following tool: {tool.to_json()}', file=sys.stderr)
        return galaxies

    # Parse a DNS object
    def resolve_dns_objects(self):
        for domain, domain_dict in self.dns_objects['domain'].items():
            ip_reference = domain_dict['related']
            domain_attribute = domain_dict['data']
            if ip_reference in self.dns_objects['ip']:
                misp_object = MISPObject('passive-dns', misp_objects_path_custom=_MISP_objects_path)
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

    def special_parsing(self, observable_object, attribute_type, attribute_value, attribute, uuid):
        if observable_object.related_objects:
            related_objects = observable_object.related_objects
            if attribute_type == "url" and len(related_objects) == 1 and related_objects[0].relationship.value == "Resolved_To":
                related_ip = self.fetch_uuid(related_objects[0].idref)
                self.dns_objects['domain'][uuid] = {"related": related_ip,
                                                    "data": {"type": "text", "value": attribute_value}}
                if related_ip not in self.dns_ips:
                    self.dns_ips.append(related_ip)
                return 1
        if attribute_type in ('ip-src', 'ip-dst'):
            attribute['type'] = attribute_type
            attribute['value'] = attribute_value
            self.dns_objects['ip'][uuid] = attribute
            return 2

    @staticmethod
    def _has_properties(observable):
        if not hasattr(observable, 'object_') or not observable.object_:
            return False
        if hasattr(observable.object_, 'properties') and observable.object_.properties:
            return True
        return False

    @staticmethod
    def _has_vulnerability(exploit_targets):
        return any(exploit_target.item.vulnerability is not None for exploit_target in exploit_targets)


def _update_namespaces():
    from mixbox.namespaces import Namespace, register_namespace
    # LIST OF ADDITIONAL NAMESPACES
    # can add additional ones whenever it is needed
    ADDITIONAL_NAMESPACES = [
        Namespace('http://us-cert.gov/ciscp', 'CISCP',
                  'http://www.us-cert.gov/sites/default/files/STIX_Namespace/ciscp_vocab_v1.1.1.xsd'),
        Namespace('http://taxii.mitre.org/messages/taxii_xml_binding-1.1', 'TAXII',
                  'http://docs.oasis-open.org/cti/taxii/v1.1.1/cs01/schemas/TAXII-XMLMessageBinding-Schema.xsd')
    ]
    for namespace in ADDITIONAL_NAMESPACES:
        register_namespace(namespace)


def generate_event(filename, tries=0):
    try:
        return STIXPackage.from_xml(filename)
    except NamespaceNotFoundError:
        if tries == 1:
            print(json.dumps({'error': 'Cannot handle STIX namespace'}))
            sys.exit(1)
        _update_namespaces()
        return generate_event(filename, 1)
    except NotImplementedError:
        print(json.dumps({'error': 'Missing python library: stix_edh'}))
        sys.exit(1)
    except Exception as e:
        try:
            import maec
            print(json.dumps({'error': f'Error while loading the STIX file: {e.__str__()}'}))
        except ImportError:
            print(json.dumps({'error': 'Missing python library: maec'}))
        sys.exit(1)


def is_from_misp(event):
    try:
        title = event.stix_header.title
    except AttributeError:
        return False
    return 'Export from ' in title and 'MISP' in title


def main(args):
    filename = args[1] if args[1][0] == '/' else '{}/tmp/{}'.format(os.path.dirname(args[0]), args[1])
    event = generate_event(filename)
    from_misp = is_from_misp(event)
    try:
        stix_parser = StixFromMISPParser() if from_misp else ExternalStixParser()
        stix_parser.load_event(args[2:], filename, from_misp, event.version)
        stix_parser.build_misp_event(event)
        stix_parser.save_to_file()
        print(json.dumps({'success': 1}))
        sys.exit(0)
    except Exception as e:
        error = type(e).__name__ + ': ' + e.__str__()
        print(json.dumps({'error': error}))
        traceback.print_tb(e.__traceback__)
        print(error, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
