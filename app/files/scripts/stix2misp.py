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

import sys, json, os, time
import pymisp
from stix.core import STIXPackage

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

descFilename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
with open(descFilename, 'r') as f:
    categories = json.loads(f.read())['result'].get('categories')

class StixParser():
    def __init__(self):
        self.misp_event = pymisp.MISPEvent()

    def loadEvent(self, args, pathname):
        try:
            filename = '{}/tmp/{}'.format(pathname, args[1])
            event = STIXPackage.from_xml(filename)
            if "CIRCL:Package" in event.id_ and "CIRCL MISP" in event.stix_header.title:
                fromMISP = True
            else:
                fromMISP = False
            if fromMISP:
                self.event = event.related_packages.related_package[0].item.incidents[0]
            else:
                self.event = event
            self.fromMISP = fromMISP
            self.filename = filename
        except:
            print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
            sys.exit(0)

    def handler(self):
        self.outputname = '{}.json'.format(self.filename)
        if self.fromMISP:
            # STIX format coming from a MISP export
            self.buildMispDict()
        else:
            # external STIX format file
            self.buildExternalDict()

    def buildMispDict(self):
        self.dictTimestampAndDate()
        self.eventInfo()
        for indicator in self.event.related_indicators.indicator:
            self.parse_misp_indicator(indicator)

    def buildExternalDict(self):
        self.dictTimestampAndDate()
        self.eventInfo()
        if self.event.indicators:
            self.parse_external_indicator(self.event.indicators)
        if self.event.observables:
            self.parse_external_observable(self.event.observables.observables)
        if self.event.ttps:
            self.parse_ttps(self.event.ttps.ttps)

    def dictTimestampAndDate(self):
        if self.event.timestamp:
            stixTimestamp = self.event.timestamp
            try:
                date = stixTimestamp.split("T")[0]
            except AttributeError:
                date = stixTimestamp
            self.misp_event.date = date
            self.misp_event.timestamp = self.getTimestampfromDate(stixTimestamp)

    def getTimestampfromDate(self, date):
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

    def eventInfo(self):
        try:
            try:
                info = self.event.stix_header.title
            except:
                info = self.event.title
            if info:
                self.misp_event.info = info
            else:
                raise Exception("Imported from external STIX event")
        except Exception as noinfo:
            self.misp_event.info = str(noinfo)

    def parse_misp_indicator(self, indicator):
        # define is an indicator will be imported as attribute or object
        if indicator.relationship in categories:
            self.parse_misp_attribute(indicator)
        else:
            self.parse_misp_object(indicator)

    def parse_misp_attribute(self, indicator):
        misp_attribute = {'category': str(indicator.relationship)}
        item = indicator.item
        misp_attribute['timestamp'] = self.getTimestampfromDate(item.timestamp)
        if item.observable:
            observable = item.observable
            try:
                properties = observable.object_.properties
                if properties:
                    attribute_type, attribute_value, _ = self.handle_attribute_type(properties)
                    self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attribute)
            except AttributeError:
                attribute_dict = {}
                for observables in observable.observable_composition.observables:
                    properties = observables.object_.properties
                    attribute_type, attribute_value, _ = self.handle_attribute_type(properties)
                    attribute_dict[attribute_type] = attribute_value
                attribute_type, attribute_value = self.composite_type(attribute_dict)
                self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attribute)

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

    def handle_attribute_type(self, properties, is_object=False, title=None):
        xsi_type = properties._XSI_TYPE
        if xsi_type == 'AddressObjectType':
            return self.handle_address(properties)
        elif xsi_type == 'EmailMessageObjectType':
            return self.handle_email_attribute(properties)
        elif xsi_type == 'DomainNameObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.value.value, event_types['relation']
        elif xsi_type == 'FileObjectType' or xsi_type == 'PDFFileObjectType':
            return self.handle_file(properties, is_object)
        elif xsi_type == 'HostnameObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.hostname_value.value, event_types['relation']
        elif xsi_type == 'HTTPSessionObjectType':
            return self.handle_http(properties)
        elif xsi_type == 'MutexObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.name.value, event_types['relation']
        elif xsi_type == 'PortObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.port_value.value, event_types['relation']
        elif xsi_type == 'SocketAddressObjectType':
            return self.handle_socket_address(properties)
        elif xsi_type == 'URIObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.value.value, event_types['relation']
        elif xsi_type == "WhoisObjectType":
            return self.handle_whois(properties)
        elif xsi_type == 'WindowsRegistryKeyObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.key.value, event_types['relation']
        elif xsi_type == "WindowsExecutableFileObjectType":
            return self.handle_pe(properties)
        elif xsi_type == "ArtifactObjectType":
            return eventTypes[xsi_type]['type'], title, properties.raw_artifact.value
        else:
            # ATM USED TO TEST TYPES
            print("Unparsed type: {}".format(xsi_type))
            sys.exit(1)

    @staticmethod
    def handle_address(properties):
        if properties.is_source:
            ip_type = "ip-src"
        else:
            ip_type = "ip-dst"
        return ip_type, properties.address_value.value, "ip"

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
        else:
            # ATM USED TO TEST EMAIL PROPERTIES
            print("Unsupported Email property")
            sys.exit(1)

    @staticmethod
    def handle_email_attachment(indicator_object):
        properties = indicator_object.related_objects[0].properties
        return "email-attachment", properties.file_name.value, "attachment"

    def handle_file(self, properties, is_object):
        b_hash, b_file = False, False
        attributes = []
        if properties.hashes:
            b_hash = True
            for h in properties.hashes:
                attributes.append(self.handle_hashes_attribute(h))
        if properties.file_format and properties.file_format.value:
            attributes.append(["mime-type", properties.file_format.value, "mimetype"])
        if properties.file_name or properties.file_path:
            try:
                value = properties.file_name.value
            except AttributeError:
                value = properties.file_path.value
            if value:
                b_file = True
                event_types = eventTypes[properties._XSI_TYPE]
                attributes.append([event_types['type'], value, event_types['relation']])
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
        return "file", self.return_attributes(attributes), ""

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

    @staticmethod
    def handle_hashes_attribute(properties):
        hash_type = properties.type_.value.lower()
        try:
            hash_value = properties.simple_hash_value.value
        except AttributeError:
            hash_value = properties.fuzzy_hash_value.value
        return hash_type, hash_value, hash_type

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

    def handle_socket_address(self, properties):
        if properties.ip_address:
            type1, value1, _ = self.handle_address(properties.ip_address)
        elif properties.hostname:
            type1 = "hostname"
            value1 = properties.hostname.hostname_value.value
        return "{}|port".format(type1), "{}|{}".format(value1, properties.port.port_value.value), ""

    def handle_whois(self, properties):
        required_one_of = False
        attributes = []
        if properties.remarks:
            attribute_type = "text"
            attributes.append([attribute_type, properties.remarks.value, attribute_type])
            required_one_of = True
        if properties.registrar_info:
            attribute_type = "whois-registrar"
            attributes.append([attribute_type, properties.registrar_info.value, attribute_type])
            required_one_of = True
        if properties.registrants:
            print(dir(properties.registrants))
        if properties.creation_date:
            attributes.append(["datetime", properties.creation_date.value, "creation-date"])
            required_one_of = True
        if properties.updated_date:
            attributes.append(["datetime", properties.updated_date.value, "modification-date"])
        if properties.expiration_date:
            attributes.append(["datetime", properties.expiration_date.value, "expiration-date"])
        if properties.nameservers:
            for nameserver in properties.nameservers:
                attributes.append(["hostname", nameserver.value.value, "nameserver"])
        if properties.ip_address:
            attributes.append(["ip-dst", properties.ip_address.value, "ip-address"])
            required_one_of = True
        if properties.domain_name:
            attribute_type = "domain"
            attributes.append([attribute_type, properties.domain_name.value, attribute_type])
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

    def handle_pe(self, properties):
        pe_uuid = self.parse_pe(properties)
        file_type, file_value, _ = self.handle_file(properties, False)
        return file_type, file_value, pe_uuid

    def parse_pe(self, properties):
        misp_object = pymisp.MISPObject('pe')
        filename = properties.file_name.value
        for attr in ('internal-filename', 'original-filename'):
            misp_object.add_attribute(**dict(zip(('type', 'value', 'object_relation'),('filename', filename, attr))))
        if properties.headers:
            headers = properties.headers
            header_object = pymisp.MISPObject('pe-section')
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
            misp_object.add_reference(header_object.uuid, 'pe-section')
        if properties.sections:
            for section in properties.sections:
                section_uuid = self.parse_pe_section(section)
                misp_object.add_reference(section_uuid, 'pe-section')
        self.misp_event.add_object(**misp_object)
        return {"pe_uuid": misp_object.uuid}

    def parse_pe_section(self, section):
        section_object = pymisp.MISPObject('pe-section')
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

    def parse_misp_object(self, indicator):
        object_type = str(indicator.relationship)
        if object_type == 'file':
            item = indicator.item
            self.fill_misp_object(item, object_type)
        elif object_type == 'network':
            item = indicator.item
            name = item.title.split(' ')[0]
            if name not in ('passive-dns'):
                self.fill_misp_object(item, name)
        else:
            if object_type != "misc":
                print("Unparsed Object type: {}".format(name))

    def fill_misp_object(self, item, name):
        misp_object = pymisp.MISPObject(name)
        misp_object.timestamp = self.getTimestampfromDate(item.timestamp)
        try:
            observables = item.observable.observable_composition.observables
            for observable in observables:
                properties = observable.object_.properties
                self.parse_observable(properties, misp_object)
        except AttributeError:
            properties = item.observable.object_.properties
            self.parse_observable(properties, misp_object)
        self.misp_event.add_object(**misp_object)

    def parse_observable(self, properties, misp_object):
        misp_attribute = pymisp.MISPAttribute()
        misp_attribute.type, misp_attribute.value, misp_attribute.object_relation = self.handle_attribute_type(properties, is_object=True)
        misp_object.add_attribute(**misp_attribute)

    def parse_external_indicator(self, indicators):
        for indicator in indicators:
            try:
                properties = indicator.observable.object_.properties
            except:
                self.parse_description(indicator)
                continue
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties)
                if type(attribute_value) is str:
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': True}
                    if indicator.timestamp:
                        attribute['timestamp'] = self.getTimestampfromDate(indicator.timestamp)
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    # otherwise, it is a dictionary of attributes, so we build an object
                    self.handle_object_case(attribute_type, attribute_value, compl_data)

    def parse_external_observable(self, observables):
        for observable in observables:
            title = observable.title
            try:
                properties = observable.object_.properties
            except:
                self.parse_description(observable)
                continue
            if properties:
                attribute_type, attribute_value, compl_data = self.handle_attribute_type(properties, title=title)
                attr_type = type(attribute_value)
                if attr_type is str or attr_type is int:
                    # if the returned value is a simple value, we build an attribute
                    attribute = {'to_ids': False}
                    self.handle_attribute_case(attribute_type, attribute_value, compl_data, attribute)
                else:
                    # otherwise, it is a dictionary of attributes, so we build an object
                    self.handle_object_case(attribute_type, attribute_value, compl_data)

    def parse_description(self, stix_object):
        if stix_object.description:
            misp_attribute = {}
            if stix_object.timestamp:
                misp_attribute['timestamp'] = self.getTimestampfromDate(stix_object.timestamp)
            self.misp_event.add_attribute("text", stix_object.description.value, **misp_attribute)

    def handle_attribute_case(self, attribute_type, attribute_value, data, attribute):
        if attribute_type == 'attachment':
            attribute['data'] = data
        self.misp_event.add_attribute(attribute_type, attribute_value, **attribute)

    def handle_object_case(self, attribute_type, attribute_value, compl_data):
        misp_object = pymisp.MISPObject(attribute_type)
        for attribute in attribute_value:
            misp_object.add_attribute(**attribute)
        if type(compl_data) is dict and "pe_uuid" in compl_data:
            # if some complementary data is a dictionary containing an uuid,
            # it means we are using it to add an object reference of a pe object
            # in a file object
            misp_object.add_reference(compl_data['pe_uuid'], 'pe')
        self.misp_event.add_object(**misp_object)

    def parse_ttps(self, ttps):
        for ttp in ttps:
            if ttp.behavior and ttp.behavior.malware_instances:
                for mi in ttp.behavior.malware_instances:
                    print(mi.to_json()) # WAITING FOR RELEVANT EXAMPLES

    @staticmethod
    def return_attributes(attributes):
        return_attributes = []
        for attribute in attributes:
            return_attributes.append(dict(zip(('type', 'value', 'object_relation'), attribute)))
        return return_attributes

    def saveFile(self):
        eventDict = self.misp_event.to_json()
        with open(self.outputname, 'w') as f:
            f.write(eventDict)

def main(args):
    pathname = os.path.dirname(args[0])
    stix_parser = StixParser()
    stix_parser.loadEvent(args, pathname)
    stix_parser.handler()
    stix_parser.saveFile()
    print(1)

if __name__ == "__main__":
    main(sys.argv)
