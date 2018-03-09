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

eventTypes = {"FileObjectType": {"type": "filename", "relation": "filename"},
              "HostnameObjectType": {"type": "hostname", "relation": "host"},
              "URIObjectType": {"type": "url", "relation": "url"},
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
            if args[1].startswith('misp.'):
                fromMISP = True
            else:
                fromMISP = False
            try:
                with open(filename, 'r') as f:
                    self.event = json.loads(f.read())
                self.isJson = True
            except:
                event = STIXPackage.from_xml(filename)
                self.isJson = False
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
        if self.isJson:
            self.outputname = self.filename
        else:
            self.outputname = '{}.json'.format(self.filename)
        if self.fromMISP:
            self.buildMispDict()
        else:
            self.buildExternalDict()

    def buildMispDict(self):
        self.dictTimestampAndDate()
        self.eventInfo()
        for indicator in self.event.related_indicators.indicator:
            self.parse_misp_indicator(indicator)

    def buildExternalDict(self):
        self.dictTimestampAndDate()
        self.eventInfo()

    def dictTimestampAndDate(self):
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
            self.misp_event.info = noinfo

    def parse_misp_indicator(self, indicator):
        if indicator.relationship in categories:
            self.parse_misp_attribute(indicator)
        else:
            self.parse_misp_object(indicator)

    def parse_misp_attribute(self, indicator):
        misp_attribute = {'category': str(indicator.relationship)}
        item = indicator.item
        misp_attribute['timestamp'] = self.getTimestampfromDate(item.timestamp)
        properties = item.observable.object_.properties
        attribute_type, attribute_value, _ = self.handle_attribute_type(properties)
        self.misp_event.add_attribute(attribute_type, attribute_value, **misp_attribute)

    def handle_attribute_type(self, properties):
        xsi_type = properties._XSI_TYPE
        # print(xsi_type)
        if xsi_type == 'EmailMessageObjectType':
            return self.handle_email_attribute(properties)
        elif xsi_type == 'DomainNameObjectType':
            return
        elif xsi_type == 'FileObjectType':
            if properties.hashes:
                return self.handle_hashes_attribute(properties)
            elif properties.file_name:
                event_types = eventTypes[xsi_type]
                return event_types['type'], properties.file_name.value, event_types['relation']
            else:
                # ATM USED TO CATCH UNSUPPORTED FILE OBJECTS PROPERTIES
                print("Unsupported File Object property")
                sys.exit(1)
        elif xsi_type == 'HostnameObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.hostname_value.value, event_types['relation']
        elif xsi_type == 'HTTPSessionObjectType':
            return
        elif xsi_type == 'URIObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.value.value, event_types['relation']
        elif xsi_type == 'WindowsRegistryKeyObjectType':
            event_types = eventTypes[xsi_type]
            return event_types['type'], properties.key.value, event_types['relation']
        else:
            # ATM USED TO TEST TYPES
            print("Unparsed type: {}".format(xsi_type))
            sys.exit(1)

    @staticmethod
    def handle_email_attribute(properties):
        if properties.from_:
            return "email-src", properties.from_.address_value.value, "from"
        elif properties.to:
            return "email-dst", properties.to.address_value.value, "to"
        elif properties.subject:
            return "email-subject", properties.subject.value, "subject"
        else:
            # ATM USED TO TEST EMAIL PROPERTIES
            print("Unsupported Email property")
            sys.exit(1)

    @staticmethod
    def handle_hashes_attribute(properties):
        if properties.md5:
            hash_type = "md5"
            return hash_type, properties.md5.value, hash_type
        elif properties.sha1:
            hash_type = "sha1"
            return hash_type, properties.sha1.value, hash_type
        elif properties.sha224:
            hash_type = "sha224"
            return hash_type, properties.sha224.value, hash_type
        elif properties.sha256:
            hash_type = "sha256"
            return hash_type, properties.sha256.value, hash_type
        elif properties.sha384:
            hash_type = "sha384"
            return hash_type, properties.sha384.value, hash_type
        elif properties.sha512:
            hash_type = "sha512"
            return hash_type, properties.sha512.value, hash_type
        elif properties.ssdeep:
            hash_type = "ssdeep"
            return hash_type, properties.ssdeep.value, hash_type
        else:
            # ATM USED TO CATCH UNSUPPORTED HASH PROPERTIES
            print("Unsupported hash property")
            sys.exit(1)

    def parse_misp_object(self, indicator):
        name = str(indicator.relationship)
        if name in ['file']:
            misp_object = pymisp.MISPObject(name)
            item = indicator.item
            misp_object.timestamp = self.getTimestampfromDate(item.timestamp)
            observables = item.observable.observable_composition.observables
            for observable in observables:
                properties = observable.object_.properties
                misp_attribute = pymisp.MISPAttribute()
                misp_attribute.type, misp_attribute.value, misp_attribute.object_relation = self.handle_attribute_type(properties)
                misp_object.add_attribute(**misp_attribute)
            self.misp_event.add_object(**misp_object)

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
