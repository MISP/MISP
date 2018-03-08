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

descFilename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
with open(descFilename, 'r') as f:
    categories = json.loads(f.read())['result'].get('categories')

class StixParser():
    def __init__(self):
        self.misp_event = pymisp.MISPEvent()

    def loadEvent(self, args, pathname):
        try:
            filename = '{}/tmp/{}'.format(pathname, args[1])
            try:
                with open(filename, 'r') as f:
                    self.event = json.loads(f.read())
                self.isJson = True
            except:
                event = STIXPackage.from_xml(filename)
                if args[1].startswith('misp.'):
                    fromMISP = True
                else:
                    fromMISP = False
                self.isJson = False
                if fromMISP:
                    self.event = event.related_packages.related_package[0].item.incidents[0]
                else:
                    self.event = event
                self.fromMISP = fromMISP
        except:
            print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
            sys.exit(0)

    def handler(self, args):
        if self.isJson:
            self.namefile = args[1]
        else:
            self.namefile = '{}.json'.format(args[1])
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
        misp_attribute = pymisp.MISPAttribute()
        misp_attribute.category = indicator.relationship
        properties = indicator.item.observable

    def parse_misp_object(self, indicator):
        name = str(indicator.relationship)
        if name in ['file']:
            misp_object = pymisp.MISPObject(name)


def main(args):
    pathname = os.path.dirname(args[0])
    stix_parser = StixParser()
    stix_parser.loadEvent(args, pathname)
    stix_parser.handler(args)
    print(stix_parser.misp_event)

if __name__ == "__main__":
    main(sys.argv)
