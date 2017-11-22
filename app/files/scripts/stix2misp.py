# -*- coding: utf-8 -*-
#    Copyright (C) 2017 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#    Copyright (C) 2017 Christian Studer
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

eventTypes = {'ipv4-addr': {'src': 'ip-src', 'dst': 'ip-dst', 'value': 'address_value'},
              'ipv6-addr': {'src': 'ip-src', 'dst': 'ip-dst', 'value': 'address_value'},
              'URIObjectType': {'category': 'url', 'value': 'value'}}

def loadEvent(args, pathname):
    try:
        filename = '{}/tmp/{}'.format(pathname, args[1])
        tempFile = open(filename, 'r')
        if filename.endswith('.json'):
            event = json.loads(tempFile.read())
        return event
    except:
        print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
        sys.exit(1)

def getTimestampfromDate(date):
    dt = date.split('+')[0]
    return int(time.mktime(time.strptime(dt, '%Y-%m-%dT%H:%M:%S')))

def buildMispDict(stixEvent):
    mispDict = {}
    stixTimestamp = stixEvent['timestamp']
    date = stixTimestamp.split('T')[0]
    mispDict['date'] = date
    timestamp = getTimestampfromDate(stixTimestamp)
    mispDict['timestamp'] = timestamp
    event = stixEvent['incidents'][0]
    orgSource = event['information_source']['identity']['name']
    orgReporter = event['reporter']['identity']['name']
    indicators = event['related_indicators']['indicators']
    mispDict['attributes'] = []
    for indic in indicators:
        attribute = {}
        indicator = indic.get('indicator')
        attribute['timestamp'] = indicator.get('timestamp').split('+')[0]
        observable = indicator.get('observable')
        properties = observable['object']['properties']
        if 'header' in properties:
            emailType = properties['header'].keys()
            print(emailType)
            sys.exit(0)
        try:
            cat = properties.get('category')
            attribute['type'] = eventTypes[cat]
            value = eventTypes[cat]['value']
        except:
            cat = properties.get('xsi:type')
            value = eventTypes[cat]['value']
            cat = eventTypes[cat]['category']
            attribute['type'] = cat
        attribute['value'] = properties[value]['value']
        attribute['category'] = indic.get('relationship')
        mispDict['attributes'].append(attribute)
    return mispDict

def main(args):
    pathname = os.path.dirname(args[0])
    stixEvent = loadEvent(args, pathname)
    stixEvent = stixEvent['package']
    mispDict = buildMispDict(stixEvent)
    print(mispDict)

if __name__ == "__main__":
    main(sys.argv)
