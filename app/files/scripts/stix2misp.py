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
from stix.core import STIXPackage

eventTypes = {"ipv4-addr": {"src": "ip-src", "dst": "ip-dst", "value": "address_value"},
              "ipv6-addr": {"src": "ip-src", "dst": "ip-dst", "value": "address_value"},
              "URIObjectType": {"type": "url", "value": "value"},
              "FileObjectType": {"type": "filename", "value": "file_name"},
              "DomainNameObjectType": {"type": "domain", "value": "value"},
              "HostnameObjectType": {"type": "hostname", "value": "hostname_value"},
              "to": {"type": "email-dst", "value": "address_value"},
              "from": {"type": "email-src", "value": "value"},
              "subject": {"type": "email-subject", "value": "value"},
              "user_agent": "user-agent"}

descFilename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
with open(descFilename, 'r') as f:
    categories = json.loads(f.read())['result'].get('categories')

def loadEvent(args, pathname):
    try:
        filename = '{}/tmp/{}'.format(pathname, args[1])
        tempFile = open(filename, 'r')
        if filename.endswith(('.json', '.json.out')):
            event = json.loads(tempFile.read())
            isJson = True
        else:
            event = STIXPackage.from_xml(tempFile)
            event = json.loads(event.related_packages.related_package[0].to_json())
            isJson = False
        return event, isJson
    except:
        print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
        sys.exit(1)

def getTimestampfromDate(date):
    dt = date.split("+")[0]
    return int(time.mktime(time.strptime(dt, "%Y-%m-%dT%H:%M:%S")))

def buildMispDict(stixEvent):
    mispDict = {}
    stixTimestamp = stixEvent.get("timestamp")
    date = stixTimestamp.split("T")[0]
    mispDict["date"] = date
    timestamp = getTimestampfromDate(stixTimestamp)
    mispDict["timestamp"] = timestamp
    event = stixEvent["incidents"][0]
    mispDict["info"] = event.get("title")
    orgSource = event["information_source"]["identity"]["name"]
    mispDict["Org"] = {}
    mispDict["Org"]["name"] = orgSource
    orgReporter = event["reporter"]["identity"]["name"]
    mispDict["Orgc"] = {}
    mispDict["Orgc"]["name"] = orgReporter
    indicators = event["related_indicators"]["indicators"]
    mispDict["Attribute"] = []
    mispDict["Object"] = []
    for indic in indicators:
        attribute = {}
        indicator = indic.get("indicator")
        timestamp = indicator.get("timestamp").split("+")[0]
        attribute["timestamp"] = getTimestampfromDate(timestamp)
        category = indic.get("relationship")
        observable = indicator.get("observable")
        try:
            properties = observable["object"].get("properties")
            attribute = {'timestamp': getTimestampfromDate(timestamp)}
            attribute['type'], attribute['value'] = fillAttribute(properties, category)
            if category in categories:
                attribute['category'] = category
                mispDict["Attribute"].append(attribute)
            else:
                #attribute['object_relation'] = fillRelation()
                obj = {'timestamp': getTimestampfromDate(timestamp), 'meta-category': category,
                       'Attribute': [attribute]}
                obj['name'] = indicator.get('description').split(' ')[0]
                mispDict["Object"].append(obj)
        except:
            observables = observable['observable_composition'].get('observables')
            if category in categories:
                domain = False
                for obs in observables:
                    properties = obs['object'].get('properties')
                    tmpType, tmpValue = fillAttribute(properties, category)
                    if tmpType == 'domain':
                        domainType = tmpType
                        domainVal = tmpValue
                        domain = True
                    elif tmpType in ('filename', 'regkey', 'hostname', 'ip-src', 'ip-dst'):
                        type1 = tmpType
                        value1 = tmpValue
                    else:
                        type2 = tmpType
                        value2 = tmpValue
                    if domain == True:
                        type2 = type1.split('-')[0]
                        type1 = domainType
                        value2 = value1
                        value1 = domainVal
                attribute = {'timestamp': getTimestampfromDate(timestamp),
                             'type': '{}|{}'.format(type1, type2),
                             'value': '{}|{}'.format(value1, value2)}
                mispDict['Attribute'].append(attribute)
            else:
                attributes = []
                for obs in observables:
                    properties = obs['object'].get('properties')
                    attribute = {'timestamp': getTimestampfromDate(timestamp)}
                    attribute['type'], attribute['value'] = fillAttribute(properties, category)
                    attributes.append(attribute)
                obj = {'timestamp': getTimestampfromDate(timestamp), 'meta-category': category,
                       'Attribute': attributes}
                obj['name'] = indicator.get('description').split(' ')[0]
                mispDict["Object"].append(obj)
    return mispDict

def fillAttribute(properties, category):
    try:
        cat = properties["category"]
    except:
        cat = properties["xsi:type"]
    if 'ip' in cat:
        if properties.get("is_source"):
            attr_type = "src"
        else:
            attr_type = "dst"
        typeVal = eventTypes[cat][attr_type]
        value = eventTypes[cat]["value"]
        valueVal = properties[value]["value"]
    elif cat == 'EmailMessageObjectType':
        header = properties["header"]
        emailType = list(header)[0]
        typeVal = eventTypes[emailType]["type"]
        value = eventTypes[emailType]["value"]
        headerVal = header[emailType]
        if emailType == "to":
            headerVal = headerVal[0]
        elif emailType == "from":
            headerVal = headerVal["address_value"]
        valueVal = headerVal.get(value)
    elif cat == "FileObjectType" and "hashes" in properties:
        hashes = properties['hashes'][0]
        if 'file_name' in properties:
            type2 = hashes["type"].get("value").lower()
            typeVal = 'filename|{}'.format(type2)
            value1 = properties['file_name'].get('value')
            value2 = hashes["simple_hash_value"].get("value")
            valueVal = '{}|{}'.format(value1, value2)
        else:
            if category == 'Network activity':
                typeVal = 'x509-fingerprint-sha1'
            else:
                typeVal = hashes["type"].get("value").lower()
            valueVal = hashes["simple_hash_value"].get("value")
    elif cat == "HTTPSessionObjectType":
        http = properties["http_request_response"][0]
        httpAttr = http["http_client_request"]["http_request_header"]["parsed_header"]
        attrVal = list(httpAttr)[0]
        valueVal = httpAttr.get(attrVal)
        typeVal = eventTypes[attrVal]
    elif cat == "WindowsRegistryKeyObjectType":
        valueVal = ""
        if properties['hive'].get('value') == "HKEY_LOCAL_MACHINE":
            valueVal += "HKLM\\"
        valueVal += properties['key'].get('value')
        typeVal = "regkey"
    else:
        value = eventTypes[cat]["value"]
        typeVal = eventTypes[cat]["type"]
        valueVal = properties[value]["value"]
    return typeVal, valueVal


def saveFile(namefile, pathname, misp):
    filepath = "{}/tmp/{}.stix".format(pathname, namefile)
    eventDict = misp.to_json()
    with open(filepath, 'w') as f:
        f.write(eventDict)

def main(args):
    pathname = os.path.dirname(args[0])
    stixEvent, isJson = loadEvent(args, pathname)
    stixEvent = stixEvent["package"]
    if isJson:
        namefile = args[1]
    else:
        namefile = '{}.json'.format(args[1][:-4])
    mispDict = buildMispDict(stixEvent)
    misp = pymisp.MISPEvent(None, False)
    misp.from_dict(**mispDict)
    saveFile(namefile, pathname, misp)
    print(1)

if __name__ == "__main__":
    main(sys.argv)
