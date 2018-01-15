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

eventTypes = {"ipv4-addr": {"src": "ip-src", "dst": "ip-dst", "value": "address_value", "relation": "ip"},
              "ipv6-addr": {"src": "ip-src", "dst": "ip-dst", "value": "address_value", "relation": "ip"},
              "URIObjectType": {"type": "url", "value": "value", "relation": "url"},
              "FileObjectType": {"type": "filename", "value": "file_name", "relation": "filename"},
              "DomainNameObjectType": {"type": "domain", "value": "value", "relation": "domain"},
              "HostnameObjectType": {"type": "hostname", "value": "hostname_value", "relation": "host"},
              "PortObjectType": {"type": "port", "value": "port_value", "relation": "port"},
              "AddressObjectType": {"email": "email-src", "": ""},
              "to": {"type": "email-dst", "value": "address_value", "relation": "to"},
              "from": {"type": "email-src", "value": "value", "relation": "from"},
              "subject": {"type": "email-subject", "value": "value", "relation": "subject"},
              "email-attachment": {"value": "file_name", "relation": "attachment"},
              "user_agent": "user-agent"}

descFilename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
with open(descFilename, 'r') as f:
    categories = json.loads(f.read())['result'].get('categories')

def loadEvent(args, pathname):
    try:
        filename = '{}/tmp/{}'.format(pathname, args[1])
        tempFile = open(filename, 'r')
        fromMISP = True
        try:
            event = json.loads(tempFile.read())
            isJson = True
        except:
            event = STIXPackage.from_xml(filename)
            event = json.loads(event.to_json())
            try:
                event = event['related_packages']['related_package'][0]
            except:
                fromMISP = False
            isJson = False
        return event, isJson, fromMISP
    except:
        print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
        sys.exit(0)

def getTimestampfromDate(date):
    try:
        dt = date.split('+')[0]
        d = int(time.mktime(time.strptime(dt, "%Y-%m-%dT%H:%M:%S")))
    except:
        dt = date.split('.')[0]
        d = int(time.mktime(time.strptime(dt, "%Y-%m-%dT%H:%M:%S")))
    return d

def buildMispDict(stixEvent):
    mispDict = {}
    stixTimestamp = stixEvent.get("timestamp")
    dictTimestampAndDate(mispDict, stixTimestamp)
    event = stixEvent["incidents"][0]
    eventInfo(mispDict, event)
    indicators = event["related_indicators"]["indicators"]
    mispDict["Attribute"] = []
    mispDict["Object"] = []
    for indic in indicators:
        try:
            indicator = indic.get("indicator")
            timestamp = indicator.get("timestamp").split("+")[0]
            category = indic.get("relationship")
            observable = indicator["observable"]
        except:
            continue
        try:
            properties = observable["object"]
            attribute = {'timestamp': getTimestampfromDate(timestamp)}
            attrType, attribute['value'], relation = fillMispAttribute(properties, category)
            attribute['type'] = attrType
            if category in categories:
                attribute['category'] = category
                mispDict["Attribute"].append(attribute)
            else:
                name = indicator.get('description').split(' ')[0]
                defineRelation(attribute, attrType, name, relation)
                obj = {'timestamp': getTimestampfromDate(timestamp), 'meta-category': category,
                       'Attribute': [attribute]}
                obj['name'] = name
                mispDict["Object"].append(obj)
        except:
            observables = observable['observable_composition'].get('observables')
            if category in categories:
                domain = False
                for obs in observables:
                    properties = obs['object']
                    tmpType, tmpValue, _ = fillMispAttribute(properties, category)
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
                name = indicator.get('description').split(' ')[0]
                for obs in observables:
                    properties = obs['object']
                    attribute = {'timestamp': getTimestampfromDate(timestamp)}
                    attrType, attribute['value'], relation = fillMispAttribute(properties, category)
                    if '|' in attrType:
                        attribute['type'] = "malware-sample"
                        attribute['object_relation'] = "malware-sample"
                    else:
                        attribute['type'] = attrType
                        defineRelation(attribute, attrType, name, relation)
                    attributes.append(attribute)
                obj = {'timestamp': getTimestampfromDate(timestamp), 'meta-category': category,
                       'Attribute': attributes}
                obj['name'] = name
                mispDict["Object"].append(obj)
    return mispDict

def dictTimestampAndDate(mispDict, stixTimestamp):
    date = stixTimestamp.split("T")[0]
    mispDict["date"] = date
    timestamp = getTimestampfromDate(stixTimestamp)
    mispDict["timestamp"] = timestamp

def eventInfo(mispDict, event):
    try:
        mispDict["info"] = event["title"]
    except:
        mispDict["info"] = "Imported from external STIX event"
    try:
        orgSource = event["information_source"]["identity"]["name"]
        mispDict["Org"] = {}
        mispDict["Org"]["name"] = orgSource
    except:
        pass
    try:
        orgReporter = event["reporter"]["identity"]["name"]
        mispDict["Orgc"] = {}
        mispDict["Orgc"]["name"] = orgReporter
    except:
        pass

def defineRelation(attribute, attrType, name, relation):
    if attrType in ('md5', 'sha1', 'sha256') and name == 'x509':
        attribute['object_relation'] = "x509-fingerprint-{}".format(attrType)
    else:
        attribute['object_relation'] = relation

def buildExternalDict(stixEvent):
    mispDict = {}
    stixTimestamp = stixEvent.get("timestamp")
    dictTimestampAndDate(mispDict, stixTimestamp)
    header = stixEvent.get('stix_header')
    eventInfo(mispDict, header)
    mispDict['Attribute'] = []
    if 'indicators' in stixEvent:
        indicators = stixEvent.get('indicators')
        parseAttributes(indicators, mispDict, True)
    if 'observables' in stixEvent:
        observables = stixEvent['observables'].get('observables')
        parseAttributes(observables, mispDict, False)
    if 'ttps' in stixEvent:
        ttps = stixEvent['ttps'].get('ttps')
        parseTTPS(ttps, mispDict)
    return mispDict

def parseAttributes(attributes, mispDict, indic):
    for attr in attributes:
        if 'observable' in attr:
            observable = attr.get('observable')
            obj = observable.get('object')
        else:
            obj = attr.get('object')
        try:
            properties = obj.get('properties')
        except:
            continue
        try:
            attrTimestamp = attr['timestamp'].split('+')[0]
            attribute = {'timestamp': getTimestampfromDate(attrTimestamp)}
        except:
            attribute = {}
        attribute['type'], attribute['value'] = fillExternalAttribute(properties)
        attribute['to_ids'] = indic
        mispDict['Attribute'].append(attribute)

def parseTTPS(ttps, mispDict):
    mispDict['Galaxy'] = []
    for ttp in ttps:
        behavior = ttp.get('behavior')
        if 'malware_instances' in behavior:
            attr = behavior['malware_instances'][0]
            attrType = attr['types'][0].get('value')
            attribute = {'type': attrType, 'GalaxyCluster': []}
            cluster = {'type': attrType}
            try:
                cluster['description'] = attr['short_description']
            except:
                cluster['description'] = attr.get('description')
            if 'names' in attr:
                synonyms = []
                for name in attr.get('names'):
                    synonyms.append(name)
                cluster['meta'] = {'synonyms': synonyms}
            cluster['value'] = ttp.get('title')
            attribute['GalaxyCluster'].append(cluster)
            mispDict['Galaxy'].append(attribute)

def fillExternalAttribute(properties):
    if 'hashes' in properties:
        hashes = properties['hashes'][0]
        typeVal = hashes.get('type').lower()
        value = hashes.get('simple_hash_value')
    else:
        attrType = properties.get('xsi:type')
        if attrType == 'AddressObjectType':
            if 'email' in properties.get('category'):
                typeVal = eventTypes[attrType]['email']
            else:
                try:
                    if properties.get('is_source') == 'false':
                        typeVal = eventTypes[properties.get('category')].get('dst')
                    else:
                        typeVal = eventTypes[properties.get('category')].get('src')
                except:
                    typeVal = "ip-src"
        else:
            typeVal = eventTypes[properties.get('xsi:type')].get('type')
        if 'address_value' in properties:
            try:
                value = properties['address_value'].get('value')
            except:
                value = properties.get('address_value')
        else:
            value = properties.get('value')
    return typeVal, value

def fillMispAttribute(prop, category):
    properties = prop['properties']
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
        relation = 'ip'
    elif cat == 'EmailMessageObjectType':
        try:
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
            relation = eventTypes[emailType]['relation']
        except:
            attachmentProp = prop['related_objects'][0]['properties']
            if attachmentProp.get('xsi:type') == 'FileObjectType':
                typeVal = 'email-attachment'
                propCat = eventTypes[typeVal]['value']
            valueVal = attachmentProp[propCat].get('value')
            relation = eventTypes[typeVal]['relation']
    elif cat == "FileObjectType" and "hashes" in properties:
        hashes = properties['hashes'][0]
        if 'file_name' in properties:
            type2 = hashes["type"].get("value").lower()
            typeVal = 'filename|{}'.format(type2)
            value1 = properties['file_name'].get('value')
            value2 = hashes["simple_hash_value"].get("value")
            valueVal = '{}|{}'.format(value1, value2)
            relation = None
        else:
            if category == 'Network activity':
                typeVal = 'x509-fingerprint-sha1'
            else:
                typeVal = hashes["type"].get("value").lower()
            valueVal = hashes["simple_hash_value"].get("value")
            relation = typeVal
    elif cat == "HTTPSessionObjectType":
        http = properties["http_request_response"][0]
        httpAttr = http["http_client_request"]["http_request_header"]["parsed_header"]
        attrVal = list(httpAttr)[0]
        valueVal = httpAttr.get(attrVal)
        typeVal = eventTypes[attrVal]
        relation = 'user-agent'
    elif cat == "WindowsRegistryKeyObjectType":
        valueVal = ""
        if properties['hive'].get('value') == "HKEY_LOCAL_MACHINE":
            valueVal += "HKLM\\"
        valueVal += properties['key'].get('value')
        typeVal = "regkey"
        relation = "key"
    else:
        value = eventTypes[cat]["value"]
        typeVal = eventTypes[cat]["type"]
        valueVal = properties[value]["value"]
        relation = eventTypes[cat]["relation"]
    return typeVal, valueVal, relation


def saveFile(namefile, pathname, misp):
    filepath = "{}/tmp/{}.stix".format(pathname, namefile)
    eventDict = misp.to_json()
    with open(filepath, 'w') as f:
        f.write(eventDict)

def main(args):
    pathname = os.path.dirname(args[0])
    stixEvent, isJson, fromMISP = loadEvent(args, pathname)
    if isJson:
        namefile = args[1]
    else:
        namefile = '{}.json'.format(args[1][:-4])
    if fromMISP:
        stixEvent = stixEvent["package"]
        mispDict = buildMispDict(stixEvent)
    else:
        mispDict = buildExternalDict(stixEvent)
    misp = pymisp.MISPEvent(None, False)
    misp.from_dict(**mispDict)
    saveFile(namefile, pathname, misp)
    print(1)

if __name__ == "__main__":
    main(sys.argv)
