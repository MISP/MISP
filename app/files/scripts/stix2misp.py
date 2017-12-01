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
              "to": {"type": "email-dst", "value": "address_value"},
              "from": {"type": "email-src", "value": "value"},
              "subject": {"type": "email-subject", "value": "value"},
              "user_agent": "user-agent"}

def loadEvent(args, pathname):
    try:
        filename = '{}/tmp/{}'.format(pathname, args[1])
        tempFile = open(filename, 'r')
        if filename.endswith('.json'):
            event = json.loads(tempFile.read())
            isJson = True
        else:
            event = STIXPackage.from_xml(tempFile)
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
    mispDict["info"] = stixEvent["stix_header"].get("title")
    event = stixEvent["incidents"][0]
    orgSource = event["information_source"]["identity"]["name"]
    orgReporter = event["reporter"]["identity"]["name"]
    indicators = event["related_indicators"]["indicators"]
    mispDict["Attribute"] = []
    for indic in indicators:
        attribute = {}
        indicator = indic.get("indicator")
        timestamp = indicator.get("timestamp").split("+")[0]
        attribute["timestamp"] = getTimestampfromDate(timestamp)
        observable = indicator.get("observable")
        properties = observable["object"]["properties"]
        try:
            cat = properties.get("category")
            if "ip" in cat:
                if properties.get("is_source"):
                    attr_type = "src"
                else:
                    attr_type = "dst"
            typeVal = eventTypes[cat][attr_type]
            value = eventTypes[cat]["value"]
            valueVal = properties[value]["value"]
        except:
            cat = properties.get("xsi:type")
            if cat == 'EmailMessageObjectType':
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
                hashes = properties["hashes"][0]
                typeVal = hashes["type"].get("value").lower()
                valueVal = hashes["simple_hash_value"].get("value")
            elif cat == "HTTPSessionObjectType":
                http = properties["http_request_response"][0]
                httpAttr = http["http_client_request"]["http_request_header"]["parsed_header"]
                attrVal = list(httpAttr)[0]
                valueVal = httpAttr.get(attrVal)
                typeVal = eventTypes[attrVal]
            else:
                value = eventTypes[cat]["value"]
                typeVal = eventTypes[cat]["type"]
                valueVal = properties[value]["value"]
        attribute["type"] = typeVal
        attribute["value"] = valueVal
        attribute["category"] = indic.get("relationship")
        mispDict["Attribute"].append(attribute)
    return mispDict

def saveFile(namefile, pathname, misp):
    filepath = "{}/tmp/{}.in".format(pathname, namefile)
    eventDict = misp.to_dict(with_timestamp=True)
    with open(filepath, 'w') as f:
        f.write(json.dumps(eventDict))

def main(args):
    pathname = os.path.dirname(args[0])
    stixEvent, isJson = loadEvent(args, pathname)
    if isJson:
        stixEvent = stixEvent["package"]
        namefile = args[1]
    else:
        stixEvent = json.loads(stixEvent.related_packages.related_package[0].to_json())['package']
        namefile = '{}.json'.format(args[1][:-4])
    mispDict = buildMispDict(stixEvent)
    misp = pymisp.MISPEvent(None, False)
    misp.from_dict(**mispDict)
    saveFile(namefile, pathname, misp)
    print(1)

if __name__ == "__main__":
    main(sys.argv)
