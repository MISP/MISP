#!/usr/bin/env python3
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
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys, json, os, time, re
from stix2 import *
import pymisp

def loadEvent(args, pathname):
    try:
        filename = os.path.join(pathname, args[1])
        tempFile = open(filename, 'r')
        event = json.loads(tempFile.read())
        return event
    except:
        print(json.dumps({'success': 0, 'message': 'The temporary STIX export file could not be read'}))
        sys.exit(1)

def buildMispDict(event):
    mispDict = {}
    identity = event.pop(0)
    mispDict['Org'] = {}
    mispDict['Org']['name'] = identity.get('name')
    report = event.pop(0)
    mispDict['info'] = report.get('name')
    mispDict['publish_timestamp'] = getTimestampfromDate(report.get('published'))
    labels = report.get('labels')
    Tag = []
    for l in labels:
        label = {'exportable': True, 'hide_tag': False}
        label['name'] = l
        Tag.append(label)
    mispDict['Tag'] = Tag
    Attribute = []
    Galaxy = []
    Object = []
    try:
        external_refs = report.get('external_references')
        for e in external_refs:
            link = {'type': 'link'}
            link['comment'] = e.get('source_name').split('url - ')[1]
            link['value'] = e.get('url')
            Attribute.append(link)
    except:
        pass
    for attr in event:
        attrType = attr.get('type')
        attrLabels = attr.pop('labels')
        if attrType in ('attack-pattern', 'course-of-action', 'intrusion-set', 'malware', 'threat-actor', 'tool'):
            fillGalaxy(attr, attrLabels, Galaxy)
        elif 'x-misp-object' in attrType:
            if 'from_object' in attrLabels:
                fillCustomFromObject(attr, attrLabels, Object)
            else:
                fillCustom(attr, attrLabels, Attribute)
        else:
            if 'from_object' in attrLabels:
                fillObjects(attr, attrLabels, Object)
            else:
                fillAttributes(attr, attrLabels, Attribute)
    #print('Attribute:', Attribute)
    #print('Object:', Object)
    #print('Galaxy:', Galaxy)
    mispDict['Attribute'] = Attribute
    mispDict['Galaxy'] = Galaxy
    #mispDict['Object'] = Object
    return mispDict

def fillGalaxy(attr, attrLabels, Galaxy):
    galaxy = {}
    mispType = getMispType(attrLabels)
    tag = attrLabels[1]
    value = tag.split(':')[1].split('=')[1]
    galaxy['type'] = mispType
    galaxy['name'] = attr.get('name')
    galaxy['GalaxyCluster'] = [{'type': mispType, 'value': value, 'tag_name': tag,
                               'description': attr.get('description')}]
    Galaxy.append(galaxy)

def fillObjects(attr, attrLabels, Object):
    obj = {}
    objType = getMispType(attrLabels)
    attrType = attr.get('type')
    if attrType == 'observed-data':
        observable = attr.get('objects')
        obj['name'] = objType
    elif attrType == 'indicator':
        obj['name'] = objType
        pattern = attr.get('pattern').split(' AND ')
        pattern[0] = pattern[0][2:]
        pattern[-1] = pattern[-1][:-2]
        obj['Attribute'] = resolvePatternFromObjects(pattern, objType)
    else:
        obj['name'] = attrType
    obj['to_ids'] = bool(attrLabels[1].split('=')[1])
    Object.append(obj)

def fillAttributes(attr, attrLabels, Attribute):
    attribute = {}
    mispType = getMispType(attrLabels)
    attrType = attr.get('type')
    if attrType == 'observed-data':
        attribute['type'] = mispType
        date = attr.get('first_observed')
        attribute['timestamp'] = getTimestampfromDate(date)
        observable = attr.get('objects')
        attribute['value'] = resolveObservable(observable, mispType)
    elif attrType == 'indicator':
        attribute['type'] = mispType
        date = attr.get('valid_from')
        attribute['timestamp'] = getTimestampfromDate(date)
        pattern = attr.get('pattern')
        attribute['value'] = resolvePattern(pattern, mispType)
    else:
        attribute['value'] = attr.get('name')
        if attrType == 'identity':
            attribute['type'] = mispType
        else:
            attribute['type'] = attrType
    attribute['to_ids'] = bool(attrLabels[1].split('=')[1])
    Attribute.append(attribute)

def fillCustom(attr, attrLabels, Attribute):
    attribute = {}
    attribute['type'] = attr.get('type').split('x-misp-object-')[1]
    attribute['timestamp'] = int(time.mktime(time.strptime(attr.get('x_misp_timestamp'), "%Y-%m-%d %H:%M:%S")))
    attribute['to_ids'] = bool(attrLabels[1].split('=')[1])
    attribute['value'] = attr.get('x_misp_value')
    Attribute.append(attribute)

def fillCustomFromObject(attr, attrLabels, Object):
    obj = {}
    obj['type'] = attr.get('type').split('x-misp-object-')[1]
    obj['timestamp'] = int(time.mktime(time.strptime(attr.get('x_misp_timestamp'), "%Y-%m-%d %H:%M:%S")))
    obj['labels'] = bool(attrLabels[0].split('=')[1])
    Attribute = []
    values = attr.get('x_misp_values')
    for obj_attr in values:
        attribute = {}
        attr_type, objRelation = obj_attr.split('_')
        attribute['type'] = attr_type
        attribute['object_relation'] = objRelation
        attribute['value'] = values.get(obj_attr)
        Attribute.append(attribute)
    obj['Attribute'] = Attribute
    Object.append(obj)

def getTimestampfromDate(date):
    return int(time.mktime(time.strptime(date, "%Y-%m-%dT%H:%M:%SZ")))

def getMispType(labels):
    return labels[0].split('=')[1][1:-1]

mispSimpleMapping = {
        'email-subject': 'subject', 'email-body': 'body', 'regkey': 'key', 'mutex': 'name', 'port': 'dst_port',
        'attachment': 'payload_bin', 'filename': 'name'}

mispComplexMapping = {
        'single': {'regkey|value': {'values': 'name'},
                   'x509-fingerprint-sha1': {'hashes': 'SHA-1'}},
        'double': {'domain|ip': {'0': 'value', '1': 'value'},
                   'ip-src|port': {'0': 'value', '1': 'src_port'},
                   'ip-dst|port': {'0': 'value', '1': 'dst_port'},
                   'hostname|port': {'0': 'value', '1': 'dst_port'}}
        }

def resolveObservable(observable, mispType):
    obj0 = observable.get('0')
    if mispType in mispSimpleMapping:
        return obj0.get(mispSimpleMapping[mispType])
    elif mispType in mispComplexMapping['single']:
        singleDict = mispComplexMapping['single'].get(mispType)
        key1 = list(singleDict.keys())[0]
        key2 = singleDict[key1]
        value2 = obj0[key1].get(key2)
        try:
            value1 = obj0.get('key')
            return '{}|{}'.format(value1, value2)
        except:
            return value2
    elif mispType in mispComplexMapping['double']:
        obj1 = observable.get('1')
        doubleDict = mispComplexMapping['double'].get(mispType)
        value0 = obj0.get(doubleDict['0'])
        value1 = obj1.get(doubleDict['1'])
        return '{}|{}'.format(value0, value1)
    elif 'filename|' in mispType or mispType == 'malware-sample':
        value1 = obj0.get('name')
        try:
            value2 = obj0['hashes'].get(mispType.split('|')[1])
        except:
            value2 = obj0['hashes'].get('md5')
        return '{}|{}'.format(value1, value2)
    elif 'hashes' in obj0:
        if 'sha' in mispType:
            return obj0['hashes'].get('SHA-{}'.format(mispType.split('sha')[1]))
        return obj0['hashes'].get(mispType.upper())
    else:
        return obj0.get('value')

def resolvePattern(pattern, mispType):
    if ' AND ' in pattern:
        patternParts = pattern.split(' AND ')
        if len(patternParts) == 3:
            _, value1 = patternParts[2].split(' = ')
            _, value2 = patternParts[0].split(' = ')
        else:
            _, value1 = patternParts[0].split(' = ')
            _, value2 = patternParts[1].split(' = ')
        value = '{}|{}'.format(value1[1:-1], value2[1:-1])
    else:
        _, value = pattern.split(' = ')
        value = value[1:-1]
    return value

objectPatternMapping = {
        'domain|ip': {'domain': 'domain', 'resolves_to_refs[*].value': 'ip-dst'},
        'email': {'to_refs': 'email-dst', 'cc_refs': 'email-dst', 'subject': 'email-subject',
                  'additional_header_fields.X-Mailer': 'email-x-mailer', 'from_ref': 'email-src',
                  'body_multipart[*].body_raw_ref.name': 'email-attachment',
                  'additional_header_fields.Reply-To': 'email-reply-to'},
        'file': {'size': 'size-in-bytes', 'name': 'filename'},
        'ip|port': {'src_port': 'src-port', 'dst_port': 'dst-port',
                    'network-traffic:dst_ref.value': 'ip-dst'},
        'registry-key': {'datatype': 'reg-datatype', 'data': 'reg-data', 'name': 'reg-name',
                         'key': 'reg-key'},
        'url': {'value': 'url'},
        'x509': {}
        }
objTextRelation = {'subject': 'subject', 'issuer': 'issuer', 'serial_number': 'serial-number',
                   'subject_public_key_exponent': 'pubkey-info-exponent', 'version': 'version',
                   'subject_public_key_modulus': 'pubkey-info-modulus', 'mime_type': 'mimetype',
                   'subject_public_key_algorithm': 'pubkey-info-algorithm'}
objDateRelation = {'validity_not_before': 'validity-not-before', 'start': 'first-seen',
                   'validity_not_after': 'validity-not-after', 'end': 'last-seen',
                   'date': 'send-date', 'modified': 'last-modified'}

def resolvePatternFromObjects(pattern, mispType):
    Attribute = []
    mapping = objectPatternMapping.get(mispType)
    for p in pattern:
        attribute = {}
        stixType, value = p.split(' = ')
        stixType = stixType.split(':')[1]
        if stixType in mapping:
            attrType = mapping.get(stixType)
        elif 'hashes' in stixType:
            attrType = stixType.split('.')[1:-1]
        else:
            if stixType in objTextRelation:
                attribute['object-relation'] = objTextRelation.get(stixType)
                attrType = 'text'
            elif stixType in objDateRelation:
                attribute['object-relation'] = objDateRelation.get(stixType)
                attrType = 'datetime'
            else:
                continue
        attribute['type'] = attrType
        attribute['value'] = value[1:-1]
        Attribute.append(attribute)
    return Attribute

def saveFile(args, misp):
    filename = '{}.in'.format(args[1])
    eventDict = misp.to_dict(with_timestamp=True)
    with open(filename, 'w') as f:
        f.write(json.dumps(eventDict))

def main(args):
    pathname = os.path.dirname(sys.argv[0])
    stix2Event = loadEvent(args, pathname)
    stix2Event = stix2Event.get('objects')
    mispDict = buildMispDict(stix2Event)
    misp = pymisp.MISPEvent(None, False)
    misp.from_dict(**mispDict)
    saveFile(args, misp)
    print(1, args[1])

if __name__ == "__main__":
    main(sys.argv)
