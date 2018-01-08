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
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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

def fillReportInfo(mispDict, report):
    mispDict['info'] = report.get('name')
    mispDict['publish_timestamp'] = getTimestampfromDate(report.get('published'))
    labels = report.get('labels')
    Tag = []
    for l in labels:
        label = {'exportable': True, 'hide_tag': False}
        label['name'] = l
        Tag.append(label)
    mispDict['Tag'] = Tag

def buildMispDict(event):
    mispDict = {}
    identity = event.pop(0)
    mispDict['Org'] = {}
    mispDict['Org']['name'] = identity.get('name')
    report = event.pop(0)
    fillReportInfo(mispDict, report)
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
    mispDict['Attribute'] = Attribute
    mispDict['Galaxy'] = Galaxy
    mispDict['Object'] = Object
    return mispDict

def fillGalaxy(attr, attrLabels, Galaxy):
    galaxy = {}
    mispType = getMispType(attrLabels)
    tag = attrLabels[1]
    value = tag.split(':')[1].split('=')[1]
    galaxy['type'] = mispType
    galaxy['name'] = attr.get('name')
    galaxyDescription, clusterDescription = attr.get('description').split(' | ')
    galaxy['description'] = galaxyDescription
    galaxy['GalaxyCluster'] = [{'type': mispType, 'value': value, 'tag_name': tag,
                               'description': clusterDescription}]
    Galaxy.append(galaxy)

def fillObjects(attr, attrLabels, Object):
    obj = {}
    objType = getMispType(attrLabels)
    objCat = getMispCategory(attrLabels)
    attrType = attr.get('type')
    if attrType == 'observed-data':
        observable = attr.get('objects')
        obj['name'] = objType
        obj['meta-category'] = objCat
        obj['Attribute'] = resolveObservableFromObjects(observable, objType, attrLabels)
    elif attrType == 'indicator':
        obj['name'] = objType
        obj['meta-category'] = objCat
        pattern = attr.get('pattern').replace('\\\\', '\\').split(' AND ')
        pattern[0] = pattern[0][2:]
        pattern[-1] = pattern[-1][:-2]
        obj['Attribute'] = resolvePatternFromObjects(pattern, objType, attrLabels)
    else:
        obj['name'] = attrType
    obj['to_ids'] = bool(attrLabels[1].split('=')[1])
    Object.append(obj)

def fillAttributes(attr, attrLabels, Attribute):
    attribute = {}
    mispType = getMispType(attrLabels)
    mispCat = getMispCategory(attrLabels)
    attrType = attr.get('type')
    if attrType == 'observed-data':
        attribute['type'] = mispType
        attribute['category'] = mispCat
        date = attr.get('first_observed')
        attribute['timestamp'] = getTimestampfromDate(date)
        observable = attr.get('objects')
        attribute['value'] = resolveObservable(observable, mispType)
    elif attrType == 'indicator':
        attribute['type'] = mispType
        attribute['category'] = mispCat
        date = attr.get('valid_from')
        attribute['timestamp'] = getTimestampfromDate(date)
        pattern = attr.get('pattern').replace('\\\\', '\\')
        attribute['value'] = resolvePattern(pattern, mispType)
    else:
        attribute['value'] = attr.get('name')
        if attrType == 'identity':
            attribute['type'] = mispType
        else:
            attribute['type'] = attrType
        attribute['category'] = mispCat
    attribute['to_ids'] = bool(attrLabels[1].split('=')[1])
    if 'description' in attr:
        attribute['comment'] = attr.get('description')
    Attribute.append(attribute)

def fillCustom(attr, attrLabels, Attribute):
    attribute = {}
    attribute['type'] = attr.get('type').split('x-misp-object-')[1]
    attribute['timestamp'] = int(time.mktime(time.strptime(attr.get('x_misp_timestamp'), "%Y-%m-%d %H:%M:%S")))
    attribute['to_ids'] = bool(attrLabels[1].split('=')[1])
    attribute['value'] = attr.get('x_misp_value')
    attribute['category'] = getMispCategory(attrLabels)
    Attribute.append(attribute)

def fillCustomFromObject(attr, attrLabels, Object):
    obj = {}
    obj['name'] = attr.get('type').split('x-misp-object-')[1]
    obj['timestamp'] = int(time.mktime(time.strptime(attr.get('x_misp_timestamp'), "%Y-%m-%d %H:%M:%S")))
    obj['meta-category'] = attr.get('category')
    #obj['labels'] = bool(attrLabels[0].split('=')[1])
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
    if '.' in date:
        return int(time.mktime(time.strptime(date.split('.')[0], "%Y-%m-%dT%H:%M:%S")))
    else:
        return int(time.mktime(time.strptime(date, "%Y-%m-%dT%H:%M:%SZ")))

def getMispType(labels):
    return labels[0].split('=')[1][1:-1]

def getMispCategory(labels):
    return labels[1].split('=')[1][1:-1]

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

def resolveObservableFromObjects(observable, mispType, attrLabels):
    mapping = objectMapping[mispType]
    if mispType == 'email':
        return resolveEmailObject(observable, mapping)
    elif mispType == 'domain|ip':
        return resolveDomainIpObject(observable, mapping)
    elif mispType == 'ip|port':
        return resolveIpPortObject (observable, mapping)
    elif mispType == 'registry-key':
        return resolveRegKeyObject(observable, mapping)
    else:
        return resolveBasicObject(observable, mapping, attrLabels)

def resolveEmailObject(observable, mapping):
    obj0 = observable.get('0')
    Attribute = []
    if obj0.pop('type') != 'email-message':
        print(json.dumps({'success': 0, 'message': 'Object type error. \'email\' needed.'}))
        sys.exit(1)
    if 'subject' in obj0:
        subject = obj0.pop('subject')
        Attribute.append(buildAttribute(mapping, subject, 'subject'))
    is_multipart = obj0.pop('is_multipart')
    if is_multipart:
        body = obj0.pop('body_multipart')
        for item in body:
            part = item.get('body_raw_ref')
            obj = observable[part].get('name')
            Attribute.append(buildAttribute(mapping, obj, 'body_raw_ref'))
    if 'additional_header_fields' in obj0:
        header = obj0.pop('additional_header_fields')
        for h in header:
            obj = header.get(h)
            Attribute.append(buildAttribute(mapping, obj, h))
    if 'from_ref' in obj0:
        part = obj0.pop('from_ref')
        obj = observable[part].get('value')
        Attribute.append(buildAttribute(mapping, obj, 'from_ref'))
    for o in obj0:
        field = obj0.get(o)
        for f in field:
            obj = observable[f].get('value')
            Attribute.append(buildAttribute(mapping, obj, o))
    return Attribute

def resolveDomainIpObject(observable, mapping):
    Attribute = []
    obj0 = observable.get('0')
    obj = obj0.get('value')
    Attribute.append(buildAttribute(mapping, obj, 'domain'))
    refs = obj.get('resolves_to_refs')
    for ref in refs:
        obj = observable[ref].get('value')
        Attribute.append(buildAttribute(mapping, obj, 'resolves_to_refs[*].value'))
    return Attribute

def resolveIpPortObject(observable, mapping):
    Attribute = []
    obj0 = observable.get('0')
    objIp = obj0.get('value')
    Attribute.append(buildAttribute(mapping, objIp, 'dst_ref.value'))
    obj1 = observable.get('1')
    for o in obj1:
        if o in mapping:
            obj = obj1.get(o)
            Attribute.append(buildAttribute(mapping, obj, o))
        elif o in objDateRelation:
            objValue = obj1.get(o)
            objRelation = objDateRelation.get(o)
            attribute = {'type': 'datetime', 'object_relation': objRelation, 'value': objValue}
            Attribute.append(attribute)
    return Attribute

def resolveRegKeyObject(observable, mapping):
    Attribute = []
    obj0 = observable.get('0')
    if 'values' in obj0:
        values = obj0.pop('values')
        for val in values[0]:
            v = values[0].get(val)
            Attribute.append(buildAttribute(mapping, v, val))
    obj0.pop('type')
    if 'key' in obj0:
        key = obj0.pop('key')
        Attribute.append(buildAttribute(mapping, key, 'key'))
    if 'modified' in obj0:
        date = obj.pop('modified')
        relation = objDateRelation.get('modified')
        attribute = {'type': 'datetime', 'object_relation': relation, 'value': date}
        Attribute.append(attribute)
    return Attribute

def resolveBasicObject(observable, mapping, attrLabels):
    obj0 = observable.get('0')
    if obj0.pop('type') not in ('x509-certificate', 'file', 'url'):
        print(json.dumps({'success': 0, 'message': 'Object type error.'}))
        sys.exit(1)
    Attribute = []
    if 'malware-sample' in attrLabels:
        for o in observable:
            if o.get('type') == 'file':
                value = '{}|{}'.format(o.get('name'), o['hashes'].get('MD5'))
                Attribute.append({'type': 'malware-sample', 'object_relation': 'malware-sample', 'value': value})
                break
    if 'hashes' in obj0:
        hashes = obj0.pop('hashes')
        for h in hashes:
            obj = hashes.get(h)
            hsh = h.lower().replace('-', '')
            Attribute.append({'type': hsh, 'object_relation': hsh, 'value': obj})
    for o in obj0:
        obj = obj0.get(o)
        if o in mapping:
            Attribute.append(buildAttribute(mapping, obj, o))
            continue
        elif o in objTextRelation:
            attribute = {}
            attrType = 'text'
            attrRelation = objTextRelation.get(o)
        elif o in objDateRelation:
            attribute = {}
            attrType = 'datetime'
            attrRelation = objDateRelation.get(o)
        attribute['type'] = attrType
        attribute['object_relation'] = attrRelation
        attribute['value'] = obj
        Attribute.append(attribute)
    return Attribute

def getTypeAndRelation(mapping, obj):
    objType = mapping[obj].get('type')
    objRelation = mapping[obj].get('relation')
    return objType, objRelation

def buildAttribute(mapping, obj, objString):
    attribute = {}
    attribute['type'], attribute['object_relation'] = getTypeAndRelation(mapping, objString)
    attribute['value'] = obj
    return attribute

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

objectMapping = {
        'domain|ip': {'domain': {'type': 'domain', 'relation': 'domain'},
                      'resolves_to_refs[*].value': {'type': 'ip-dst', 'relation': 'ip'}},
        'email': {'to_refs': {'type': 'email-dst', 'relation': 'to'},
                  'cc_refs': {'type': 'email-dst', 'relation': 'cc'},
                  'subject': {'type': 'email-subject', 'relation': 'subject'},
                  'additional_header_fields.X-Mailer': {'type': 'email-x-mailer', 'relation': 'x-mailer'},
                  'x-mailer': {'type': 'email-x-mailer', 'relation': 'x-mailer'},
                  'from_ref': {'type': 'email-src', 'relation': 'from'},
                  'body_multipart[*].body_raw_ref.name': {'type': 'email-attachment', 'relation': 'attachment'},
                  'body_raw_ref': {'type': 'email-attachment', 'relation': 'attachment'},
                  'additional_header_fields.Reply-To': {'type': 'email-reply-to', 'relation': 'reply-to'},
                  'reply-to': {'type': 'email-reply-to', 'relation': 'reply-to'}},
        'file': {'size': {'type': 'size-in-bytes', 'relation': 'size-in-bytes'},
                 'name': {'type': 'filename', 'relation': 'filename'}},
        'ip|port': {'src_port': {'type': 'port', 'relation': 'src-port'},
                    'dst_port': {'type': 'port', 'relation': 'dst-port'},
                    'dst_ref.value': {'type': 'ip-dst', 'relation': 'ip'}},
        'registry-key': {'data_type': {'type': 'text', 'relation': 'data-type'},
                         'data': {'type': 'text', 'relation': 'data'},
                         'name': {'type': 'text', 'relation': 'name'},
                         'key': {'type': 'regkey', 'relation': 'key'}},
        'url': {'value': {'type': 'url', 'relation': 'url'}},
        'x509': {}
        }
objTextRelation = {'subject': 'subject', 'issuer': 'issuer', 'serial_number': 'serial-number',
                   'subject_public_key_exponent': 'pubkey-info-exponent', 'version': 'version',
                   'subject_public_key_modulus': 'pubkey-info-modulus', 'mime_type': 'mimetype',
                   'subject_public_key_algorithm': 'pubkey-info-algorithm'}
objDateRelation = {'validity_not_before': 'validity-not-before', 'start': 'first-seen',
                   'validity_not_after': 'validity-not-after', 'end': 'last-seen',
                   'date': 'send-date', 'modified': 'last-modified'}

def resolvePatternFromObjects(pattern, mispType, attrLabels):
    Attribute = []
    mapping = objectMapping.get(mispType)
    if 'malware-sample' in attrLabels:
        name = False
        h = False
        for p in pattern:
            if 'file:name' in p:
                filename = p.split(' = ')[1][1:-1]
                name = True
            if 'hashes.\'md5\'' in p:
                md5 = p.split(' = ')[1][1:-1]
                h = True
            if name == True and h == True:
                break
        Attribute.append({'type': 'malware-sample', 'object_relation': 'malware-sample',
                          'value': '{}|{}'.format(filename, md5)})
    for p in pattern:
        attribute = {}
        stixType, value = p.split(' = ')
        stixType = stixType.split(':')[1]
        if stixType in mapping:
            attrType = mapping[stixType].get('type')
            relation = mapping[stixType].get('relation')
        elif 'hashes' in stixType:
            attrType = stixType.split('.')[1][1:-1]
            relation = attrType
        else:
            if stixType in objTextRelation:
                relation = objTextRelation.get(stixType)
                attrType = 'text'
            elif stixType in objDateRelation:
                relation = objDateRelation.get(stixType)
                attrType = 'datetime'
            else:
                continue
        attribute['type'] = attrType
        attribute['object_relation'] = relation
        attribute['value'] = value[1:-1]
        Attribute.append(attribute)
    return Attribute

def parseExternalStix(event):
    mispDict = {}
    report = event.pop(0)
    fillReportInfo(mispDict, report)
    Attribute = []
    Galaxy = []
    Object = []
    for e in event:
        attrType = e.get('type')
        if attrType in ('relationship', 'report'):
            continue
        if attrType == 'indicator':
            pattern = e.get('pattern')
            attribute = {'type': 'stix2-pattern', 'object_relation': 'stix2-pattern', 'value': pattern}
            obj = {'name': 'stix2-pattern', 'meta-category': 'stix2-pattern', 'Attribute': [attribute]}
            Object.append(obj)
            pattern = re.split(' AND | OR ', pattern[2:-2])
            #pattern_parser(pattern)
    mispDict['Attribute'] = Attribute
    mispDict['Galaxy'] = Galaxy
    mispDict['Object'] = Object
    return mispDict

def pattern_parser(pattern):
    #pattern_dict = {}
    for p in pattern:
        if ' LIKE ' in p:
            continue
        if p.startswith('('):
            print(p)
            p = p[1:]
            print(p)
        if p.endswith(')') and '(' not in p:
            p = p[:-1]
        pType, pValue = p.split(' = ')
    #    pattern_dict[pType] = pValue[1:-1]
    if len(pattern_dict) == 1:
        fieldType = 'attribute'
    #return fieldType

def observable_parser(observable):
    return

def saveFile(args, misp):
    filename = '{}.stix2'.format(args[1])
    eventDict = misp.to_json()
    with open(filename, 'w') as f:
        f.write(eventDict)

def checkIfFromMISP(stix2Event):
    for e in stix2Event:
        if e.get('type') == 'report' and 'misp:tool="misp2stix"' in e.get('labels'):
            return True
    return False

def main(args):
    pathname = os.path.dirname(sys.argv[0])
    stix2Event = loadEvent(args, pathname)
    stix2Event = stix2Event.get('objects')
    if checkIfFromMISP(stix2Event):
        mispDict = buildMispDict(stix2Event)
    else:
        mispDict = parseExternalStix(stix2Event)
    misp = pymisp.MISPEvent(None, False)
    misp.from_dict(**mispDict)
    saveFile(args, misp)
    print(1)

if __name__ == "__main__":
    main(sys.argv)
