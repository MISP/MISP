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

import sys, json, os, datetime, re
import pymisp 
from stix2 import *

namespace = ['https://github.com/MISP/MISP', 'MISP']

not_implemented_attributes = ['yara', 'pattern-in-traffic', 'pattern-in-memory']

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email',
                            'target-machine', 'target-org', 'target-location', 'target-external',
                            'vulnerability', 'attachment']

mispTypesMapping = {'md5': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                            'pattern': 'file:hashes.\'md5\' = \'{0}\''},
                    'sha1': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                             'pattern': 'file:hashes.\'sha1\' = \'{0}\''},
                    'sha256': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                               'pattern': 'file:hashes.\'sha256\' = \'{0}\''},
                    'filename': {'observable': {'0': {'type': 'file', 'name': ''}},
                                 'pattern': 'file:name = \'{0}\''},
                    'filename|md5': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                     'pattern': 'file:name = \'{0}\' AND file:hashes.\'md5\' = \'{1}\''},
                    'filename|sha1': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                      'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha1\' = \'{1}\''},
                    'filename|sha256': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                        'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha256\' = \'{1}\''},
                    'ip-src': {'observable': {'0': {'type': '', 'value': ''}},
                               'pattern': '{0}:value = \'{1}\''},
                    'ip-dst': {'observable': {'0': {'type': '', 'value': ''}},
                               'pattern': '{0}:value = \'{1}\''},
                    'hostname': {'observable': {'0': {'type': 'domain-name', 'value': ''}},
                                 'pattern': 'domain-name:value = \'{0}\''},
                    'domain': {'observable': {'0': {'type': 'domain-name', 'value': ''}},
                               'pattern': 'domain-name:value = \'{0}\''},
                    'domain|ip': {'observable': {'0': {'type': 'domain-name', 'value': '', 'resolves_to_refs': '1'}, '1': {'type': '', 'value': ''}},
                                  'pattern': 'domain-name:value = \'{0}\' AND domain-name:resolves_to_refs[*].value = \'{1}\''},
                    'email-src': {'observable': {'0': {'type': 'email-addr', 'value': ''}},
                                  'pattern': 'email-addr:value = \'{0}\''},
                    'email-dst': {'observable': {'0': {'type': 'email-addr', 'value': ''}},
                                  'pattern': 'email-addr:value = \'{0}\''},
                    'email-subject': {'observable': {'0': {'type': 'email-message', 'subject': '', 'is_multipart': 'false'}},
                                      'pattern': 'email-message:subject = \'{0}\''},
#                    'email-attachment': {'observable': '', 'pattern': ''},
                    'email-body': {'observable': {'0': {'type': 'email-message', 'body': '', 'is_multipart': 'false'}},
                                   'pattern': 'email-message:body = \'{0}\''},
                    'url': {'observable': {'0': {'type': 'url', 'value': ''}},
                            'pattern': 'url:value = \'{0}\''},
                    'regkey': {'observable': {'0': {'type': 'windows-registry-key', 'key': ''}},
                               'pattern': 'windows-registry-key:key = \'{0}\''},
                    'regkey|value': {'observable': {'0': {'type': 'windows-registry-key', 'key': '', 'values': {'name': ''}}},
                                     'pattern': 'windows-registry-key:key = \'{0}\' AND windows-registry-key:values = \'{1}\''},
                    'malware-sample': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                       'pattern': 'file:name = \'{0}\' AND file:hashes.\'md5\' = \'{1}\''},
                    'mutex': {'observable': {'0': {'type': 'mutex', 'name': ''}},
                              'pattern': 'mutex:name = \'{0}\''},
                    'uri': {'observable': {'0': {'type': 'url', 'value': ''}},
                            'pattern': 'url:value = \'{0}\''},
                    'authentihash': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                                     'pattern': 'file:hashes.\'authentihash\' = \'{0}\''},
                    'ssdeep': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                               'pattern': 'file:hashes.\'ssdeep\' = \'{0}\''},
                    'imphash': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                                'pattern': 'file:hashes.\'imphash\' = \'{0}\''},
                    'pehash': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                               'pattern': 'file:hashes.\'pehash\' = \'{0}\''},
                    'impfuzzy': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                                 'pattern': 'file:hashes.\'impfuzzy\' = \'{0}\''},
                    'sha224': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                               'pattern': 'file:hashes.\'sha224\' = \'{0}\''},
                    'sha384': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                               'pattern': 'file:hashes.\'sha384\' = \'{0}\''},
                    'sha512': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                               'pattern': 'file:hashes.\'sha512\' = \'{0}\''},
                    'sha512/224': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                                   'pattern': 'file:hashes.\'sha512/224\' = \'{0}\''},
                    'sha512/256': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                                   'pattern': 'file:hashes.\'sha512/256\' = \'{0}\''},
                    'tlsh': {'observable': {'0': {'type': 'file', 'hashes': ''}},
                             'pattern': 'file:hashes.\'tlsh\' = \'{0}\''},
                    'filename|authentihash': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                              'pattern': 'file:name = \'{0}\' AND file:hashes.\'authentihash\' = \'{1}\''},
                    'filename|ssdeep': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                        'pattern': 'file:name = \'{0}\' AND file:hashes.\'ssdeep\' = \'{1}\''},
                    'filename|imphash': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                         'pattern': 'file:name = \'{0}\' AND file:hashes.\'imphash\' = \'{1}\''},
                    'filename|impfuzzy': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                          'pattern': 'file:name = \'{0}\' AND file:hashes.\'impfuzzy\' = \'{1}\''},
                    'filename|pehash': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                        'pattern': 'file:name = \'{0}\' AND file:hashes.\'pehash\' = \'{1}\''},
                    'filename|sha224': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                        'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha224\' = \'{1}\''},
                    'filename|sha384': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                        'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha384\' = \'{1}\''},
                    'filename|sha512': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                        'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha512\' = \'{1}\''},
                    'filename|sha512/224': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                            'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha512/224\' = \'{1}\''},
                    'filename|sha512/256': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                            'pattern': 'file:name = \'{0}\' AND file:hashes.\'sha512/256\' = \'{1}\''},
                    'filename|tlsh': {'observable': {'0': {'type': 'file', 'name': '', 'hashes': ''}},
                                      'pattern': 'file:name = \'{0}\' AND file:hashes.\'tlsh\' = \'{1}\''},
                    'x509-fingerprint-sha1': {'observable': {'0': {'type': 'x509-certificate', 'hashes': {'sha1': ''}}},
                                              'pattern': 'x509-certificate:hashes = \'{0}\''},
                    'port': {'observable': {'0': {'type': 'network-traffic', 'dst_port': ''}},
                             'pattern': 'network-traffic:dst_port = \'{0}\''},
                    'ip-dst|port': {'observable': {'0': {'type': '', 'value': ''}, '1': {'type': 'network-traffic', 'dst_ref': '0', 'dst_port': ''}},
                                    'pattern': 'network-traffic:dst_port = \'{1}\' AND network-traffic:dst_ref.type = \'{2}\' AND network-traffic:dst_ref.value = \'{0}\''},
                    'ip-src|port': {'observable': {'0': {'type': '', 'value': ''}, '1': {'type': 'network-traffic', 'src_ref': '0', 'dst_port': ''}},
                                    'pattern': 'network-traffic:dst_port = \'{1}\' AND network-traffic:src_ref.type = \'{2}\' AND network-traffic:src_ref.value = \'{0}\''},
                    'hostname|port': {'observable': {'0': {'type': 'domain-name', 'value': ''}, '1': {'type': 'traffic-network', 'dst_ref': '0', 'dst_port': ''}},
                                      'pattern': 'domain-name:value = \'{0}\' AND network-traffic:dst_port = \'{1}\''},
                    }

relationshipsSpecifications = {'attack-pattern': {'vulnerability': 'targets', 'identity': 'targets',
                                                  'malware': 'uses', 'tool': 'uses'},
                               'campaign': {'intrusion-set': 'attributed-to', 'threat-actor': 'attributed-to',
                                            'identity': 'targets', 'vulnerability': 'targets',
                                            'attack-pattern': 'uses', 'malware': 'uses',
                                            'tool': 'uses'},
                               'course-of-action':{'attack-pattern': 'mitigates', 'malware': 'mitigates',
                                                   'tool': 'mitigates', 'vulnerability': 'mitigates'},
                               'indicator': {'attack-pattern': 'indicates', 'cacmpaign': 'indicates',
                                             'intrusion-set': 'indicates', 'malware': 'indicates',
                                             'threat-actor': 'indicates', 'tool': 'indicates'},
                               'intrusion-set': {'threat-actor': 'attributed-to', 'identity': 'targets',
                                                 'vulnerability': 'targets', 'attack-pattern': 'uses',
                                                 'malware': 'uses', 'tool': 'uses'},
                               'malware': {'identity': 'targets', 'vulnerability': 'targets',
                                           'tool': 'uses', 'malware': 'variant-of'},
                               'threat-actor': {'identity': 'attributed-to', 'vulnerability': 'targets',
                                                'attack-pattern': 'uses', 'malware': 'uses',
                                                'tool': 'uses'},
                               'tool': {'identity': 'targets', 'vulnerability': 'targets'}
                               }

def loadEvent(args, pathname):
    try:
        filename = args[1]
        tempFile = open(filename, 'r')
        events = json.loads(tempFile.read())
        return events
    except:
        print(json.dumps({'success' : 0, 'message' : 'The temporary MISP export file could not be read'}))
        sys.exit(1)

def saveFile(args, pathname, package):
    filename = args[1] + '.out'
    with open(filename, 'w') as f:
        f.write(str(package))

# converts timestamp to the format used by STIX
def getDateFromTimestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp).isoformat() + "+00:00"

def setIdentity(event):
    org = event.Orgc
    identity = Identity(type="identity", id="identity--{}".format(org["uuid"]),
                        name=org["name"], identity_class="organization")
    return identity

def readAttributes(event, identity, object_refs, external_refs):
    attributes = []
    for attribute in event.attributes:
        attr_type = attribute['type']
        if attr_type not in mispTypesMapping:
            continue
        if attr_type in non_indicator_attributes:
            if attr_type == "link":
                handleLink(attribute, external_refs)
            elif attr_type in ('text', 'comment', 'other'):
                addCustomObject(object_refs, attributes, attribute, identity)
            else:
                handleNonIndicatorAttribute(object_refs, attributes, attribute, identity)
        else:
            if attribute['to_ids']:
                handleIndicatorAttribute(object_refs, attributes, attribute, identity)
            else:
                addObservedData(object_refs, attributes, attribute, identity)
    if event['Galaxy']:
        galaxies = event['Galaxy']
        for galaxy in galaxies:
            galaxyType = galaxy['type']
            if 'attack-pattern' in galaxyType:
                addAttackPattern(object_refs, attributes, galaxy, identity)
            elif 'course' in galaxyType:
                addCourseOfAction(object_refs, attributes, galaxy, identity)
            elif 'intrusion' in galaxyType:
                addIntrusionSet(object_refs, attributes, galaxy, identity)
            elif 'ware' in galaxyType:
                addMalware(object_refs, attributes, galaxy, identity)
            elif galaxyType in ['threat-actor', 'microsoft-activity-group']:
                addThreatActor(object_refs, attributes, galaxy, identity)
            elif galaxyType in ['rat', 'exploit-kit'] or 'tool' in galaxyType:
                addTool(object_refs, attributes, galaxy, identity)
    return attributes

def handleLink(attribute, external_refs):
    url = attribute['value']
    source = 'url'
    if 'comment' in attribute:
        source += ' - {}'.format(attribute['comment'])
    link = {'source_name': source, 'url': url}
    external_refs.append(link)


def addAttackPattern(object_refs, attributes, galaxy, identity):
    killchain = [{'kill_chain_name': 'misp-category',
                  'phase_name': galaxy['type']}
                 ]
    cluster = galaxy['GalaxyCluster'][0]
    attack_id = "attack-pattern--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    attack_args = {'id': attack_id, 'type': 'attack-pattern', 'created_by_ref': identity, 'name': name,
                  'description': description, 'kill_chain_phases': killchain}
    if cluster['tag_name']:
        attack_args['labels'] = cluster['tag_name']
    attackPattern = AttackPattern(**attack_args)
    attributes.append(attackPattern)
    object_refs.append(attack_id)

def addCampaign(object_refs, attributes, galaxy, identity):
    cluster = galaxy['GalaxyCluster'][0]
    campaign_id = "campaign--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    campaign_args = {'id': campaign_id, 'type': 'campaign', 'name': name, 'description': description,
                     'created_by_ref': identity}
    if cluster['tag_name']:
        campaign_args['labels'] = cluster['tag_name']
    meta = cluster['meta']
    addAliases(meta, campaign_args)
    campaign = Campaign(**campaign_args)
    attributes.append(campaign)
    object_refs.append(campaign_id)

def addCourseOfAction(object_refs, attributes, galaxy, identity):
    cluster = galaxy['GalaxyCluster'][0]
    courseOfAction_id = "course-of-action--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    courseOfAction_args = {'id': courseOfAction_id, 'type': 'course-of-action', 'name': name,
                           'description': description, 'created_by_ref': identity}
    if cluster['tag_name']:
        courseOfAction_args['labels'] = cluster['tag_name']
    courseOfAction = CourseOfAction(**courseOfAction_args)
    attributes.append(courseOfAction)
    object_refs.append(courseOfAction_id)

def addCustomObject(object_refs, attributes, attribute, identity):
    customObject_id = "x-misp-object--{}".format(attribute['uuid'])
    timestamp = attribute['timestamp']
    customObject_type = 'x-misp-object'.format(attribute['type'])
    to_ids = attribute['to_ids']
    value = attribute['value']
    labels = 'misp:to_ids=\"{}\"'.format(attribute['to_ids'])
    customObject_args = {'type': customObject_type, 'id': customObject_id, 'timestamp': timestamp,
                         'to_ids': to_ids, 'value': value, 'created_by_ref': identity, 'labels': labels}
    if attribute['comment']:
        customObject_args['comment'] = attribute['comment']
    # At the moment, we skip it
#    attributes.append(customObject_args)
#    object_refs.append(customObject_id)

def addIdentity(object_refs, attributes, attribute, identity):
    identity_id = "identity--{}".format(attribute['uuid'])
    name = attribute['value']
    identityClass = defineIdentityClass(attribute['type'])
    identity_args = {'id': identity, 'type': 'identity', 'name': name, 'created_by_ref': identity, 'identity_class': identityClass}
    if 'comment' in attribute:
        identity_args['descritpion'] = attribute['comment']
    identityObject = Identity(**identity_args)
    attributes.append(identityObject)
    object_refs.append(identityObject)

def addIntrusionSet(object_refs, attributes, galaxy, identity):
    cluster = galaxy['GalaxyCluster'][0]
    intrusionSet_id = "intrusion-set--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    intrusion_args = {'id': intrusionSet_id, 'type': 'intrusion-set', 'name': name, 'description': description,
                      'created_by_ref': identity}
    meta = cluster['meta']
    if "synonyms" in meta:
        addAliases(meta, intrusion_args)
    if cluster['tag_name']:
        intrusion_args['labels'] = cluster['tag_name']
    intrusionSet = IntrusionSet(**intrusion_args)
    attributes.append(intrusionSet)
    object_refs.append(intrusionSet_id)

def addMalware(object_refs, attributes, galaxy, identity):
    killchain = [{'kill_chain_name': 'misp-category',
                  'phase_name': galaxy['type']}
                 ]
    cluster = galaxy['GalaxyCluster'][0]
    malware_id = "malware--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    malware_args = {'id': malware_id, 'type': 'malware', 'name': name, 'description': description,
                    'created_by_ref': identity, 'kill_chain_phases': killchain}
    if cluster['tag_name']:
        malware_args['labels'] = cluster['tag_name']
    malware = Malware(**malware_args)
    attributes.append(malware)
    object_refs.append(malware_id)

#def addNote(object_refs, attributes, attribute, identity):         ## SEEMS LIKE IT WILL APPEAR IN THE ##
#    note_id = "note--{}".format(attribute['uuid'])                 ##          UPCOMMING CHANGES       ##
#    note_args = {}
#    note = Note(**note_args)
#    attributes.append(note)
#    object_refs.append(note)

def addObservedData(object_refs, attributes, attribute, identity):
    observedData_id = "observed-data--{}".format(attribute['uuid'])
    timestamp = attribute['timestamp']
    attr_type = attribute['type']
    attr_val = attribute['value']
    objects = defineObservableObject(attr_type, attr_val)
    labels = 'misp:to_ids=\"{}\"'.format(attribute['to_ids'])
    observedData_args = {'id': observedData_id, 'type': 'observed-data', 'number_observed': 1,
                         'first_observed': timestamp, 'last_observed': timestamp, 'objects': objects,
                         'created_by_ref': identity, 'labels': labels}
    observedData = ObservedData(**observedData_args)
    attributes.append(observedData)
    object_refs.append(observedData_id)

def addThreatActor(object_refs, attributes, galaxy, identity):
    cluster = galaxy['GalaxyCluster'][0]
    threatActor_id = "threat-actor--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    threatActor_args = {'id': threatActor_id, 'type': 'threat-actor', 'name': name, 'description': description,
                        'created_by_ref': identity}
    meta = cluster['meta']
    if 'synonyms' in meta:
        addAliases(meta, threatActor_args)
    if cluster['tag_name']:
        threatActor_args['labels'] = cluster['tag_name']
    threatActor = ThreatActor(**threatActor_args)
    attributes.append(threatActor)
    object_refs.append(threatActor_id)

def addTool(object_refs, attributes, galaxy, identity):
    killchain = [{'kill_chain_name': 'misp-category',
                  'phase_name': galaxy['type']}
                 ]
    cluster = galaxy['GalaxyCluster'][0]
    tool_id = "tool--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    tool_args = {'id': tool_id, 'type': 'tool', 'name': name, 'description': description,
                 'created_by_ref': identity, 'kill_chain_phases': killchain}
    if cluster['tag_name']:
        tool_args['labels'] = cluster['tag_name']
    tool = Tool(**tool_args)
    attributes.append(tool)
    object_refs.append(tool_id)

def addVulnerability(object_refs, attributes, attribute, identity):
    vuln_id = "vulnerability--{}".format(attribute['uuid'])
    name = attribute['value']
    ext_refs = [{'source_name': 'cve',
                 'external_id': name}]
    labels = 'misp:to_ids=\"{}\"'.format(attribute['to_ids'])
    vuln_args = {'type': 'vulnerability', 'id': vuln_id, 'external_references': ext_refs, 'name': name,
                 'created_by_ref': identity, 'labels': labels}
    vulnerability = Vulnerability(**vuln_args)
    attributes.append(vulnerability)
    object_refs.append(vuln_id)

def addAliases(meta, argument):
    aliases = []
    for a in meta['synonyms']:
        aliases.append(a)
    argument['aliases'] = aliases

def handleNonIndicatorAttribute(object_refs, attributes, attribute, identity):
    attr_type = attribute['type']
    if attr_type == "vulnerability":
        addVulnerability(object_refs, attributes, attribute, identity)
    else:
        addObservedData(object_refs, attributes, attribute, identity)

def handleIndicatorAttribute(object_refs, attributes, attribute, identity):
    indic_id = "indicator--{}".format(attribute['uuid'])
    category = attribute['category']
    killchain = [{'kill_chain_name': 'misp-category',
                 'phase_name': category}]
    labels = 'misp:to_ids=\"{}\"'.format(attribute['to_ids'])
    attr_type = attribute['type']
    attr_val = attribute['value']
    args_indicator = {'valid_from': attribute['timestamp'], 'type': 'indicator',
                      'labels': labels, 'pattern': [definePattern(attr_type, attr_val)], 'id': indic_id,
                      'created_by_ref': identity, 'kill_chain_phases': killchain}
    if attribute['comment']:
        args_indicator['description'] = attribute['comment']
    indicator = Indicator(**args_indicator)
    attributes.append(indicator)
    object_refs.append(indic_id)

def buildRelationships(attributes, object_refs):
    return

def defineObservableObject(attr_type, attr_val):
    observed_object = mispTypesMapping[attr_type]['observable'].copy()
    object0 = observed_object['0']
    if '|' in attr_type:
        _, attr_type2 = attr_type.split('|')
        attr_val1, attr_val2 = attr_val.split('|')
        object1 = observed_object['1']
        if '|ip' in attr_type:
            addr_type = defineAddressType(attr_val2)
            object0['value'] = attr_val1
            object1['type'] = addr_type
            object1['value'] = attr_val2
        elif 'ip-' in attr_type:
            addr_type = defineAddressType(attr_val2)
            object0['type'] = addr_type
            object0['value'] = attr_val1
            object1['dst_port'] = attr_val2
        elif 'hostname' in attr_type:
            object0['value'] = attr_val1
            object1['dst_port'] = attr_val2
        elif 'regkey' in attr_type:
            object0['key'] = attr_val1
            object0['values']['name'] = attr_val2
        else:
            object0['name'] = attr_val1
            object0['hashes'] = {attr_type2: attr_val2}
    elif attr_type == 'malware-sample':
        attr_val1, attr_val2 = attr_val.split('|')
        object0['name'] = attr_val1
        object0['hashes'] = {'md5': attr_val2}
    else:
        if 'x509' in attr_type:
            object0['hashes']['sha1'] = attr_val
            return observed_object
        elif 'ip-' in attr_type:
            addr_type = defineAddressType(attr_val)
            object0['type'] = addr_type
        for obj_attr in object0:
            if obj_attr in ('name', 'value', 'body', 'subject', 'dst_port', 'key'):
                object0[obj_attr] = attr_val
            if 'hashes' in obj_attr:
                object0[obj_attr] = {attr_type: attr_val}
    return observed_object

def definePattern(attr_type, attr_val):
    if '|' in attr_type:
        attr_type1, attr_type2 = attr_type.split('|')
        attr_val1, attr_val2 = attr_val.split('|')
        if 'ip-' in attr_type1 or 'ip' in attr_type2:
            addr_type = defineAddressType(attr_val2)
            pattern = mispTypesMapping[attr_type]['pattern'].format(attr_val1, attr_val2, addr_type)
        else:
            pattern = mispTypesMapping[attr_type]['pattern'].format(attr_val1, attr_val2)
    elif attr_type == 'malware-sample':
        attr_val1, attr_val2 = attr_val.split('|')
        pattern = mispTypesMapping[attr_type]['pattern'].format(attr_val1, attr_val2)
    else:
        if 'ip-' in attr_type:
            addr_type = defineAddressType(attr_val)
            pattern = mispTypesMapping[attr_type]['pattern'].format(addr_type, attr_val)
        else:
            pattern = mispTypesMapping[attr_type]['pattern'].format(attr_val)
    return pattern

def defineAddressType(attr_val):
    if ':' in attr_val:
        addr_type = 'ipv6-addr'
    else:
        addr_type = 'ipv4-addr'
    return addr_type

def defineIdentityClass(attr_type):
    identityClass = 'unknown'
    if attr_type in ('**name'):
        identityClass = 'individual'
    return identityClass

def eventReport(event, identity, object_refs, external_refs):
    timestamp = event["publish_timestamp"]
    name = event["info"]
    labels = []
    if 'Tag' in event:
        tags = event['Tag']
        for tag in tags:
            labels.append(tag['name'])

    args_report = {'type': "report", 'id': "report--{}".format(event["uuid"]), 'created_by_ref': identity["id"],
                    'name': name, 'published': timestamp}

    if labels:
        args_report['labels'] = labels
    else:
        args_report['labels'] = ['threat-report']

    if object_refs:
        args_report['object_refs'] = object_refs
    if external_refs:
        args_report['external_references'] = external_refs
    report = Report(**args_report)
    return report

def generateEventPackage(event, SDOs):
    bundle_id = event['uuid']
    bundle_args = {'type': "bundle", 'spec_version': "2.0", 'id': "bundle--{}".format(bundle_id), 'objects': SDOs}
    bundle = Bundle(**bundle_args)
    return bundle

def main(args):
    pathname = os.path.dirname(sys.argv[0])
    if len(sys.argv) > 3:
        namespace[0] = sys.argv[3]
    if len(sys.argv) > 4:
        namespace[1] = sys.argv[4].replace(" ", "_")
        namespace[1] = re.sub('[\W]+', '', namespace[1])
    misp = pymisp.MISPEvent(None, False)
    misp.load_file(os.path.join(pathname, args[1]))
    SDOs = []
    object_refs = []
    external_refs = []
    identity = setIdentity(misp)
    SDOs.append(identity)
    attributes = readAttributes(misp, identity, object_refs, external_refs)
    buildRelationships(attributes, object_refs)
    report = eventReport(misp, identity, object_refs, external_refs)
    SDOs.append(report)
    for attribute in attributes:
        SDOs.append(attribute)
    stix_package = generateEventPackage(misp, SDOs)
    saveFile(args, pathname, stix_package)
    print(1)

if __name__ == "__main__":
    main(sys.argv)
