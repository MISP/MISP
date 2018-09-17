def attribute_data_observable(data):
    return {'type': 'artifact', 'payload_bin': data}

def attribute_data_pattern(data):
    return "artifact:payload_bin = '{}'".format(data)

def define_address_type(address):
    if ':' in address:
        return 'ipv6-addr'
    return 'ipv4-addr'

def observable_as(_, attribute_value):
    return {'0': {'type': 'autonomous-system', 'number': attribute_value}}

def pattern_as(_, attribute_value):
    return "[autonomous-system:number = '{}']".format(attribute_value)

def observable_attachment(*args):
    observable = observable_file(args[0], args[1])
    if len(args) == 3:
        observable['0']['content_ref'] = '0'
        return {'0': attribute_data_observable(args[2]), '1': observable['0']}
    return observable

def pattern_attachment(*args):
    pattern = pattern_file(args[0], args[1])[1:-1]
    if len(args) == 3:
        pattern += " AND {}".format(attribute_data_pattern(args[2]))
    return "[{}]".format(pattern)

def observable_domain(_, attribute_value):
    return {'0': {'type': 'domain-name', 'value': attribute_value}}

def pattern_domain(_, attribute_value):
    return "[domain-name:value = '{}']".format(attribute_value)

def observable_domain_ip(_, attribute_value):
    address_type = define_address_type(attribute_value)
    domain_value, ip_value = attribute_value.split('|')
    domain = observable_domain(_, domain_value)
    domain['0']['resolves_to_refs'] = '1'
    domain['1'] = {'type': address_type, 'value': ip_value}
    return domain

def pattern_domain_ip(_, attribute_value):
    address_type = define_address_type(attribute_value)
    domain_value, ip_value = attribute_value.split('|')
    domain = pattern_domain(_, domain_value)[1:-1]
    domain += " AND domain-name:resolves_to_refs[*].value = '{}'".format(ip_value)
    return "[{}]".format(domain)

def observable_email_address(attribute_type, attribute_value):
    email_type = "from_ref" if 'src' in attribute_type else "to_refs"
    return {'0': {'type': 'email-addr', 'value': attribute_value},
            '1': {'type': 'email-message', email_type: '0', 'is_multipart': 'false'}}

def pattern_email_address(attribute_type, attribute_value):
    email_type = "from_ref" if 'src' in attribute_type else "to_refs"
    return "[email-message:{} = '{}']".format(email_type, attribute_value)

def observable_email_attachment(_, attribute_value):
    observable = observable_file(_, attribute_value)
    observable['1'] = {"type": "email-message", 'is_multipart': 'true',
                       "body_multipart": [{"content_disposition": "attachment; filename=''".format(attribute_value), "body_raw_ref": "0"}]}
    return observable

def pattern_email_attachment(_, attribute_value):
    return "[email-message:body_multipart[*].body_raw_ref.name = '{}']".format(attribute_value)

def observable_email_message(attribute_type, attribute_value):
    email_type = attribute_type.split('-')[1]
    return {'0': {'type': 'email-message', email_type: attribute_value, 'is_multipart': 'false'}}

def pattern_email_message(attribute_type, attribute_value):
    email_type = attribute_type.split('-')[1]
    return "[email-message:{} = '{}']".format(email_type, attribute_value)

def observable_file(_, attribute_value):
    return {'0': {'type': 'file', 'name': attribute_value}}

def pattern_file(_, attribute_value):
    return "[file:name = '{}']".format(attribute_value)

def observable_file_hash(attribute_type, attribute_value):
    _, hash_type = attribute_type.split('|')
    value1, value2 = attribute_value.split('|')
    return {'0': {'type': 'file', 'name': value1, 'hashes': {hash_type: value2}}}

def pattern_file_hash(attribute_type, attribute_value):
    _, hash_type = attribute_type.split('|')
    value1, value2 = attribute_value.split('|')
    return "[file:name = '{0}' AND file:hashes.'{1}' = '{2}']".format(value1, hash_type, value2)

def observable_hash(attribute_type, attribute_value):
    return {'0': {'type': 'file', 'hashes': {attribute_type: attribute_value}}}

def pattern_hash(attribute_type, attribute_value):
    return "[file:hashes.'{}' = '{}']".format(attribute_type, attribute_value)

def observable_hostname_port(_, attribute_value):
    hostname, port = attribute_value.split('|')
    hostname_port = observable_domain(_, hostname)
    hostname_port[1] = observable_port(_, port)['0']
    return hostname_port

def pattern_hostname_port(_, attribute_value):
    hostname, port = attribute_value.split('|')
    return "[{} AND {}]".format(pattern_domain(_, hostname)[1:-1], pattern_port(_, port)[1:-1])

def observable_ip(attribute_type, attribute_value):
    ip_type = attribute_type.split('-')[1]
    address_type = define_address_type(attribute_value)
    return {'0': {'type': address_type, 'value': attribute_value},
            '1': {'type': 'network-traffic', '{}_ref'.format(ip_type): '0',
                  'protocols': [address_type.split('-')[0]]}}

def pattern_ip(attribute_type, attribute_value):
    ip_type = attribute_type.split('-')[1]
    address_type = define_address_type(attribute_value)
    return "[network-traffic:{0}_ref.type = '{1}' AND network-traffic:{0}_ref.value = '{2}']".format(ip_type, address_type, attribute_value)

def observable_ip_port(attribute_type, attribute_value):
    ip_type, _ = attribute_type.split('|')
    ip, port = attribute_value.split('|')
    ip_port = observable_ip(ip_type, ip)
    port_type = "{}_port".format(ip_type.split('-')[1])
    ip_port['1'][port_type] = port
    return ip_port

def pattern_ip_port(attribute_type, attribute_value):
    ip_type, _ = attribute_type.split('|')
    ip, port = attribute_value.split('|')
    port_type = "{}_port".format(ip_type.split('-')[1])
    return "[network-traffic:{} = '{}' AND {}]".format(port_type, port, pattern_ip(ip_type, ip)[1:-1])

def observable_mac_address(_, attribute_value):
    return {'0': {'type': 'mac-addr', 'value': attribute_value}}

def pattern_mac_address(_, attribute_value):
    return "[mac-addr:value = '{}']".format(attribute_value)

def observable_malware_sample(*args):
    observable = observable_file_hash("filename|md5", args[1])
    if len(args) == 3:
        observable['0']['content_ref'] = '0'
        return {'0': attribute_data_observable(args[2]), '1': observable['0']}
    return observable

def pattern_malware_sample(*args):
    pattern = pattern_file_hash("filename|md5", args[1])[1:-1]
    if len(args) == 3:
        pattern += " AND {}".format(attribute_data_pattern(args[2]))
    return "[{}]".format(pattern)

def observable_mutex(_, attribute_value):
    return {'0': {'type': 'mutex', 'name': attribute_value}}

def pattern_mutex(_, attribute_value):
    return "[mutex:name = '{}']".format(attribute_value)

def observable_port(_, attribute_value):
    return {'0': {'type': 'network-traffic', 'dst_port': attribute_value, 'protocols': []}}

def pattern_port(_, attribute_value):
    return "[network-traffic:dst_port = '{}']".format(attribute_value)

def observable_regkey(_, attribute_value):
    return {'0': {'type': 'windows-registry-key', 'key': attribute_value.strip()}}

def pattern_regkey(_, attribute_value):
    return "[windows-registry-key:key = '{}']".format(attribute_value.strip())

def observable_regkey_value(_, attribute_value):
    from stix2 import WindowsRegistryValueType
    key, value = attribute_value.split('|')
    regkey = observable_regkey(_, key)
    regkey['0']['values'] = WindowsRegistryValueType(**{'name': value.strip()})
    return regkey

def pattern_regkey_value(_, attribute_value):
    key, value = attribute_value.split('|')
    regkey = pattern_regkey(_, key)[1:-1]
    regkey += " AND windows-registry-key:values = '{}'".format(value.strip())
    return "[{}]".format(regkey)

def observable_reply_to(_, attribute_value):
    return {'0': {'type': 'email-addr', 'value': attribute_value},
            '1': {'type': 'email-message', 'additional_header_fields': {'Reply-To': ['0']}, 'is_multipart': 'false'}}

def pattern_reply_to(_, attribute_value):
    return "[email-message:additional_header_fields.reply_to = '{}']".format(attribute_value)

def observable_url(_, attribute_value):
    return {'0': {'type': 'url', 'value': attribute_value}}

def pattern_url(_, attribute_value):
    return "[url:value = '{}']".format(attribute_value)

def observable_x509(_, attribute_value):
    return {'0': {'type': 'x509-certificate', 'hashes': {'sha1': attribute_value}}}

def pattern_x509(_, attribute_value):
    return "[x509-certificate:hashes = '{}']".format(attribute_value)

def return_vulnerability(name):
    return {'source_name': 'cve', 'external_id': name}

mispTypesMapping = {
    'link': {'to_call': 'handle_link'},
    'vulnerability': {'to_call': 'add_vulnerability', 'vulnerability_args': return_vulnerability},
    'md5': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha1': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha256': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'filename': {'to_call': 'handle_usual_type', 'observable': observable_file, 'pattern': pattern_file},
    'filename|md5': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha1': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha256': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'ip-src': {'to_call': 'handle_usual_type', 'observable': observable_ip, 'pattern': pattern_ip},
    'ip-dst': {'to_call': 'handle_usual_type', 'observable': observable_ip, 'pattern': pattern_ip},
    'hostname': {'to_call': 'handle_usual_type', 'observable': observable_domain, 'pattern': pattern_domain},
    'domain': {'to_call': 'handle_usual_type', 'observable': observable_domain, 'pattern': pattern_domain},
    'domain|ip': {'to_call': 'handle_usual_type', 'observable': observable_domain_ip, 'pattern': pattern_domain_ip},
    'email-src': {'to_call': 'handle_usual_type', 'observable': observable_email_address, 'pattern': pattern_email_address},
    'email-dst': {'to_call': 'handle_usual_type', 'observable': observable_email_address, 'pattern': pattern_email_address},
    'email-subject': {'to_call': 'handle_usual_type', 'observable': observable_email_message, 'pattern': pattern_email_message},
    'email-body': {'to_call': 'handle_usual_type', 'observable': observable_email_message, 'pattern': pattern_email_message},
    'email-attachment': {'to_call': 'handle_usual_type', 'observable': observable_email_attachment, 'pattern': pattern_email_attachment},
    'url': {'to_call': 'handle_usual_type', 'observable': observable_url, 'pattern': pattern_url},
    'regkey': {'to_call': 'handle_usual_type', 'observable': observable_regkey, 'pattern': pattern_regkey},
    'regkey|value': {'to_call': 'handle_usual_type', 'observable': observable_regkey_value, 'pattern': pattern_regkey_value},
    'malware-sample': {'to_call': 'handle_usual_type', 'observable': observable_malware_sample, 'pattern': pattern_malware_sample},
    'mutex': {'to_call': 'handle_usual_type', 'observable': observable_mutex, 'pattern': pattern_mutex},
    'uri': {'to_call': 'handle_usual_type', 'observable': observable_url, 'pattern': pattern_url},
    'authentihash': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'ssdeep': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'imphash': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'pehash': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'impfuzzy': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha224': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha384': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha512': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha512/224': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'sha512/256': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'tlsh': {'to_call': 'handle_usual_type', 'observable': observable_hash, 'pattern': pattern_hash},
    'filename|authentihash': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|ssdeep': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|imphash': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|impfuzzy': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|pehash': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha224': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha384': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha512': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha512/224': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha512/256': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|tlsh': {'to_call': 'handle_usual_type', 'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'x509-fingerprint-sha1': {'to_call': 'handle_usual_type', 'observable': observable_x509, 'pattern': pattern_x509},
    'port': {'to_call': 'handle_usual_type', 'observable': observable_port, 'pattern': pattern_port},
    'ip-dst|port': {'to_call': 'handle_usual_type', 'observable': observable_ip_port, 'pattern': pattern_ip_port},
    'ip-src|port': {'to_call': 'handle_usual_type', 'observable': observable_ip_port, 'pattern': pattern_ip_port},
    'hostname|port': {'to_call': 'handle_usual_type', 'observable': observable_hostname_port, 'pattern': pattern_hostname_port},
    'email-reply-to': {'to_call': 'handle_usual_type', 'observable': observable_reply_to, 'pattern': pattern_reply_to},
    'attachment': {'to_call': 'handle_usual_type', 'observable': observable_attachment, 'pattern': pattern_attachment},
    'mac-address': {'to_call': 'handle_usual_type', 'observable': observable_mac_address, 'pattern': pattern_mac_address},
    'AS': {'to_call': 'handle_usual_type', 'observable': observable_as, 'pattern': pattern_as}
    #'email-dst-display-name': {'observable': {'0': {'type': 'email-addr', 'display_name': ''}},
    #                           'pattern': 'email-addr:display_name = \'{0}\''},
    #'email-src-display-name': {'observable': {'0': {'type': 'email-addr', 'display_name': ''}},
    #                           'pattern': 'email-addr:display_name = \'{0}\''}
}

network_traffic_pattern = "network-traffic:{0} = '{1}' AND "
network_traffic_src_ref = "src_ref.type = '{0}' AND network-traffic:src_ref.value"
network_traffic_dst_ref = "dst_ref.type = '{0}' AND network-traffic:dst_ref.value"

objectsMapping = {'asn': {'to_call': 'handle_usual_object_name',
                          'observable': {'type': 'autonomous-system'},
                          'pattern': "autonomous-system:{0} = '{1}' AND "},
                  'course-of-action': {'to_call': 'add_course_of_action_from_object'},
                  'domain-ip': {'to_call': 'handle_usual_object_name',
                                'pattern': "domain-name:{0} = '{1}' AND "},
                  'email': {'to_call': 'handle_usual_object_name',
                            'observable': {'0': {'type': 'email-message'}},
                            'pattern': "email-{0}:{1} = '{2}' AND "},
                  'file': {'to_call': 'handle_usual_object_name',
                           'observable': {'0': {'type': 'file', 'hashes': {}}},
                           'pattern': "file:{0} = '{1}' AND "},
                  'ip-port': {'to_call': 'handle_usual_object_name',
                              'pattern': network_traffic_pattern},
                  'network-socket': {'to_call': 'handle_usual_object_name',
                                     'pattern': network_traffic_pattern},
                  'pe': {'to_call': 'populate_objects_to_parse'},
                  'pe-section': {'to_call': 'populate_objects_to_parse'},
                  'process': {'to_call': 'handle_usual_object_name',
                              'pattern': "process:{0} = '{1}' AND "},
                  'registry-key': {'to_call': 'handle_usual_object_name',
                                   'observable': {'0': {'type': 'windows-registry-key'}},
                                   'pattern': "windows-registry-key:{0} = '{1}' AND "},
                  'url': {'to_call': 'handle_usual_object_name',
                          'observable': {'0': {'type': 'url'}},
                          'pattern': "url:{0} = '{1}' AND "},
                  'vulnerability': {'to_call': 'add_object_vulnerability'},
                  'x509': {'to_call': 'handle_usual_object_name',
                           'pattern': "x509-certificate:{0} = '{1}' AND "}
}

asnObjectMapping = {'asn': 'number', 'description': 'name', 'subnet-announced': 'value'}

domainIpObjectMapping = {'ip-dst': 'resolves_to_refs[*].value', 'domain': 'value'}

emailObjectMapping = {'email-body': {'email_type': 'message', 'stix_type': 'body'},
                      'subject': {'email_type': 'message', 'stix_type': 'subject'},
                      'to': {'email_type': 'message', 'stix_type': 'to_refs'}, 'cc': {'email_type': 'message', 'stix_type': 'cc_refs'},
                      'to-display-name': {'email_type': 'addr', 'stix_type': 'display_name'},
                      'from': {'email_type': 'message', 'stix_type': 'from_ref'},
                      'from-display-name': {'email_type': 'addr', 'stix_type': 'display_name'},
                      'reply-to': {'email_type': 'message', 'stix_type': 'additional_header_fields.reply_to'},
                      'attachment': {'email_type': 'message', 'stix_type': 'body_multipart[*].body_raw_ref.name'},
                      'send-date': {'email_type': 'message', 'stix_type': 'date'},
                      'x-mailer': {'email_type': 'message', 'stix_type': 'additional_header_fields.x_mailer'}}

fileMapping = {'hashes': "hashes.'{0}'", 'size-in-bytes': 'size', 'filename': 'name', 'mime-type': 'mime_type'}

ipPortObjectMapping = {'ip': network_traffic_dst_ref,
                       'src-port': 'src_port', 'dst-port': 'dst_port',
                       'first-seen': 'start', 'last-seen': 'end',
                       'domain': 'value'}

networkSocketMapping = {'address-family': 'address_family', 'domain-family': 'protocol_family',
                        'protocol': 'protocols', 'src-port': 'src_port', 'dst-port': 'dst_port',
                        'ip-src': network_traffic_src_ref, 'ip-dst': network_traffic_dst_ref,
                        'hostname-src': network_traffic_src_ref, 'hostname-dst': network_traffic_dst_ref}

peMapping = {'type': 'pe_type', 'number-sections': 'number_of_sections', 'imphash': 'imphash'}

peSectionMapping = {'name': 'name', 'size-in-bytes': 'size', 'entropy': 'entropy'}

processMapping = {'name': 'name', 'pid': 'pid', 'creation-time': 'created'}

regkeyMapping = {'data-type': 'data_type', 'data': 'data', 'name': 'name',
                 'last-modified': 'modified', 'key': 'key'}

urlMapping = {'url': 'value', 'domain': 'value', 'port': 'dst_port'}

x509mapping = {'pubkey-info-algorithm': 'subject_public_key_algorithm', 'subject': 'subject',
               'pubkey-info-exponent': 'subject_public_key_exponent', 'issuer': 'issuer',
               'pubkey-info-modulus': 'subject_public_key_modulus', 'serial-number': 'serial_number',
               'validity-not-before': 'validity_not_before', 'validity-not-after': 'validity_not_after',
               'version': 'version',}

defineProtocols = {'80': 'http', '443': 'https'}

relationshipsSpecifications = {'attack-pattern': {'vulnerability': 'targets', 'identity': 'targets',
                                                 'malware': 'uses', 'tool': 'uses'},
                              'campaign': {'intrusion-set': 'attributed-to', 'threat-actor': 'attributed-to',
                                           'identity': 'targets', 'vulnerability': 'targets',
                                           'attack-pattern': 'uses', 'malware': 'uses',
                                           'tool': 'uses'},
                              'course-of-action':{'attack-pattern': 'mitigates', 'malware': 'mitigates',
                                                  'tool': 'mitigates', 'vulnerability': 'mitigates'},
                              'indicator': {'attack-pattern': 'indicates', 'campaign': 'indicates',
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
