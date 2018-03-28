def define_address_type(address):
    if ':' in address:
        return 'ipv6-addr'
    else:
        return 'ipv4-addr'

def observable_attachment(_, attribute_value):
    return {'0': {'type': 'artifact', 'payload_bin': attribute_value}}

def pattern_attachment(_, attribute_value):
    return "artifact:payload_bin = '{}'".format(attribute_value)

def observable_domain(_, attribute_value):
    return {'0': {'type': 'domain-name', 'value': attribute_value}}

def pattern_domain(_, attribute_value):
    return "domain-name:value = '{}'".format(attribute_value)

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
    domain = pattern_domain(_, domain_value)
    domain += " AND domain-name:resolves_to_refs[*].value = '{}'".format(ip_value)
    return domain

def observable_email_address(attribute_type, attribute_value):
    email_type = "from_ref" if 'src' in attribute_type else "to_refs"
    return {'0': {'type': 'email-addr', 'value': attribute_value},
            '1': {'type': 'email-message', email_type: '0', 'is_multipart': 'false'}}

def pattern_email_address(attribute_type, attribute_value):
    email_type = "from_ref" if 'src' in attribute_type else "to_refs"
    return "email-message:{} = '{}'".format(email_type, attribute_value)

def observable_email_message(attribute_type, attribute_value):
    email_type = attribute_type.split('-')[1]
    return {'0': {'type': 'email-message', email_type: attribute_value, 'is_multipart': 'false'}}

def pattern_email_message(attribute_type, attribute_value):
    email_type = attribute_type.split('-')[1]
    return "email-message:{} = '{}'".format(email_type, attribute_value)

def observable_file(_, attribute_value):
    return {'0': {'type': 'file', 'name': attribute_value}}

def pattern_file(_, attribute_value):
    return "file:name = '{}'".format(attribute_value)

def observable_file_hash(attribute_type, attribute_value):
    _, hash_type = attribute_type.split('|')
    value1, value2 = attribute_value.split('|')
    return {'0': {'type': 'file', 'name': value1, 'hashes': {hash_type: value2}}}

def pattern_file_hash(attribute_type, attribute_value):
    _, hash_type = attribute_type.split('|')
    value1, value2 = attribute_value.split('|')
    return "file:name = '{0}' AND file:hashes.'{1}' = '{2}'".format(value1, hash_type, value2)

def observable_hash(attribute_type, attribute_value):
    return {'0': {'type': 'file', 'hashes': {attribute_type: attribute_value}}}

def pattern_hash(attribute_type, attribute_value):
    return "file:hashes.'{}' = '{}'".format(attribute_type, attribute_value)

def observable_hostname_port(_, attribute_value):
    hostname, port = attribute_value.split('|')
    hostname_port = observable_domain(_, hostname)
    hostname_port[1] = observable_port(_, port)['0']
    return hostname_port

def pattern_hostname_port(_, attribute_value):
    hostname, port = attribute_value.split('|')
    return "{} AND {}".format(pattern_domain(_, hostname), pattern_port(_, port))

def observable_ip(attribute_type, attribute_value):
    ip_type = attribute_type.split('-')[1]
    address_type = define_address_type(attribute_value)
    return {'0': {'type': address_type, 'value': attribute_value},
            '1': {'type': 'network-traffic', '{}_ref'.format(ip_type): '0', 'protocols': ['tcp']}}

def pattern_ip(attribute_type, attribute_value):
    ip_type = attribute_type.split('-')[1]
    address_type = define_address_type(attribute_value)
    return "network-traffic:{0}_ref.type = '{1}' AND network-traffic:{0}_ref.value = '{2}'".format(ip_type, address_type, attribute_value)

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
    return "network-traffic:{} = '{}' AND {}".format(port_type, port, pattern_ip(ip_type, ip))

def observable_mac_address(_, attribute_value):
    return {'0': {'type': 'mac-addr', 'value': attribute_value}}

def pattern_mac_address(_, attribute_value):
    return "mac-addr:value = '{}'".format(attribute_value)

def observable_mutex(_, attribute_value):
    return {'0': {'type': 'mutex', 'name': attribute_value}}

def pattern_mutex(_, attribute_value):
    return "mutex:name = '{}'".format(attribute_value)

def observable_port(_, attribute_value):
    return {'0': {'type': 'network-traffic', 'dst_port': attribute_value, 'protocols': []}}

def pattern_port(_, attribute_value):
    return "network-traffic:dst_port = '{}'".format(attribute_value)

def observable_regkey(_, attribute_value):
    return {'0': {'type': 'windows-registry-key', 'key': attribute_value}}

def pattern_regkey(_, attribute_value):
    return "windows-registry-key:key = '{}'".format(attribute_value)

def observable_regkey_value(_, attribute_value):
    key, value = attribute_value.split('|')
    regkey = observable_regkey(_, key)
    regkey['0']['values'] = {'name': value}
    return regkey

def pattern_regkey_value(_, attribute_value):
    key, value = attribute_value.split('|')
    regkey = pattern_regkey(_, key)
    regkey += " AND windows-registry-key:values = '{}'".format(value)

def observable_reply_to(_, attribute_value):
    return {'0': {'type': 'email-addr', 'value': attribute_value},
            '1': {'type': 'email-message', 'additional_header_fields': {'Reply-To': ['0']}, 'is_multipart': 'false'}}

def pattern_reply_to(_, attribute_value):
    return "email-message:additional_header_fields.Reply-To = '{}'".format(attribute_value)

def observable_url(_, attribute_value):
    return {'0': {'type': 'url', 'value': attribute_value}}

def pattern_url(_, attribute_value):
    return "url:value = '{}'".format(attribute_value)

def observable_x509(_, attribute_value):
    return {'0': {'type': 'x509-certificate', 'hashes': {'sha1': attribute_value}}}

def pattern_x509(_, attribute_value):
    return "x509-certificate:hashes = '{}'".format(attribute_value)

def return_vulnerability(name):
    return {'source_name': 'cve', 'external_id': name}

mispTypesMapping = {
    'vulnerability': return_vulnerability,
    'md5': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha1': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha256': {'observable': observable_hash, 'pattern': pattern_hash},
    'filename': {'observable': observable_file, 'pattern': pattern_file},
    'filename|md5': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha1': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha256': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'ip-src': {'observable': observable_ip, 'pattern': pattern_ip},
    'ip-dst': {'observable': observable_ip, 'pattern': pattern_ip},
    'hostname': {'observable': observable_domain, 'pattern': pattern_domain},
    'domain': {'observable': observable_domain, 'pattern': pattern_domain},
    'domain|ip': {'observable': observable_domain_ip, 'pattern': pattern_domain_ip},
    'email-src': {'observable': observable_email_address, 'pattern': pattern_email_address},
    'email-dst': {'observable': observable_email_address, 'pattern': pattern_email_address},
    'email-subject': {'observable': observable_email_message, 'pattern': pattern_email_message},
    'email-body': {'observable': observable_email_message, 'pattern': pattern_email_message},
    'url': {'observable': observable_url, 'pattern': pattern_url},
    'regkey': {'observable': observable_regkey, 'pattern': pattern_regkey},
    'regkey|value': {'observable': observable_regkey_value, 'pattern': pattern_regkey_value},
    'malware-sample': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'mutex': {'observable': observable_mutex, 'pattern': pattern_mutex},
    'uri': {'observable': observable_url, 'pattern': pattern_url},
    'authentihash': {'observable': observable_hash, 'pattern': pattern_hash},
    'ssdeep': {'observable': observable_hash, 'pattern': pattern_hash},
    'imphash': {'observable': observable_hash, 'pattern': pattern_hash},
    'pehash': {'observable': observable_hash, 'pattern': pattern_hash},
    'impfuzzy': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha224': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha384': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha512': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha512/224': {'observable': observable_hash, 'pattern': pattern_hash},
    'sha512/256': {'observable': observable_hash, 'pattern': pattern_hash},
    'tlsh': {'observable': observable_hash, 'pattern': pattern_hash},
    'filename|authentihash': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|ssdeep': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|imphash': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|impfuzzy': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|pehash': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha224': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha384': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha512': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha512/224': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|sha512/256': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'filename|tlsh': {'observable': observable_file_hash, 'pattern': pattern_file_hash},
    'x509-fingerprint-sha1': {'observable': observable_x509, 'pattern': pattern_x509},
    'port': {'observable': observable_port, 'pattern': pattern_port},
    'ip-dst|port': {'observable': observable_ip_port, 'pattern': pattern_ip_port},
    'ip-src|port': {'observable': observable_ip_port, 'pattern': pattern_ip_port},
    'hostname|port': {'observable': observable_hostname_port, 'pattern': pattern_hostname_port},
    'email-reply-to': {'observable': observable_reply_to, 'pattern': pattern_reply_to},
    'attachment': {'observable': observable_attachment, 'pattern': pattern_attachment},
    'mac-address': {'observable': observable_mac_address, 'pattern': pattern_mac_address}
    #'email-dst-display-name': {'observable': {'0': {'type': 'email-addr', 'display_name': ''}},
    #                           'pattern': 'email-addr:display_name = \'{0}\''},
    #'email-src-display-name': {'observable': {'0': {'type': 'email-addr', 'display_name': ''}},
    #                           'pattern': 'email-addr:display_name = \'{0}\''}
}

objectsMapping = {'domain|ip': {'pattern': 'domain-name:{0} = \'{1}\' AND '},
                 'email': {'observable': {'0': {'type': 'email-message'}},
                           'pattern': 'email-{0}:{1} = \'{2}\' AND '},
                 'file': {'observable': {'0': {'type': 'file', 'hashes': {}}},
                          'pattern': 'file:{0} = \'{1}\' AND '},
                 'ip|port': {'pattern': 'network-traffic:{0} = \'{1}\' AND '},
                 'registry-key': {'observable': {'0': {'type': 'windows-registry-key'}},
                                  'pattern': 'windows-registry-key:{0} = \'{1}\' AND '},
                 'url': {'observable': {'0': {'type': 'url'}},
                         'pattern': 'url:{0} = \'{1}\' AND '},
                 'x509': {'observable': {'0': {'type': 'x509-certificate', 'hashes': {}}},
                          'pattern': 'x509-certificate:{0} = \'{1}\' AND '}
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
objectTypes = {'text': {'x509': {'subject': 'subject', 'issuer': 'issuer', 'pubkey-info-algorithm': 'subject_public_key_algorithm',
                                'pubkey-info-exponent': 'subject_public_key_exponent', 'pubkey-info-modulus': 'subject_public_key_modulus',
                                'serial-number': 'serial_number', 'version': 'version'},
                       'file': {'mimetype': 'mime_type'},
                       'registry-key': {'data-type': 'data_type', 'data': 'data', 'name': 'name'}},
              'datetime': {'x509': {'validity-not-before': 'validity_not_before', 'validity-not-after': 'validity_not_after'},
                           'ip|port': {'first-seen': 'start', 'last-seen': 'end'},
                           'email': 'date',
                           'registry-key': 'modified'},
              'port': {'src-port': 'src_port', 'dst-port': 'dst_port'}, 'url': 'value',
              'domain': {'domain': 'domain'}, 'email-x-mailer': 'additional_header_fields.X-Mailer',
              'email-subject': 'subject', 'email-attachment': 'body_multipart[*].body_raw_ref.name',
              'email-dst': {'to': 'to_refs', 'cc': 'cc_refs'}, 'email-src': 'from_ref',
              'email-reply-to': 'additional_header_fields.Reply-To',
              'hashes': 'hashes.\'{0}\'', 'size-in-bytes': 'size', 'filename': 'name',
              'ip-dst': {'ip|port': 'dst_ref.type = \'{0}\' AND network-traffic:dst_ref.value',
                         'domain|ip': 'resolves_to_refs[*].value'},
              'regkey': 'key'
}

defineProtocols = {'80': 'http', '443': 'https'}
