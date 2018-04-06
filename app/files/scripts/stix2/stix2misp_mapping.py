def define_observable_hash_type(h_type):
    if 'sha' in h_type:
        return 'SHA-{}'.format(h_type.split('sha')[1])
    if h_type == 'md5':
        return h_type.upper()
    return h_type

def parse_name(observable, _):
    return observable['0'].get('name')

def parse_value(observable, _):
    return observable['0'].get('value')

def parse_attachment(observable, _):
    return observable['0'].get('payload_bin')

def parse_domain_ip(observable, _):
    return "{}|{}".format(parse_value(observable, _), observable['1'].get('value'))

def parse_email_message(observable, attribute_type):
    return observable['0'].get(attribute_type.split('-')[1])

def parse_hash(observable, attribute_type):
    observable_type = define_observable_hash_type(attribute_type)
    return observable['0']['hashes'].get(observable_type)

def parse_ip_port(observable, _):
    try:
        port = observable['1']['src_port']
    except:
        port = observable['1']['dst_port']
    return '{}|{}'.format(parse_value(observable, _), port)

def parse_hostname_port(observable, _):
    return '{}|{}'.format(parse_value(observable, _), observable['1'].get('dst_port'))

def parse_filename_hash(observable, attribute_type):
    _, h = attribute_type.split('|')
    return "{}|{}".format(parse_name(observable, _), parse_hash(observable, h))

def parse_malware_sample(observable, _):
    return parse_filename_hash(observable, 'filename|md5')

def parse_port(observable, _):
    return observable

def parse_regkey(observable, _):
    return observable['0'].get('key')

def parse_regkey_value(observable, _):
    return '{}|{}'.format(parse_regkey(observable,_), parse_name(observable, _))

misp_types_mapping = {
    'md5': parse_hash,
    'sha1': parse_hash,
    'sha256': parse_hash,
    'filename': parse_name,
    'filename|md5': parse_filename_hash,
    'filename|sha1': parse_filename_hash,
    'filename|sha256': parse_filename_hash,
    'ip-src': parse_value,
    'ip-dst': parse_value,
    'hostname': parse_value,
    'domain': parse_value,
    'domain|ip': parse_domain_ip,
    'email-src': parse_value,
    'email-dst': parse_value,
    'email-subject': parse_email_message,
    'email-body': parse_email_message,
    'url': parse_value,
    'regkey': parse_regkey,
    'regkey|value': parse_regkey_value,
    'malware-sample': parse_malware_sample,
    'mutex': parse_name,
    'uri': parse_value,
    'authentihash': parse_hash,
    'ssdeep': parse_hash,
    'imphash': parse_hash,
    'pehash': parse_hash,
    'impfuzzy': parse_hash,
    'sha224': parse_hash,
    'sha384': parse_hash,
    'sha512': parse_hash,
    'sha512/224': parse_hash,
    'sha512/256': parse_hash,
    'tlsh': parse_hash,
    'filename|authentihash': parse_filename_hash,
    'filename|ssdeep': parse_filename_hash,
    'filename|imphash': parse_filename_hash,
    'filename|impfuzzy': parse_filename_hash,
    'filename|pehash': parse_filename_hash,
    'filename|sha224': parse_filename_hash,
    'filename|sha384': parse_filename_hash,
    'filename|sha512': parse_filename_hash,
    'filename|sha512/224': parse_filename_hash,
    'filename|sha512/256': parse_filename_hash,
    'filename|tlsh': parse_filename_hash,
    'x509-fingerprint-sha1': parse_hash,
    'port': parse_port,
    'ip-dst|port': parse_ip_port,
    'ip-src|port': parse_ip_port,
    'hostname|port': parse_hostname_port,
    'email-reply-to': parse_value,
    'attachment': parse_attachment,
    'mac-address': parse_value
}

def fill_attributes(attributes, stix_object, object_mapping):
    for o in stix_object:
        try:
            mapping = object_mapping[o]
        except:
            continue
        attributes.append({'type': mapping.get('type'), 'object_relation': mapping.get('relation'),
                           'value': stix_object.get(o)})

domain_ip_mapping = {'domain-name': {'type': 'domain', 'relation': 'domain'},
                     'ipv4-addr': {'type': 'ip-dst', 'relation': 'ip'},
                     'ipv6-addr': {'type': 'ip-dst', 'relation': 'ip'}}

def observable_domain_ip(observable):
    attributes = []
    for o in observable:
        observable_part = observable[o]
        part_type = observable_part._type
        mapping = domain_ip_mapping[part_type]
        attributes.append({'type': mapping.get('type'), 'object_relation': mapping.get('relation'),
                           'value': observable_part.get('value')})
    return attributes

def pattern_domain_ip(pattern):
    return pattern

email_mapping = {'to_refs': {'type': 'email-dst', 'relation': 'to'},
                 'cc_refs': {'type': 'email-dst', 'relation': 'cc'},
                 'subject': {'type': 'email-subject', 'relation': 'subject'},
                 'X-Mailer': {'type': 'email-x-mailer', 'relation': 'x-mailer'},
                 'Reply-To': {'type': 'email-reply-to', 'relation': 'reply-to'}}

def observable_email(observable):
    attributes = []
    addresses = {}
    files = {}
    for o in observable:
        observable_part = observable[o]
        part_type = observable_part._type
        if part_type == 'email-addr':
            addresses[o] = observable_part.get('value')
        elif part_type == 'file':
            files[o] = observable_part.get('name')
        else:
            message = dict(observable_part)
    attributes.append({'type': 'email-src', 'object_relation': 'from',
                       'value': addresses[message.pop('from_ref')]})
    for ref in ('to_refs', 'cc_refs', 'ouioui'):
        if ref in message:
            for item in message.pop(ref):
                mapping = email_mapping[ref]
                attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                                   'value': addresses[item]})
    if 'body_multipart' in message:
        for f in message.pop('body_multipart'):
            attributes.append({'type': 'email-attachment', 'object_relation': 'attachment',
                               'value': files[f.get('body_raw_ref')]})
    for m in message:
        if m == 'additional_header_fields':
            fields = message[m]
            for field in fields:
                mapping = email_mapping[field]
                if field == 'Reply-To':
                    for rt in fields[field]:
                        attributes.append({'type': mapping['type'],
                                           'object_relation': mapping['relation'],
                                           'value': rt})
                else:
                    attributes.append({'type': mapping['type'],
                                       'object_relation': mapping['relation'],
                                       'value': fields[field]})
        else:
            try:
                mapping = email_mapping[m]
            except:
                continue
            attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                               'value': message[m]})
    return attributes

def pattern_email(pattern):
    return pattern

file_mapping = {'mime_type': {'type': 'mime-type', 'relation': 'mimetype'},
                'name': {'type': 'filename', 'relation': 'filename'},
                'size': {'type': 'size-in-bytes', 'relation': 'size-in-bytes'}}

def observable_file(observable):
    attributes = []
    observable = dict(observable['0'])
    if 'hashes' in observable:
        hashes = observable.pop('hashes')
        for h in hashes:
            h_type = h.lower().replace('-', '')
            attributes.append({'type': h_type, 'object_relation': h_type,
                               'value': hashes[h]})
    fill_attributes(attributes, observable, file_mapping)
    return attributes

def pattern_file(pattern):
    return pattern

ip_port_mapping = {'src_port': {'type': 'port', 'relation': 'src-port'},
                   'dst_port': {'type': 'port', 'relation': 'dst-port'},
                   'start': {'type': 'datetime', 'relation': 'first-seen'},
                   'end': {'type': 'datetime', 'relation': 'last-seen'},
                   'value': {'type': 'domain', 'relation': 'domain'}}

def observable_ip_port(observable):
    attributes = []
    if len(observable) == 2:
        attributes.append({'type': 'ip-dst', 'object_relation': 'ip',
                           'value': observable['0'].get('value')})
    observable = dict(observable['1'])
    fill_attributes(attributes, observable, ip_port_mapping)
    return attributes

def pattern_ip_port(pattern):
    return pattern

regkey_mapping = {'data': {'type': 'text', 'relation': 'data'},
                  'data_type': {'type': 'text', 'relation': 'data-type'},
                  'modified': {'type': 'datetime', 'relation': 'last-modified'},
                  'name': {'type': 'text', 'relation': 'name'},
                  'key': {'type': 'regkey', 'relation': 'key'}}

def observable_regkey(observable):
    attributes = []
    observable = dict(observable['0'])
    if 'values' in observable:
        values = observable.pop('values')
        fill_attributes(attributes, values[0], regkey_mapping)
    # here following, we don't use the function just used on values bacause we may want to rearrange
    # the strings (such as for regkeys) but not for all the values in all the other objects
    for o in observable:
        try:
            mapping = regkey_mapping[o]
        except:
            continue
        attributes.append({'type': mapping.get('type'), 'object_relation': mapping.get('relation'),
                            'value': observable.get(o).replace('\\\\', '\\')})
    return attributes

def pattern_regkey(pattern):
    return pattern

url_mapping = {'url': {'type': 'url', 'relation': 'url'},
               'domain-name': {'type': 'domain', 'relation': 'domain'},
               'network-traffic': {'type': 'port', 'relation': 'port'}}

def observable_url(observable):
    attributes = []
    for o in observable:
        observable_part = observable[o]
        part_type = observable_part._type
        mapping = url_mapping[part_type]
        try:
            value = observable_part['value']
        except:
            value = observable_part['dst_port']
        attributes.append({'type': mapping['type'], 'object_relation': mapping['relation'],
                           'value': value})
    return attributes

def pattern_url(pattern):
    return pattern

x509_mapping = {'issuer': {'type': 'text', 'relation': 'issuer'},
                'serial_number': {'type': 'text', 'relation': 'serial-number'},
                'subject': {'type': 'text', 'relation': 'subject'},
                'subject_public_key_algorithm': {'type': 'text', 'relation': 'pubkey-info-algorithm'},
                'subject_public_key_exponent': {'type': 'text', 'relation': 'pubkey-info-exponent'},
                'subject_public_key_modulus': {'type': 'text', 'relation': 'pubkey-info-modulus'},
                'validity_not_before': {'type': 'datetime', 'relation': 'validity-not-before'},
                'validity_not_after': {'type': 'datetime', 'relation': 'validity-not-after'},
                'version': {'type': 'text', 'relation': 'version'},
                'SHA-1': {'type': 'x509-fingerprint-sha1', 'relation': 'x509-fingerprint-sha1'},
                'SHA-256': {'type': 'x509-fingerprint-sha256', 'relation': 'x509-fingerprint-sha256'},
                'MD5': {'type': 'x509-fingerprint-md5', 'relation': 'x509-fingerprint-md5'}}

def observable_x509(observable):
    attributes = []
    observable = dict(observable['0'])
    if 'hashes' in observable:
        hashes = observable.pop('hashes')
        fill_attributes(attributes, hashes, x509_mapping)
    fill_attributes(attributes, observable, x509_mapping)
    return attributes

def pattern_x509(pattern):
    return pattern

objects_mapping = {'domain-ip':{'observable': observable_domain_ip, 'pattern': pattern_domain_ip},
                   'email': {'observable': observable_email, 'pattern': pattern_email},
                   'file': {'observable': observable_file, 'pattern': pattern_file},
                   'ip-port': {'observable': observable_ip_port, 'pattern': pattern_ip_port},
                   'registry-key': {'observable': observable_regkey, 'pattern': pattern_regkey},
                   'url': {'observable': observable_url, 'pattern': pattern_url},
                   'x509': {'observable': observable_x509, 'pattern': pattern_x509}}
