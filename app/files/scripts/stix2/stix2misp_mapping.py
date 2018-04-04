def define_observable_hash_type(h_type):
    return 'SHA-{}'.format(h_type.split('sha')[1]) if 'sha' in h_type else h_type.upper()

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
