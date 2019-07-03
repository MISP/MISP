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
    if len(observable) > 1:
        return observable['1'].get('name'), observable['0'].get('payload_bin')
    return observable['0'].get('name')

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
    except KeyError:
        port = observable['1']['dst_port']
    return '{}|{}'.format(parse_value(observable, _), port)

def parse_hostname_port(observable, _):
    return '{}|{}'.format(parse_value(observable, _), observable['1'].get('dst_port'))

def parse_filename_hash(observable, attribute_type):
    _, h = attribute_type.split('|')
    return "{}|{}".format(parse_name(observable, _), parse_hash(observable, h))

def parse_malware_sample(observable, _):
    if len(observable) > 1:
        file_observable = observable['1']
        filename = file_observable['name']
        md5 = file_observable['hashes']['MD5']
        return "{}|{}".format(filename, md5), observable['0'].get('payload_bin')
    return parse_filename_hash(observable, 'filename|md5')

def parse_number(observable, _):
    return observable['0'].get('number')

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
    'email-attachment': parse_name,
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
    'cdhash': parse_hash,
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
    'mac-address': parse_value,
    'AS': parse_number
}

address_family_attribute_mapping = {'type': 'text','relation': 'address-family'}
as_number_attribute_mapping = {'type': 'AS', 'relation': 'asn'}
asn_description_attribute_mapping = {'type': 'text', 'relation': 'description'}
asn_subnet_attribute_mapping = {'type': 'ip-src', 'relation': 'subnet-announced'}
body_multipart_mapping = {'type': 'email-attachment', 'relation': 'attachment'}
cc_attribute_mapping = {'type': 'email-dst', 'relation': 'cc'}
data_attribute_mapping = {'type': 'text', 'relation': 'data'}
data_type_attribute_mapping = {'type': 'text', 'relation': 'data-type'}
domain_attribute_mapping = {'type': 'domain', 'relation': 'domain'}
domain_family_attribute_mapping = {'type': 'text', 'relation': 'domain-family'}
dst_port_attribute_mapping = {'type': 'port', 'relation': 'dst-port'}
email_date_attribute_mapping = {'type': 'datetime', 'relation': 'send-date'}
email_subject_attribute_mapping = {'type': 'email-subject', 'relation': 'subject'}
end_datetime_attribute_mapping = {'type': 'datetime', 'relation': 'last-seen'}
entropy_mapping = {'type': 'float', 'relation': 'entropy'}
filename_attribute_mapping = {'type': 'filename', 'relation': 'filename'}
from_attribute_mapping = {'type': 'email-src', 'relation': 'from'}
imphash_mapping = {'type': 'imphash', 'relation': 'imphash'}
ip_attribute_mapping = {'type': 'ip-dst', 'relation': 'ip'}
issuer_attribute_mapping = {'type': 'text', 'relation': 'issuer'}
key_attribute_mapping = {'type': 'regkey', 'relation': 'key'}
mime_type_attribute_mapping = {'type': 'mime-type', 'relation': 'mimetype'}
modified_attribute_mapping = {'type': 'datetime', 'relation': 'last-modified'}
number_sections_mapping = {'type': 'counter', 'relation': 'number-sections'}
password_mapping = {'type': 'text', 'relation': 'password'}
pe_type_mapping = {'type': 'text', 'relation': 'type'}
pid_attribute_mapping = {'type': 'text', 'relation': 'pid'}
process_command_line_mapping = {'type': 'text', 'relation': 'command-line'}
process_creation_time_mapping = {'type': 'datetime', 'relation': 'creation-time'}
process_name_mapping = {'type': 'text', 'relation': 'name'}
regkey_name_attribute_mapping = {'type': 'text', 'relation': 'name'}
reply_to_attribute_mapping = {'type': 'email-reply-to', 'relation': 'reply-to'}
section_name_mapping = {'type': 'text', 'relation': 'name'}
serial_number_attribute_mapping = {'type': 'text', 'relation': 'serial-number'}
size_attribute_mapping = {'type': 'size-in-bytes', 'relation': 'size-in-bytes'}
src_port_attribute_mapping = {'type': 'port', 'relation': 'src-port'}
start_datetime_attribute_mapping = {'type': 'datetime', 'relation': 'first-seen'}
state_attribute_mapping = {'type': 'text', 'relation': 'state'}
to_attribute_mapping = {'type': 'email-dst', 'relation': 'to'}
url_attribute_mapping = {'type': 'url', 'relation': 'url'}
url_port_attribute_mapping = {'type': 'port', 'relation': 'port'}
username_mapping = {'type': 'text', 'relation': 'username'}
x_mailer_attribute_mapping = {'type': 'email-x-mailer', 'relation': 'x-mailer'}
x509_md5_attribute_mapping = {'type': 'x509-fingerprint-md5', 'relation': 'x509-fingerprint-md5'}
x509_sha1_attribute_mapping = {'type': 'x509-fingerprint-sha1', 'relation': 'x509-fingerprint-sha1'}
x509_sha256_attribute_mapping = {'type': 'x509-fingerprint-sha256', 'relation': 'x509-fingerprint-sha256'}
x509_spka_attribute_mapping = {'type': 'text', 'relation': 'pubkey-info-algorithm'} # x509 subject public key algorithm
x509_spke_attribute_mapping = {'type': 'text', 'relation': 'pubkey-info-exponent'} # x509 subject public key exponent
x509_spkm_attribute_mapping = {'type': 'text', 'relation': 'pubkey-info-modulus'} # x509 subject public key modulus
x509_subject_attribute_mapping = {'type': 'text', 'relation': 'subject'}
x509_version_attribute_mapping = {'type': 'text', 'relation': 'version'}
x509_vna_attribute_mapping = {'type': 'datetime', 'relation': 'validity-not-after'} # x509 validity not after
x509_vnb_attribute_mapping = {'type': 'datetime', 'relation': 'validity-not-before'} # x509 validity not before

asn_mapping = {'number': as_number_attribute_mapping,
               'autonomous-system:number': as_number_attribute_mapping,
               'name': asn_description_attribute_mapping,
               'autonomous-system:name': asn_description_attribute_mapping,
               'value': asn_subnet_attribute_mapping,
               'ipv4-addr:value': asn_subnet_attribute_mapping,
               'ipv6-addr:value': asn_subnet_attribute_mapping}

domain_ip_mapping = {'domain-name': domain_attribute_mapping,
                     'domain-name:value': domain_attribute_mapping,
                     'ipv4-addr': ip_attribute_mapping,
                     'ipv6-addr': ip_attribute_mapping,
                     'domain-name:resolves_to_refs[*].value': ip_attribute_mapping}

email_mapping = {'date': email_date_attribute_mapping,
                 'email-message:date': email_date_attribute_mapping,
                 'to_refs': to_attribute_mapping,
                 'email-message:to_refs': to_attribute_mapping,
                 'cc_refs': cc_attribute_mapping,
                 'email-message:cc_refs': cc_attribute_mapping,
                 'subject': email_subject_attribute_mapping,
                 'email-message:subject': email_subject_attribute_mapping,
                 'X-Mailer': x_mailer_attribute_mapping,
                 'email-message:additional_header_fields.x_mailer': x_mailer_attribute_mapping,
                 'Reply-To': reply_to_attribute_mapping,
                 'email-message:additional_header_fields.reply_to': reply_to_attribute_mapping,
                 'from_ref': from_attribute_mapping,
                 'email-message:from_ref': from_attribute_mapping,
                 'body_multipart': body_multipart_mapping,
                 'email-message:body_multipart[*].body_raw_ref.name': body_multipart_mapping}

file_mapping = {'mime_type': mime_type_attribute_mapping,
                'file:mime_type': mime_type_attribute_mapping,
                'name': filename_attribute_mapping,
                'file:name': filename_attribute_mapping,
                'size': size_attribute_mapping,
                'file:size': size_attribute_mapping}

network_traffic_mapping = {'src_port': src_port_attribute_mapping,
                           'network-traffic:src_port': src_port_attribute_mapping,
                           'dst_port': dst_port_attribute_mapping,
                           'network-traffic:dst_port': dst_port_attribute_mapping,
                           'start': start_datetime_attribute_mapping,
                           'network-traffic:start': start_datetime_attribute_mapping,
                           'end': end_datetime_attribute_mapping,
                           'network-traffic:end': end_datetime_attribute_mapping,
                           'value': domain_attribute_mapping,
                           'domain-name:value': domain_attribute_mapping,
                           'network-traffic:dst_ref.value': ip_attribute_mapping,
                           'address_family': address_family_attribute_mapping,
                           "network-traffic:extensions.'socket-ext'.address_family": address_family_attribute_mapping,
                           'protocol_family': domain_family_attribute_mapping,
                           "network-traffic:extensions.'socket-ext'.protocol_family": domain_family_attribute_mapping,
                           'is_blocking': state_attribute_mapping,
                           "network-traffic:extensions.'socket-ext'.is_blocking": state_attribute_mapping,
                           'is_listening': state_attribute_mapping,
                           "network-traffic:extensions.'socket-ext'.is_listening": state_attribute_mapping}

network_traffic_extensions = {'socket-ext': 'network-socket'}

network_traffic_ip = ('ip-{}', 'ip-{}')
ip_port_ip = ('ip-dst', 'ip')
ip_port_types = {'domain-name': ('domain', 'domain'), 'ipv4-addr': ip_port_ip, 'ipv6-addr': ip_port_ip}
network_socket_types = {'domain-name': ('hostname', 'hostname-{}'), 'ipv4-addr': network_traffic_ip, 'ipv6-addr': network_traffic_ip}
network_traffic_references_mapping = {'with_extensions': network_socket_types, 'without_extensions': ip_port_types}

pe_mapping = {'pe_type': pe_type_mapping, 'number_of_sections': number_sections_mapping, 'imphash': imphash_mapping}

pe_section_mapping = {'name': section_name_mapping, 'size': size_attribute_mapping, 'entropy': entropy_mapping}

process_mapping = {'name': process_name_mapping,
                   'process:name': process_name_mapping,
                   'pid': pid_attribute_mapping,
                   'process:pid': pid_attribute_mapping,
                   'created': process_creation_time_mapping,
                   'process:created': process_creation_time_mapping,
                   'command_line': process_command_line_mapping,
                   'process:command_line': process_command_line_mapping,
                   'process:parent_ref': {'type': 'text', 'relation': 'parent-pid'},
                   'process:child_refs': {'type': 'text', 'relation': 'child-pid'}}

regkey_mapping = {'data': data_attribute_mapping,
                  'windows-registry-key:data': data_attribute_mapping,
                  'data_type': data_type_attribute_mapping,
                  'windows-registry-key:data_type': data_type_attribute_mapping,
                  'modified': modified_attribute_mapping,
                  'windows-registry-key:modified': modified_attribute_mapping,
                  'name': regkey_name_attribute_mapping,
                  'windows-registry-key:name': regkey_name_attribute_mapping,
                  'key': key_attribute_mapping,
                  'windows-registry-key:key': key_attribute_mapping,
                  'windows-registry-key:value': {'type': 'text', 'relation': 'hive'}
                  }

url_mapping = {'url': url_attribute_mapping,
               'url:value': url_attribute_mapping,
               'domain-name': domain_attribute_mapping,
               'domain-name:value': domain_attribute_mapping,
               'network-traffic': url_port_attribute_mapping,
               'network-traffic:dst_port': url_port_attribute_mapping
               }

x509_mapping = {'issuer': issuer_attribute_mapping,
                'x509-certificate:issuer': issuer_attribute_mapping,
                'serial_number': serial_number_attribute_mapping,
                'x509-certificate:serial_number': serial_number_attribute_mapping,
                'subject': x509_subject_attribute_mapping,
                'x509-certificate:subject': x509_subject_attribute_mapping,
                'subject_public_key_algorithm': x509_spka_attribute_mapping,
                'x509-certificate:subject_public_key_algorithm': x509_spka_attribute_mapping,
                'subject_public_key_exponent': x509_spke_attribute_mapping,
                'x509-certificate:subject_public_key_exponent': x509_spke_attribute_mapping,
                'subject_public_key_modulus': x509_spkm_attribute_mapping,
                'x509-certificate:subject_public_key_modulus': x509_spkm_attribute_mapping,
                'validity_not_before': x509_vnb_attribute_mapping,
                'x509-certificate:validity_not_before': x509_vnb_attribute_mapping,
                'validity_not_after': x509_vna_attribute_mapping,
                'x509-certificate:validity_not_after': x509_vna_attribute_mapping,
                'version': x509_version_attribute_mapping,
                'x509-certificate:version': x509_version_attribute_mapping,
                'SHA-1': x509_sha1_attribute_mapping,
                "x509-certificate:hashes.'sha1'": x509_sha1_attribute_mapping,
                'SHA-256': x509_sha256_attribute_mapping,
                "x509-certificate:hashes.'sha256'": x509_sha256_attribute_mapping,
                'MD5': x509_md5_attribute_mapping,
                "x509-certificate:hashes.'md5'": x509_md5_attribute_mapping,
                }

domain_pattern_mapping = {'value': {'type': 'domain'}}
ip_pattern_mapping = {'value': {'type': 'ip-dst'}}

external_pattern_mapping = {'domain-name': domain_pattern_mapping,
                            'email-addr': {'value': {'type': 'email-dst'}},
                            'file': file_mapping,
                            'ipv4-addr': ip_pattern_mapping,
                            'ipv6-addr': ip_pattern_mapping,
                            'url': {'value':{'type': 'url'}},
                            'x509-certificate': x509_mapping
                            }
