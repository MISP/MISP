attributes_mapping = {
    'filename': '_parse_name',
    'ip-src': '_parse_value',
    'ip-dst': '_parse_value',
    'hostname': '_parse_value',
    'domain': '_parse_value',
    'domain|ip': '_parse_domain_ip_attribute',
    'email-src': '_parse_value',
    'email-dst': '_parse_value',
    'email-attachment': '_parse_name',
    'url': '_parse_value',
    'regkey': '_parse_regkey_attribute',
    'regkey|value': '_parse_regkey_value',
    'malware-sample': '_parse_malware_sample',
    'mutex': '_parse_name',
    'uri': '_parse_value',
    'port': '_parse_port',
    'ip-dst|port': '_parse_network_attribute',
    'ip-src|port': '_parse_network_attribute',
    'hostname|port': '_parse_network_attribute',
    'email-reply-to': '_parse_email_reply_to',
    'attachment': '_parse_attachment',
    'mac-address': '_parse_value',
    'AS': '_parse_number'
}

attributes_type_mapping = {
    'md5': '_parse_hash',
    'sha1': '_parse_hash',
    'sha256': '_parse_hash',
    'filename|md5': '_parse_filename_hash',
    'filename|sha1': '_parse_filename_hash',
    'filename|sha256': '_parse_filename_hash',
    'email-subject': '_parse_email_message',
    'email-body': '_parse_email_message',
    'authentihash': '_parse_hash',
    'ssdeep': '_parse_hash',
    'imphash': '_parse_hash',
    'pehash': '_parse_hash',
    'impfuzzy': '_parse_hash',
    'sha224': '_parse_hash',
    'sha384': '_parse_hash',
    'sha512': '_parse_hash',
    'sha512/224': '_parse_hash',
    'sha512/256': '_parse_hash',
    'tlsh': '_parse_hash',
    'cdhash': '_parse_hash',
    'filename|authentihash': '_parse_filename_hash',
    'filename|ssdeep': '_parse_filename_hash',
    'filename|imphash': '_parse_filename_hash',
    'filename|impfuzzy': '_parse_filename_hash',
    'filename|pehash': '_parse_filename_hash',
    'filename|sha224': '_parse_filename_hash',
    'filename|sha384': '_parse_filename_hash',
    'filename|sha512': '_parse_filename_hash',
    'filename|sha512/224': '_parse_filename_hash',
    'filename|sha512/256': '_parse_filename_hash',
    'filename|tlsh': '_parse_filename_hash',
    'x509-fingerprint-md5': '_parse_x509_attribute',
    'x509-fingerprint-sha1': '_parse_x509_attribute',
    'x509-fingerprint-sha256': '_parse_x509_attribute'
}

address_family_attribute_mapping = {'type': 'text','object_relation': 'address-family'}
as_number_attribute_mapping = {'type': 'AS', 'object_relation': 'asn'}
description_attribute_mapping = {'type': 'text', 'object_relation': 'description'}
asn_subnet_attribute_mapping = {'type': 'ip-src', 'object_relation': 'subnet-announced'}
cc_attribute_mapping = {'type': 'email-dst', 'object_relation': 'cc'}
credential_mapping = {'type': 'text', 'object_relation': 'password'}
data_attribute_mapping = {'type': 'text', 'object_relation': 'data'}
data_type_attribute_mapping = {'type': 'text', 'object_relation': 'data-type'}
domain_attribute_mapping = {'type': 'domain', 'object_relation': 'domain'}
domain_family_attribute_mapping = {'type': 'text', 'object_relation': 'domain-family'}
dst_port_attribute_mapping = {'type': 'port', 'object_relation': 'dst-port'}
email_attachment_attribute_mapping = {'type': 'email-attachment', 'object_relation': 'attachment'}
email_date_attribute_mapping = {'type': 'datetime', 'object_relation': 'send-date'}
email_subject_attribute_mapping = {'type': 'email-subject', 'object_relation': 'subject'}
encoding_attribute_mapping = {'type': 'text', 'object_relation': 'file-encoding'}
end_datetime_attribute_mapping = {'type': 'datetime', 'object_relation': 'last-seen'}
entropy_mapping = {'type': 'float', 'object_relation': 'entropy'}
filename_attribute_mapping = {'type': 'filename', 'object_relation': 'filename'}
from_attribute_mapping = {'type': 'email-src', 'object_relation': 'from'}
imphash_mapping = {'type': 'imphash', 'object_relation': 'imphash'}
id_attribute_mapping = {'type': 'text', 'object_relation': 'id'}
ip_attribute_mapping = {'type': 'ip-dst', 'object_relation': 'ip'}
issuer_attribute_mapping = {'type': 'text', 'object_relation': 'issuer'}
key_attribute_mapping = {'type': 'regkey', 'object_relation': 'key'}
malware_sample_attribute_mapping = {'type': 'malware-sample', 'object_relation': 'malware-sample'}
mime_type_attribute_mapping = {'type': 'mime-type', 'object_relation': 'mimetype'}
modified_attribute_mapping = {'type': 'datetime', 'object_relation': 'last-modified'}
name_attribute_mapping = {'type': 'text', 'object_relation': 'name'}
network_traffic_ip = {'type': 'ip-{}', 'object_relation': 'ip-{}'}
number_sections_mapping = {'type': 'counter', 'object_relation': 'number-sections'}
password_mapping = {'type': 'text', 'object_relation': 'password'}
pe_type_mapping = {'type': 'text', 'object_relation': 'type'}
pid_attribute_mapping = {'type': 'text', 'object_relation': 'pid'}
process_command_line_mapping = {'type': 'text', 'object_relation': 'command-line'}
process_creation_time_mapping = {'type': 'datetime', 'object_relation': 'creation-time'}
process_image_mapping = {'type': 'filename', 'object_relation': 'image'}
process_name_mapping = {'type': 'text', 'object_relation': 'name'}
regkey_name_attribute_mapping = {'type': 'text', 'object_relation': 'name'}
references_attribute_mapping = {'type': 'link', 'object_relation': 'references'}
reply_to_attribute_mapping = {'type': 'email-reply-to', 'object_relation': 'reply-to'}
screenshot_attribute_mapping = {'type': 'attachment', 'object_relation': 'screenshot'}
section_name_mapping = {'type': 'text', 'object_relation': 'name'}
serial_number_attribute_mapping = {'type': 'text', 'object_relation': 'serial-number'}
size_attribute_mapping = {'type': 'size-in-bytes', 'object_relation': 'size-in-bytes'}
src_port_attribute_mapping = {'type': 'port', 'object_relation': 'src-port'}
start_datetime_attribute_mapping = {'type': 'datetime', 'object_relation': 'first-seen'}
state_attribute_mapping = {'type': 'text', 'object_relation': 'state'}
summary_attribute_mapping = {'type': 'text', 'object_relation': 'summary'}
to_attribute_mapping = {'type': 'email-dst', 'object_relation': 'to'}
url_attribute_mapping = {'type': 'url', 'object_relation': 'url'}
url_port_attribute_mapping = {'type': 'port', 'object_relation': 'port'}
user_id_mapping = {'type': 'text', 'object_relation': 'username'}
username_mapping = {'type': 'text', 'object_relation': 'username'}
x_mailer_attribute_mapping = {'type': 'email-x-mailer', 'object_relation': 'x-mailer'}
x509_md5_attribute_mapping = {'type': 'x509-fingerprint-md5', 'object_relation': 'x509-fingerprint-md5'}
x509_sha1_attribute_mapping = {'type': 'x509-fingerprint-sha1', 'object_relation': 'x509-fingerprint-sha1'}
x509_sha256_attribute_mapping = {'type': 'x509-fingerprint-sha256', 'object_relation': 'x509-fingerprint-sha256'}
x509_spka_attribute_mapping = {'type': 'text', 'object_relation': 'pubkey-info-algorithm'} # x509 subject public key algorithm
x509_spke_attribute_mapping = {'type': 'text', 'object_relation': 'pubkey-info-exponent'} # x509 subject public key exponent
x509_spkm_attribute_mapping = {'type': 'text', 'object_relation': 'pubkey-info-modulus'} # x509 subject public key modulus
x509_subject_attribute_mapping = {'type': 'text', 'object_relation': 'subject'}
x509_version_attribute_mapping = {'type': 'text', 'object_relation': 'version'}
x509_vna_attribute_mapping = {'type': 'datetime', 'object_relation': 'validity-not-after'} # x509 validity not after
x509_vnb_attribute_mapping = {'type': 'datetime', 'object_relation': 'validity-not-before'} # x509 validity not before

artifact_mapping = {'artifact:mime_type': mime_type_attribute_mapping,
                    'file:content_ref.mime_type': mime_type_attribute_mapping}

asn_mapping = {'number': as_number_attribute_mapping,
               'autonomous-system:number': as_number_attribute_mapping,
               'name': description_attribute_mapping,
               'autonomous-system:name': description_attribute_mapping,
               'ipv4-addr': asn_subnet_attribute_mapping,
               'ipv6-addr': asn_subnet_attribute_mapping,
               'ipv4-addr:value': asn_subnet_attribute_mapping,
               'ipv6-addr:value': asn_subnet_attribute_mapping}

attack_pattern_mapping = {'name': name_attribute_mapping,
                          'description': summary_attribute_mapping}

attack_pattern_references_mapping = {'mitre-attack': references_attribute_mapping,
                                     'capec': id_attribute_mapping}

course_of_action_mapping = {'description': description_attribute_mapping,
                            'name': name_attribute_mapping}

credential_mapping = {'credential': credential_mapping,
                      'user-account:credential': credential_mapping,
                      'user_id': user_id_mapping,
                      'user-account:user_id': user_id_mapping}

domain_ip_mapping = {'domain-name': domain_attribute_mapping,
                     'domain-name:value': domain_attribute_mapping,
                     'ipv4-addr': ip_attribute_mapping,
                     'ipv6-addr': ip_attribute_mapping,
                     'domain-name:resolves_to_refs[*].value': ip_attribute_mapping,
                     'network-traffic:dst_port': dst_port_attribute_mapping,
                     'network-traffic:src_port': src_port_attribute_mapping}

email_mapping = {'date': email_date_attribute_mapping,
                 'email-message:date': email_date_attribute_mapping,
                 'email-message:to_refs': to_attribute_mapping,
                 'email-message:cc_refs': cc_attribute_mapping,
                 'subject': email_subject_attribute_mapping,
                 'email-message:subject': email_subject_attribute_mapping,
                 'X-Mailer': x_mailer_attribute_mapping,
                 'email-message:additional_header_fields.x_mailer': x_mailer_attribute_mapping,
                 'Reply-To': reply_to_attribute_mapping,
                 'email-message:additional_header_fields.reply_to': reply_to_attribute_mapping,
                 'email-message:from_ref': from_attribute_mapping,
                 'email-addr:value': to_attribute_mapping}

email_references_mapping = {'attachment': email_attachment_attribute_mapping,
                            'cc_refs': cc_attribute_mapping,
                            'from_ref': from_attribute_mapping,
                            'screenshot': screenshot_attribute_mapping,
                            'to_refs': to_attribute_mapping}

file_mapping = {'mime_type': mime_type_attribute_mapping,
                'file:mime_type': mime_type_attribute_mapping,
                'name': filename_attribute_mapping,
                'file:name': filename_attribute_mapping,
                'name_enc': encoding_attribute_mapping,
                'file:name_enc': encoding_attribute_mapping,
                'file:parent_directory_ref.path': {'type': 'text', 'object_relation': 'path'},
                'size': size_attribute_mapping,
                'file:size': size_attribute_mapping}

network_traffic_mapping = {'dst_port':dst_port_attribute_mapping,
                           'src_port': src_port_attribute_mapping,
                           'network-traffic:dst_port': dst_port_attribute_mapping,
                           'network-traffic:src_port': src_port_attribute_mapping}

ip_port_mapping = {'value': domain_attribute_mapping,
                   'domain-name:value': domain_attribute_mapping,
                   'network-traffic:dst_ref.value': {'type': 'ip-dst', 'object_relation': 'ip-dst'},
                   'network-traffic:src_ref.value': {'type': 'ip-src', 'object_relation': 'ip-src'}}
ip_port_mapping.update(network_traffic_mapping)

ip_port_references_mapping = {'domain-name': domain_attribute_mapping,
                              'ipv4-addr': network_traffic_ip,
                              'ipv6-addr': network_traffic_ip}

network_socket_extension_mapping = {'address_family': address_family_attribute_mapping,
                                    "network-traffic:extensions.'socket-ext'.address_family": address_family_attribute_mapping,
                                    'protocol_family': domain_family_attribute_mapping,
                                    "network-traffic:extensions.'socket-ext'.protocol_family": domain_family_attribute_mapping,
                                    'is_blocking': state_attribute_mapping,
                                    "network-traffic:extensions.'socket-ext'.is_blocking": state_attribute_mapping,
                                    'is_listening': state_attribute_mapping,
                                    "network-traffic:extensions.'socket-ext'.is_listening": state_attribute_mapping}

network_traffic_references_mapping = {'domain-name': {'type': 'hostname', 'object_relation': 'hostname-{}'},
                                      'ipv4-addr': network_traffic_ip,
                                      'ipv6-addr': network_traffic_ip}

pe_mapping = {'pe_type': pe_type_mapping, 'number_of_sections': number_sections_mapping, 'imphash': imphash_mapping}

pe_section_mapping = {'name': section_name_mapping, 'size': size_attribute_mapping, 'entropy': entropy_mapping}

hash_types = ('MD5', 'SHA-1', 'SHA-256', 'SHA-224', 'SHA-384', 'SHA-512', 'ssdeep', 'tlsh')
for hash_type in hash_types:
    misp_hash_type = hash_type.replace('-', '').lower()
    attribute = {'type': misp_hash_type, 'object_relation': misp_hash_type}
    file_mapping[hash_type] = attribute
    for object_type in ('artifact:', 'file:content_ref.'):
        artifact_mapping.update({f"{object_type}hashes.'{feature}'": attribute for feature in (hash_type, misp_hash_type)})
    file_mapping.update({f"file:hashes.'{feature}'": attribute for feature in (hash_type, misp_hash_type)})
    pe_section_mapping[hash_type] = attribute
    pe_section_mapping[misp_hash_type] = attribute
artifact_mapping.update(file_mapping)

process_mapping = {'name': process_name_mapping,
                   'process:name': process_name_mapping,
                   'pid': pid_attribute_mapping,
                   'process:pid': pid_attribute_mapping,
                   'created': process_creation_time_mapping,
                   'process:created': process_creation_time_mapping,
                   'command_line': process_command_line_mapping,
                   'process:command_line': process_command_line_mapping,
                   'process:parent_ref.pid': {'type': 'text', 'object_relation': 'parent-pid'},
                   'process:child_refs[*].pid': {'type': 'text', 'object_relation': 'child-pid'},
                   'process:binary_ref.name': process_image_mapping}

child_process_reference_mapping = {'pid': {'type': 'text', 'object_relation': 'child-pid'}}

parent_process_reference_mapping = {'command_line': {'type': 'text', 'object_relation': 'parent-command-line'},
                                    'pid': {'type': 'text', 'object_relation': 'parent-pid'},
                                    'process-name': {'type': 'text', 'object_relation': 'parent-process-name'}}

regkey_mapping = {'data': data_attribute_mapping,
                  'windows-registry-key:values.data': data_attribute_mapping,
                  'data_type': data_type_attribute_mapping,
                  'windows-registry-key:values.data_type': data_type_attribute_mapping,
                  'modified': modified_attribute_mapping,
                  'windows-registry-key:modified': modified_attribute_mapping,
                  'name': regkey_name_attribute_mapping,
                  'windows-registry-key:values.name': regkey_name_attribute_mapping,
                  'key': key_attribute_mapping,
                  'windows-registry-key:key': key_attribute_mapping,
                  'windows-registry-key:value': {'type': 'text', 'object_relation': 'hive'}
                  }

url_mapping = {'url': url_attribute_mapping,
               'url:value': url_attribute_mapping,
               'domain-name': domain_attribute_mapping,
               'domain-name:value': domain_attribute_mapping,
               'network-traffic': url_port_attribute_mapping,
               'network-traffic:dst_port': url_port_attribute_mapping
               }

user_account_mapping = {'account_created': {'type': 'datetime', 'object_relation': 'created'},
                        'account_expires': {'type': 'datetime', 'object_relation': 'expires'},
                        'account_first_login': {'type': 'datetime', 'object_relation': 'first_login'},
                        'account_last_login': {'type': 'datetime', 'object_relation': 'last_login'},
                        'account_login': {'type': 'text', 'object_relation': 'username'},
                        'account_type': {'type': 'text', 'object_relation': 'account-type'},
                        'can_escalate_privs': {'type': 'boolean', 'object_relation': 'can_escalate_privs'},
                        'credential': {'type': 'text', 'object_relation': 'password'},
                        'credential_last_changed': {'type': 'datetime', 'object_relation': 'password_last_changed'},
                        'display_name': {'type': 'text', 'object_relation': 'display-name'},
                        'gid': {'type': 'text', 'object_relation': 'group-id'},
                        'home_dir': {'type': 'text', 'object_relation': 'home_dir'},
                        'is_disabled': {'type': 'boolean', 'object_relation': 'disabled'},
                        'is_privileged': {'type': 'boolean', 'object_relation': 'privileged'},
                        'is_service_account': {'type': 'boolean', 'object_relation': 'is_service_account'},
                        'shell': {'type': 'text', 'object_relation': 'shell'},
                        'user_id': {'type': 'text', 'object_relation': 'user-id'}}

vulnerability_mapping = {'name': id_attribute_mapping,
                         'description': summary_attribute_mapping}

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

attachment_types = ('file:content_ref.name', 'file:content_ref.payload_bin',
                    'artifact:x_misp_text_name', 'artifact:payload_bin',
                    "file:hashes.'MD5'", "file:content_ref.hashes.'MD5'",
                    'file:name')

connection_protocols = {"IP": "3", "ICMP": "3", "ARP": "3",
                        "TCP": "4", "UDP": "4",
                        "HTTP": "7", "HTTPS": "7", "FTP": "7"}
