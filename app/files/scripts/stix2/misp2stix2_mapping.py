misp_hash_types = ("authentihash", "ssdeep", "imphash", "md5", "sha1", "sha224",
                   "sha256", "sha384", "sha512", "sha512/224","sha512/256","tlsh")
attack_pattern_galaxies_list = ('mitre-attack-pattern', 'mitre-enterprise-attack-attack-pattern',
                                'mitre-mobile-attack-attack-pattern', 'mitre-pre-attack-attack-pattern')
course_of_action_galaxies_list = ('mitre-course-of-action', 'mitre-enterprise-attack-course-of-action',
                                  'mitre-mobile-attack-course-of-action')
intrusion_set_galaxies_list = ('mitre-enterprise-attack-intrusion-set', 'mitre-mobile-attack-intrusion-set',
                               'mitre-pre-attack-intrusion-set', 'mitre-intrusion-set')
malware_galaxies_list = ('android', 'banker', 'stealer', 'backdoor', 'ransomware', 'mitre-malware',
                         'mitre-enterprise-attack-malware', 'mitre-mobile-attack-malware')
threat_actor_galaxies_list = ('threat-actor', 'microsoft-activity-group')
tool_galaxies_list = ('botnet', 'rat', 'exploit-kit', 'tds', 'tool', 'mitre-tool',
                      'mitre-enterprise-attack-tool', 'mitre-mobile-attack-tool')

galaxies_mapping = {'branded-vulnerability': ['vulnerability', 'add_vulnerability_from_galaxy']}
galaxies_mapping.update(dict.fromkeys(attack_pattern_galaxies_list, ['attack-pattern', 'add_attack_pattern']))
galaxies_mapping.update(dict.fromkeys(course_of_action_galaxies_list, ['course-of-action', 'add_course_of_action']))
galaxies_mapping.update(dict.fromkeys(intrusion_set_galaxies_list, ['intrusion-set', 'add_intrusion_set']))
galaxies_mapping.update(dict.fromkeys(malware_galaxies_list, ['malware', 'add_malware']))
galaxies_mapping.update(dict.fromkeys(threat_actor_galaxies_list, ['threat-actor', 'add_threat_actor']))
galaxies_mapping.update(dict.fromkeys(tool_galaxies_list, ['tool', 'add_tool']))

mispTypesMapping = {
    'md5': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha1': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha256': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'filename': {'observable': '_get_file_observable', 'pattern': '_get_file_pattern'},
    'filename|md5': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha1': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha256': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'ip-src': {'observable': '_get_ip_observable', 'pattern': '_get_ip_pattern'},
    'ip-dst': {'observable': '_get_ip_observable', 'pattern': '_get_ip_pattern'},
    'hostname': {'observable': '_get_domain_observable', 'pattern': '_get_domain_pattern'},
    'domain': {'observable': '_get_domain_observable', 'pattern': '_get_domain_pattern'},
    'domain|ip': {'observable': '_get_domain_ip_observable', 'pattern': '_get_domain_ip_pattern'},
    'email-src': {'observable': '_get_email_address_observable', 'pattern': '_get_email_address_pattern'},
    'email-dst': {'observable': '_get_email_address_observable', 'pattern': '_get_email_address_pattern'},
    'email-subject': {'observable': '_get_email_message_observable', 'pattern': '_get_email_message_pattern'},
    'email-body': {'observable': '_get_email_message_observable', 'pattern': '_get_email_message_pattern'},
    'email-attachment': {'observable': '_get_email_attachment_observable', 'pattern': '_get_email_attachment_observable'},
    'url': {'observable': '_get_url_observable', 'pattern': '_get_url_pattern'},
    'regkey': {'observable': '_get_regkey_observable', 'pattern': '_get_regkey_pattern'},
    'regkey|value': {'observable': '_get_regkey_value_observable', 'pattern': '_get_regkey_value_pattern'},
    'malware-sample': {'observable': '_get_malware_sample_observable', 'pattern': '_get_malware_sample_pattern'},
    'mutex': {'observable': '_get_mutex_observable', 'pattern': '_get_mutex_pattern'},
    'uri': {'observable': '_get_url_observable', 'pattern': '_get_url_pattern'},
    'authentihash': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'ssdeep': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'imphash': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'pehash': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'impfuzzy': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha224': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha384': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha512': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha512/224': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'sha512/256': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'tlsh': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'cdhash': {'observable': '_get_hash_observable', 'pattern': '_get_hash_pattern'},
    'filename|authentihash': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|ssdeep': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|imphash': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|impfuzzy': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|pehash': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha224': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha384': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha512': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha512/224': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|sha512/256': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'filename|tlsh': {'observable': '_get_file_hash_observable', 'pattern': '_get_file_hash_pattern'},
    'x509-fingerprint-md5': {'observable': '_get_x509_observable', 'pattern': '_get_x509_pattern'},
    'x509-fingerprint-sha1': {'observable': '_get_x509_observable', 'pattern': '_get_x509_pattern'},
    'x509-fingerprint-sha256': {'observable': '_get_x509_observable', 'pattern': '_get_x509_pattern'},
    'port': {'observable': '_get_port_observable', 'pattern': '_get_port_pattern'},
    'ip-dst|port': {'observable': '_get_ip_port_observable', 'pattern': '_get_ip_port_pattern'},
    'ip-src|port': {'observable': '_get_ip_port_observable', 'pattern': '_get_ip_port_pattern'},
    'hostname|port': {'observable': '_get_hostname_port_observable', 'pattern': '_get_hostname_port_pattern'},
    'email-reply-to': {'observable': '_get_reply_to_observable', 'pattern': '_get_reply_to_pattern'},
    'attachment': {'observable': '_get_attachment_observable', 'pattern': '_get_attachment_pattern'},
    'mac-address': {'observable': '_get_mac_address_observable', 'pattern': '_get_mac_address_pattern'},
    'AS': {'observable': '_get_as_observable', 'pattern': '_get_as_pattern'}
    #'email-dst-display-name': {'observable': {'0': {'type': 'email-addr', 'display_name': ''}},
    #                           'pattern': 'email-addr:display_name = \'{0}\''},
    #'email-src-display-name': {'observable': {'0': {'type': 'email-addr', 'display_name': ''}},
    #                           'pattern': 'email-addr:display_name = \'{0}\''}
}

objects_mapping = {
    'asn': {'observable': 'resolve_asn_observable',
            'pattern': 'resolve_asn_pattern'},
    'credential': {'observable': 'resolve_credential_observable',
                   'pattern': 'resolve_credential_pattern'},
    'domain-ip': {'observable': 'resolve_domain_ip_observable',
                  'pattern': 'resolve_domain_ip_pattern'},
    'email': {'observable': 'resolve_email_object_observable',
              'pattern': 'resolve_email_object_pattern'},
    'file': {'observable': 'resolve_file_observable',
             'pattern': 'resolve_file_pattern'},
    'ip-port': {'observable': 'resolve_ip_port_observable',
                'pattern': 'resolve_ip_port_pattern'},
    'network-connection': {'observable': 'resolve_network_connection_observable',
                           'pattern': 'resolve_network_connection_pattern'},
    'network-socket': {'observable': 'resolve_network_socket_observable',
                       'pattern': 'resolve_network_socket_pattern'},
    'process': {'observable': 'resolve_process_observable',
                'pattern': 'resolve_process_pattern'},
    'registry-key': {'observable': 'resolve_regkey_observable',
                     'pattern': 'resolve_regkey_pattern'},
    'stix2-pattern': {'pattern': 'resolve_stix2_pattern'},
    'url': {'observable': 'resolve_url_observable',
            'pattern': 'resolve_url_pattern'},
    'user-account': {'observable': 'resolve_user_account_observable',
                     'pattern': 'resolve_user_account_pattern'},
    'x509': {'observable': 'resolve_x509_observable',
             'pattern': 'resolve_x509_pattern'}
}

network_traffic_pattern = "network-traffic:{0} = '{1}'"
network_traffic_src_ref = "src_{0}.type = '{1}' AND network-traffic:src_{0}.value"
network_traffic_dst_ref = "dst_{0}.type = '{1}' AND network-traffic:dst_{0}.value"
network_traffic_reference_mapping = {'': ''}

objectsMapping = {'asn': {'to_call': 'handle_usual_object_name',
                          'observable': {'type': 'autonomous-system'},
                          'pattern': "autonomous-system:{0} = '{1}'"},
                  'attack-pattern': {'to_call': 'add_attack_pattern_object'},
                  'course-of-action': {'to_call': 'add_course_of_action_from_object'},
                  'credential': {'to_call': 'handle_usual_object_name',
                                 'observable': {'type': 'user-account'},
                                 'pattern': "user-account:{0} = '{1}'"},
                  'domain-ip': {'to_call': 'handle_usual_object_name',
                                'pattern': "domain-name:{0} = '{1}'"},
                  'email': {'to_call': 'handle_usual_object_name',
                            'observable': {'0': {'type': 'email-message'}},
                            'pattern': "email-{0}:{1} = '{2}'"},
                  'file': {'to_call': 'handle_usual_object_name',
                           'observable': {'0': {'type': 'file', 'hashes': {}}},
                           'pattern': "file:{0} = '{1}'"},
                  'ip-port': {'to_call': 'handle_usual_object_name',
                              'pattern': network_traffic_pattern},
                  'network-connection': {'to_call': 'handle_usual_object_name',
                                         'pattern': network_traffic_pattern},
                  'network-socket': {'to_call': 'handle_usual_object_name',
                                     'pattern': network_traffic_pattern},
                  'pe': {'to_call': 'populate_objects_to_parse'},
                  'pe-section': {'to_call': 'populate_objects_to_parse'},
                  'process': {'to_call': 'handle_usual_object_name',
                              'pattern': "process:{0} = '{1}'"},
                  'registry-key': {'to_call': 'handle_usual_object_name',
                                   'observable': {'0': {'type': 'windows-registry-key'}},
                                   'pattern': "windows-registry-key:{0} = '{1}'"},
                  'stix2-pattern': {'to_call': 'handle_usual_object_name'},
                  'url': {'to_call': 'handle_usual_object_name',
                          'observable': {'0': {'type': 'url'}},
                          'pattern': "url:{0} = '{1}'"},
                  'user-account': {'to_call': 'handle_usual_object_name',
                                   'pattern': "user-account:{0} = '{1}'"},
                  'vulnerability': {'to_call': 'add_object_vulnerability'},
                  'x509': {'to_call': 'handle_usual_object_name',
                           'pattern': "x509-certificate:{0} = '{1}'"}
}

asnObjectMapping = {'asn': 'number', 'description': 'name', 'subnet-announced': 'value'}

attackPatternObjectMapping = {'name': 'name', 'summary': 'description'}

attack_pattern_reference_mapping = {'id': ('capec', 'external_id'),
                                    'references': ('mitre-attack', 'url')}

credentialObjectMapping = {'password': 'credential', 'username': 'user_id'}

domainIpObjectMapping = {'ip-dst': 'resolves_to_refs[*].value', 'domain': 'value'}

email_attachment = {'email_type': 'message', 'stix_type': 'body_multipart[{}].body_raw_ref.name'}
emailObjectMapping = {'email-body': {'email_type': 'message', 'stix_type': 'body'},
                      'subject': {'email_type': 'message', 'stix_type': 'subject'},
                      'to': {'email_type': 'message', 'stix_type': 'to_refs'},
                      'cc': {'email_type': 'message', 'stix_type': 'cc_refs'},
                      'to-display-name': {'email_type': 'addr', 'stix_type': 'display_name'},
                      'from': {'email_type': 'message', 'stix_type': 'from_ref'},
                      'from-display-name': {'email_type': 'addr', 'stix_type': 'display_name'},
                      'reply-to': {'email_type': 'message', 'stix_type': 'additional_header_fields.reply_to'},
                      'attachment': email_attachment, 'screenshot': email_attachment,
                      'send-date': {'email_type': 'message', 'stix_type': 'date'},
                      'x-mailer': {'email_type': 'message', 'stix_type': 'additional_header_fields.x_mailer'}}

fileMapping = {'size-in-bytes': 'size', 'mime-type': 'mime_type', 'file-encoding': 'name_enc'}
hash_types = ('MD5', 'SHA-1', 'SHA-256', 'SHA-224', 'SHA-384', 'SHA-512', 'ssdeep', 'tlsh')
fileMapping.update({hash_type.replace('-', '').lower(): hash_type for hash_type in hash_types})
hash_types = tuple(hash_type.replace('-', '').lower() for hash_type in hash_types)

ipPortObjectMapping = {'ip': network_traffic_dst_ref,
                       'src-port': 'src_port', 'dst-port': 'dst_port',
                       'first-seen': 'start', 'last-seen': 'end',
                       'domain': 'value'}

networkTrafficMapping = {'address-family': 'address_family', 'domain-family': 'protocol_family',
                        'protocol': 'protocols', 'src-port': 'src_port', 'dst-port': 'dst_port',
                        'ip-src': network_traffic_src_ref, 'ip-dst': network_traffic_dst_ref,
                        'hostname-src': network_traffic_src_ref, 'hostname-dst': network_traffic_dst_ref}

peMapping = {'type': 'pe_type', 'number-sections': 'number_of_sections', 'imphash': 'imphash'}

peSectionMapping = {'name': 'name', 'size-in-bytes': 'size', 'entropy': 'entropy'}

processMapping = {'pid': 'pid', 'child-pid': 'child_refs[*].pid',
                  'name': 'name', 'parent-pid': 'parent_ref.pid',
                  'creation-time': 'created', 'image': 'binary_ref.name'}

regkeyMapping = {'data-type': 'data_type', 'data': 'data', 'name': 'name',
                 'last-modified': 'modified', 'key': 'key'}

urlMapping = {'url': 'value', 'domain': 'value', 'port': 'dst_port'}

userAccountMapping = {'account-type': 'account_type', 'can_escalate_privs': 'can_escalate_privs',
                      'created': 'account_created', 'disabled': 'is_disabled', 'display-name': 'display_name',
                      'expires': 'account_expires', 'first_login': 'account_first_login',
                      'is_service_account': 'is_service_account', 'last_login': 'account_last_login',
                      'password': 'credential', 'password_last_changed': 'credential_last_changed',
                      'privileged': 'is_privileged', 'username': 'account_login', 'user-id': 'user_id'}

unixAccountExtensionMapping = {'group': 'groups', 'group-id': 'gid', 'home_dir': 'home_dir', 'shell': 'shell'}

vulnerabilityMapping = {'id': 'name', 'summary': 'description'}

x509mapping = {'pubkey-info-algorithm': 'subject_public_key_algorithm', 'subject': 'subject',
               'pubkey-info-exponent': 'subject_public_key_exponent', 'issuer': 'issuer',
               'pubkey-info-modulus': 'subject_public_key_modulus', 'serial-number': 'serial_number',
               'validity-not-before': 'validity_not_before', 'validity-not-after': 'validity_not_after',
               'version': 'version',}

defineProtocols = {'80': 'http', '443': 'https'}

tlp_markings = {'tlp:white': 'TLP_WHITE', 'tlp:green': 'TLP_GREEN',
                'tlp:amber': 'TLP_AMBER', 'tlp:red': 'TLP_RED'}

relationshipsSpecifications = {'attack-pattern': {'vulnerability': 'targets', 'identity': 'targets',
                                                 'malware': 'uses', 'tool': 'uses'},
                              'campaign': {'intrusion-set': 'attributed-to', 'threat-actor': 'attributed-to',
                                           'identity': 'targets', 'vulnerability': 'targets',
                                           'attack-pattern': 'uses', 'malware': 'uses',
                                           'tool': 'uses'},
                              'course-of-action':{'attack-pattern': 'mitigates', 'malware': 'mitigates',
                                                  'tool': 'mitigates', 'vulnerability': 'mitigates'},
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
galaxy_types = ('attack-pattern', 'campaign', 'intrusion-set', 'malware', 'threat-actor', 'tool')
relationshipsSpecifications['indicator'] = {feature: 'indicates' for feature in galaxy_types}
relationshipsSpecifications['observed-data'] = {feature: 'observed-with' for feature in galaxy_types}
