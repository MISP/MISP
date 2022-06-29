_file_attribute_type = ('filename', 'filename')
_network_socket_addresses = ['local_address', 'remote_address']
_network_connection_addresses = ['source_socket_address', 'destination_socket_address']
_s_types = ['src', 'dst']

attribute_types_mapping = {
    'AccountObjectType': 'handle_credential',
    'AddressObjectType': 'handle_address',
    'ArtifactObjectType': 'handle_attachment',
    'ASObjectType': 'handle_as',
    'CustomObjectType': 'handle_custom',
    'DNSRecordObjectType': 'handle_dns',
    'DomainNameObjectType': 'handle_domain_or_url',
    'EmailMessageObjectType': 'handle_email_attribute',
    'FileObjectType': 'handle_file',
    'HostnameObjectType': 'handle_hostname',
    'HTTPSessionObjectType': 'handle_http',
    'LinkObjectType': 'handle_link',
    'MutexObjectType': 'handle_mutex',
    'NetworkConnectionObjectType': 'handle_network_connection',
    'NetworkSocketObjectType': 'handle_network_socket',
    'PDFFileObjectType': 'handle_file',
    'PipeObjectType': 'handle_pipe',
    'PortObjectType': 'handle_port',
    'ProcessObjectType': 'handle_process',
    'SocketAddressObjectType': 'handle_socket_address',
    'SystemObjectType': 'handle_system',
    'UnixUserAccountObjectType': 'handle_unix_user',
    'URIObjectType': 'handle_domain_or_url',
    'UserAccountObjectType': 'handle_user',
    'WhoisObjectType': 'handle_whois',
    'WindowsFileObjectType': 'handle_file',
    'WindowsRegistryKeyObjectType': 'handle_regkey',
    'WindowsExecutableFileObjectType': 'handle_pe',
    'WindowsServiceObjectType': 'handle_windows_service',
    'WindowsUserAccountObjectType': 'handle_windows_user',
    'X509CertificateObjectType': 'handle_x509'
}

eventTypes = {
    "ArtifactObjectType": {"type": "attachment", "relation": "attachment"},
    "DomainNameObjectType": {"type": "domain", "relation": "domain"},
    "FileObjectType": _file_attribute_type,
    "HostnameObjectType": {"type": "hostname", "relation": "host"},
    "MutexObjectType": {"type": "mutex", "relation": "mutex"},
    "PDFFileObjectType": _file_attribute_type,
    "PortObjectType": {"type": "port", "relation": "port"},
    "URIObjectType": {"type": "url", "relation": "url"},
    "WindowsFileObjectType": _file_attribute_type,
    "WindowsExecutableFileObjectType": _file_attribute_type,
    "WindowsRegistryKeyObjectType": {"type": "regkey", "relation": ""}
}

_AS_attribute = ('AS', 'asn')
_as_mapping = {'number': _AS_attribute, 'handle': _AS_attribute, 'name': ('text', 'description')}
_attack_pattern_object_mapping = {'capec_id': 'id', 'title': 'name', 'description': 'summary'}
_attack_pattern_galaxy_mapping = {'description': 'description', 'title': 'value'}
_coa_mapping = {'type_': 'value', 'stage': 'value', 'impact': 'value.value',
                'description': 'value', 'objective': 'description.value',
                'cost': 'value.value', 'efficacy': 'value.value'}
_credential_authentication_mapping = {'authentication_type': ('text', 'value', 'type'),
                                       'authentication_data': ('text', 'value', 'password'),
                                       'structured_authentication_mechanism': ('text', 'description.value', 'format')}
_credential_custom_types = ("username", "origin", "notification")
_email_mapping = {'boundary': ("email-mime-boundary", 'value', "mime-boundary"),
                  'from_': ("email-src", "address_value.value", "from"),
                  'message_id': ("email-message-id", "value", "message-id"),
                  'reply_to': ("email-reply-to", 'address_value.value', "reply-to"),
                  'subject': ("email-subject", 'value', "subject"),
                  'user_agent': ("text", 'value', "user-agent"),
                  'x_mailer': ("email-x-mailer", 'value', "x-mailer")}
_file_mapping = {'file_path': ('text', 'file_path.value', 'path'),
                 'full_path': ('text', 'full_path.value', 'fullpath'),
                 'file_format': ('mime-type', 'file_format.value', 'mimetype'),
                 'byte_runs': ('pattern-in-file', 'byte_runs[0].byte_run_data', 'pattern-in-file'),
                 'size_in_bytes': ('size-in-bytes', 'size_in_bytes.value', 'size-in-bytes'),
                 'peak_entropy': ('float', 'peak_entropy.value', 'entropy')}
_network_socket_mapping = {'protocol': ('text', 'protocol.value', 'protocol'),
                            'address_family': ('text', 'address_family.value', 'address-family'),
                            'domain': ('text', 'domain.value', 'domain-family')}
_process_mapping = {'creation_time': ('datetime', 'creation-time'),
                     'start_time': ('datetime', 'start-time'),
                     'name': ('text', 'name'),
                     'pid': ('text', 'pid'),
                     'parent_pid': ('text', 'parent-pid')}
_regkey_mapping = {'hive': ('text', 'hive'), 'key': ('regkey', 'key')}
_regkey_value_mapping = {'data': ('text', 'data'), 'datatype': ('text', 'data-type'), 'name': ('text', 'name')}
_socket_mapping = {'ip_address': ('ip-{}', 'address_value', 'ip-{}'),
                    'port': ('port', 'port_value', '{}-port'),
                    'hostname': ('hostname', 'hostname_value', 'hostname-{}')}
_user_account_object_mapping = {'username': ('text', 'username'), 'full_name': ('text', 'display-name'),
                                'disabled': ('boolean', 'disabled'), 'creation_date': ('datetime', 'created'),
                                'last_login': ('datetime', 'last_login'), 'home_directory': ('text', 'home_dir'),
                                'script_path': ('text', 'shell')}
_vulnerability_object_mapping = {'cve_id': ('text', 'id'), 'description': ('text', 'summary'),
                                 'published_datetime': ('datetime', 'published')}
_weakness_object_mapping = {'cwe_id': 'id', 'description': 'description'}
_whois_registrant_mapping = {'email_address': ('whois-registrant-email', 'address_value.value', 'registrant-email'),
                              'name': ('whois-registrant-name', 'value', 'registrant-name'),
                              'phone_number': ('whois-registrant-phone', 'value', 'registrant-phone'),
                              'organization': ('whois-registrant-org', 'value', 'registrant-org')}
_whois_mapping = {'registrar_info': ('whois-registrar', 'value', 'whois-registrar'),
                   'ip_address': ('ip-src', 'address_value.value', 'ip-address'),
                   'domain_name': ('domain', 'value.value', 'domain')}
_x509_datetime_types = ('not_before', 'not_after')
_x509_pubkey_types = ('exponent', 'modulus')
_x509_certificate_types = ('version', 'serial_number', 'issuer', 'subject')

cybox_to_misp_object = {
    "Account": "credential",
    "AutonomousSystem": "asn",
    "EmailMessage": "email",
    "NetworkConnection": "network-connection",
    "NetworkSocket": "network-socket",
    "Observable": "obsevrable",
    "Process": "process",
    "UnixUserAccount": "user-account",
    "UserAccount": "user-account",
    "WindowsUserAccount": "user-account",
    "x509Certificate": "x509",
    "Whois": "whois"
}

test_mechanisms_mapping = {
    'yaraTM:YaraTestMechanismType': 'yara'
}

marking_mapping = {
    'AIS:AISMarkingStructure': 'parse_AIS_marking',
    'tlpMarking:TLPMarkingStructureType': 'parse_TLP_marking'
}

_AIS_marking_mapping = {'prefix': 'ais-marking:',
                        'proprietary': 'AISMarking="{}_Proprietary"',
                        'cisa_proprietary': 'CISA_Proprietary="{}"',
                        'ais_consent': ('consent', 'AISConsent="{}"'),
                        'tlp_marking': ('color', 'TLPMarking="{}"')}

threat_level_mapping = {'High': '1', 'Medium': '2', 'Low': '3', 'Undefined': '4'}
