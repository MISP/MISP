_file_attribute_type = ('filename', 'filename')
_network_socket_addresses = ['local_address', 'remote_address']
_network_connection_addresses = ['source_socket_address', 'destination_socket_address']
_s_types = ['src', 'dst']

eventTypes = {"ArtifactObjectType": {"type": "attachment", "relation": "attachment"},
              "DomainNameObjectType": {"type": "domain", "relation": "domain"},
              "FileObjectType": _file_attribute_type,
              "HostnameObjectType": {"type": "hostname", "relation": "host"},
              "MutexObjectType": {"type": "mutex", "relation": "mutex"},
              "PDFFileObjectType": _file_attribute_type,
              "PortObjectType": {"type": "port", "relation": "port"},
              "URIObjectType": {"type": "url", "relation": "url"},
              "WindowsFileObjectType": _file_attribute_type,
              "WindowsExecutableFileObjectType": _file_attribute_type,
              "WindowsRegistryKeyObjectType": {"type": "regkey", "relation": ""}}

_AS_attribute = ('AS', 'asn')
_as_mapping = {'number': _AS_attribute, 'handle': _AS_attribute, 'name': ('text', 'description')}
_coa_mapping = {'type_': 'value', 'stage': 'value', 'impact': 'value.value',
                'description': 'value', 'objective': 'description.value',
                'cost': 'value.value', 'efficacy': 'value.value'}
_credential_authentication_mapping = {'authentication_type': ('text', 'value', 'type'),
                                       'authentication_data': ('text', 'value', 'password'),
                                       'structured_authentication_mechanism': ('text', 'description.value', 'format')}
_credential_custom_types = ("username", "origin", "notification")
_email_mapping = {'from_': ("email-src", "address_value.value", "from"),
                   'reply_to': ("email-reply-to", 'address_value.value', "reply-to"),
                   'subject': ("email-subject", 'value', "subject"),
                   'x_mailer': ("email-x-mailer", 'value', "x-mailer"),
                   'boundary': ("email-mime-boundary", 'value', "mime-boundary"),
                   'user_agent': ("text", 'value', "user-agent")}
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
