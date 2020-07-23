# mappings
status_mapping = {'0': 'New', '1': 'Open', '2': 'Closed'}
threat_level_mapping = {'1': 'High', '2': 'Medium', '3': 'Low', '4': 'Undefined'}
TLP_order = {'RED': 4, 'AMBER': 3, 'AMBER NATO ALLIANCE': 3, 'GREEN': 2, 'WHITE': 1}
confidence_mapping = {False: 'None', True: 'High'}

not_implemented_attributes = ('yara', 'snort', 'pattern-in-traffic', 'pattern-in-memory')

non_indicator_attributes = (
    'text',
    'comment',
    'other',
    'link',
    'target-user',
    'target-email',
    'target-machine',
    'target-org',
    'target-location',
    'target-external',
    'vulnerability'
)

hash_type_attributes = {
    "single": (
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512/224",
        "sha512/256",
        "ssdeep",
        "imphash",
        "authentihash",
        "pehash",
        "tlsh",
        "cdhash"
    ),
    "composite": (
        "filename|md5",
        "filename|sha1",
        "filename|sha224",
        "filename|sha256",
        "filename|sha384",
        "filename|sha512",
        "filename|sha512/224",
        "filename|sha512/256",
        "filename|authentihash",
        "filename|ssdeep",
        "filename|tlsh",
        "filename|imphash",
        "filename|pehash"
    )
}

# mapping for the attributes that can go through the simpleobservable script
misp_cybox_name = {
    "domain": "DomainName",
    "hostname": "Hostname",
    "url": "URI",
    "AS": "AutonomousSystem",
    "mutex": "Mutex",
    "named pipe": "Pipe",
    "link": "URI",
    "network-connection": "NetworkConnection",
    "windows-service-name": "WinService"
}
cybox_name_attribute = {
    "DomainName": "value",
    "Hostname": "hostname_value",
    "URI": "value",
    "AutonomousSystem": "number",
    "Pipe": "name",
    "Mutex": "name",
    "WinService": "name"
}
misp_indicator_type = {
    "email-attachment": "Malicious E-mail",
    "filename": "File Hash Watchlist",
    "mutex": "Host Characteristics",
    "named pipe": "Host Characteristics",
    "url": "URL Watchlist"
}
misp_indicator_type.update(dict.fromkeys(list(hash_type_attributes["single"]), "File Hash Watchlist"))
misp_indicator_type.update(dict.fromkeys(list(hash_type_attributes["composite"]), "File Hash Watchlist"))
misp_indicator_type.update(
    dict.fromkeys(
        [
            "email-src",
            "email-dst",
            "email-subject",
            "email-reply-to",
            "email-attachment"
        ],
        "Malicious E-mail"
    )
)
misp_indicator_type.update(
    dict.fromkeys(
        [
            "AS",
            "ip-src",
            "ip-dst",
            "ip-src|port",
            "ip-dst|port"
        ],
        "IP Watchlist"
    )
)
misp_indicator_type.update(
    dict.fromkeys(
        [
            "domain",
            "domain|ip",
            "hostname"
        ],
        "Domain Watchlist"
    )
)
misp_indicator_type.update(
    dict.fromkeys(
        [
            "regkey",
            "regkey|value"
        ],
        "Host Characteristics"
    )
)
cybox_validation = {"AutonomousSystem": "isInt"}

## ATTRIBUTES MAPPING
simple_type_to_method = {
    'attachment': 'resolve_attachment',
    'domain|ip': 'generate_domain_ip_observable',
    'email-attachment': 'generate_email_attachment_observable',
    'filename': 'resolve_file_observable',
    'mac-address': 'resolve_system_observable',
    'malware-sample': 'resolve_malware_sample',
    'named pipe': 'generate_pipe_observable',
    'port': 'generate_port_observable',
}
simple_type_to_method.update(
    dict.fromkeys(
        list(hash_type_attributes["single"]),
        'resolve_file_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        list(hash_type_attributes["composite"]),
        'resolve_file_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "ip-src",
            "ip-dst"
        ],
        'generate_ip_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "ip-src|port",
            "ip-dst|port",
            "hostname|port"
        ],
        'generate_socket_address_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "regkey",
            "regkey|value"
        ],
        'generate_regkey_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "hostname",
            "domain",
            "url",
            "AS",
            "mutex",
            "named pipe",
            "link",
            "windows-service-name"
        ],
        'generate_simple_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "email-src",
            "email-dst",
            "email-subject",
            "email-reply-to"
        ],
        'resolve_email_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "http-method",
            "user-agent"
        ],
        'resolve_http_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            "pattern-in-file",
            "pattern-in-traffic",
            "pattern-in-memory"
        ],
        'resolve_pattern_observable'
    )
)
simple_type_to_method.update(
    dict.fromkeys(
        [
            'x509-fingerprint-md5',
            'x509-fingerprint-sha1',
            'x509-fingerprint-sha256'
        ],
        'parse_x509_object'
    )
)

## OBJECTS MAPPING
ttp_names = {
    'attack-pattern': 'parse_attack_pattern',
    'course-of-action': 'parse_course_of_action',
    'vulnerability': 'parse_vulnerability',
    'weakness': 'parse_weakness'
}
objects_mapping = {
    "asn": 'parse_asn_object',
    "credential": 'parse_credential_object',
    "domain-ip": 'parse_domain_ip_object',
    "email": 'parse_email_object',
    "file": 'parse_file_object',
    "ip-port": 'parse_ip_port_object',
    "network-connection": 'parse_network_connection_object',
    "network-socket": 'parse_network_socket_object',
    "pe": 'store_pe',
    "pe-section": 'store_pe',
    "process": 'parse_process_object',
    "registry-key": 'parse_regkey_object',
    "url": 'parse_url_object',
    "user-account": 'parse_user_account_object',
    "whois": 'parse_whois',
    "x509": 'parse_x509_object'
}

## GALAXIES MAPPING
galaxy_types_mapping = {'branded-vulnerability': 'parse_vulnerability_galaxy'}
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'mitre-attack-pattern',
            'mitre-enterprise-attack-attack-pattern',
            'mitre-mobile-attack-attack-pattern',
            'mitre-pre-attack-attack-pattern'
        ],
        'parse_attack_pattern_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'mitre-course-of-action',
            'mitre-enterprise-attack-course-of-action',
            'mitre-mobile-attack-course-of-action'
        ],
        'parse_course_of_action_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'android',
            'banker',
            'stealer',
            'backdoor',
            'ransomware',
            'mitre-malware',
            'malpedia',
            'mitre-enterprise-attack-malware',
            'mitre-mobile-attack-malware'
        ],
        'parse_malware_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'threat-actor',
            'microsoft-activity-group'
        ],
        'parse_threat_actor_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'botnet',
            'rat',
            'exploit-kit',
            'tds',
            'tool',
            'mitre-tool',
            'mitre-enterprise-attack-tool',
            'mitre-mobile-attack-tool'
        ],
        'parse_tool_galaxy'
    )
)

# mapping Windows Registry Hives and their abbreviations
# see https://cybox.mitre.org/language/version2.1/xsddocs/objects/Win_Registry_Key_Object_xsd.html#RegistryHiveEnum
# the dict keys must be UPPER CASE and end with \\
misp_reghive = {
    "HKEY_CLASSES_ROOT\\": "HKEY_CLASSES_ROOT",
    "HKCR\\": "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG\\": "HKEY_CURRENT_CONFIG",
    "HKCC\\": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_USER\\": "HKEY_CURRENT_USER",
    "HKCU\\": "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE\\": "HKEY_LOCAL_MACHINE",
    "HKLM\\": "HKEY_LOCAL_MACHINE",
    "HKEY_USERS\\": "HKEY_USERS",
    "HKU\\": "HKEY_USERS",
    "HKEY_CURRENT_USER_LOCAL_SETTINGS\\": "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKCULS\\": "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKEY_PERFORMANCE_DATA\\": "HKEY_PERFORMANCE_DATA",
    "HKPD\\": "HKEY_PERFORMANCE_DATA",
    "HKEY_PERFORMANCE_NLSTEXT\\": "HKEY_PERFORMANCE_NLSTEXT",
    "HKPN\\": "HKEY_PERFORMANCE_NLSTEXT",
    "HKEY_PERFORMANCE_TEXT\\": "HKEY_PERFORMANCE_TEXT",
    "HKPT\\": "HKEY_PERFORMANCE_TEXT",
}


attack_pattern_object_mapping = {
    'id': 'capec_id',
    'name': 'title',
    'summary': 'description'
}
course_of_action_object_keys = (
    'type',
    'description',
    'objective',
    'stage',
    'cost',
    'impact',
    'efficacy'
)
email_object_mapping = {
    'from': 'from_',
    'reply-to': 'reply_to',
    'subject': 'subject',
    'x-mailer': 'x_mailer',
    'mime-boundary': 'boundary',
    'user-agent': 'user_agent'
}
file_object_mapping = {
    'path': 'full_path',
    'size-in-bytes': 'size_in_bytes',
    'entropy': 'peak_entropy'
}
process_object_keys = (
    'creation-time',
    'start-time',
    'name',
    'pid',
    'parent-pid'
)
regkey_object_mapping = {
    'name': 'name',
    'data': 'data',
    'data-type': 'datatype'
}
user_account_id_mapping = {
    'unix': 'user_id',
    'windows-domain': 'security_id',
    'windows-local': 'security_id'
}
user_account_object_mapping = {
    'username': 'username',
    'display-name': 'full_name',
    'disabled': 'disabled',
    'created': 'creation_date',
    'last_login': 'last_login',
    'home_dir': 'home_directory',
    'shell': 'script_path'
}
vulnerability_object_mapping = {
    'id': 'cve_id',
    'summary': 'description',
    'published': 'published_datetime'
}
weakness_object_mapping = {
    'id': 'cwe_id',
    'description': 'description'
}
whois_object_mapping = {
    'creation-date': 'creation_date',
    'modification-date': 'updated_date',
    'expiration-date': 'expiration_date'
}
whois_registrant_mapping = {
    'registrant-name': 'name',
    'registrant-phone': 'phone_number',
    'registrant-email': 'email_address',
    'registrant-org': 'organization'
}
x509_creation_mapping = {
    'version': 'contents',
    'serial-number': 'contents',
    'issuer': 'contents',
    'subject': 'contents',
    'validity-not-before': 'validity',
    'validity-not-after': 'validity',
    'pubkey-info-exponent': 'rsa_pubkey',
    'pubkey-info-modulus': 'rsa_pubkey',
    'raw-base64': 'raw_certificate',
    'pem': 'raw_certificate',
    'x509-fingerprint-md5': 'signature',
    'x509-fingerprint-sha1': 'signature',
    'x509-fingerprint-sha256': 'signature',
    'pubkey-info-algorithm': 'subject_pubkey'
}
x509_object_keys = (
    'version',
    'serial-number',
    'issuer',
    'subject'
)
