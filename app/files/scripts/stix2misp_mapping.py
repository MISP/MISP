from operator import attrgetter
from collections import defaultdict

__file_attribute_type = ('filename', 'filename')
__network_socket_addresses = ['local_address', 'remote_address']
__network_connection_addresses = ['source_socket_address', 'destination_socket_address']
__s_types = ['src', 'dst']

eventTypes = {"ArtifactObjectType": {"type": "attachment", "relation": "attachment"},
              "DomainNameObjectType": {"type": "domain", "relation": "domain"},
              "FileObjectType": __file_attribute_type,
              "HostnameObjectType": {"type": "hostname", "relation": "host"},
              "MutexObjectType": {"type": "mutex", "relation": "mutex"},
              "PDFFileObjectType": __file_attribute_type,
              "PortObjectType": {"type": "port", "relation": "port"},
              "URIObjectType": {"type": "url", "relation": "url"},
              "WindowsExecutableFileObjectType": __file_attribute_type,
              "WindowsRegistryKeyObjectType": {"type": "regkey", "relation": ""}}

__AS_attribute = ('AS', 'asn')
__as_mapping = {'number': __AS_attribute, 'handle': __AS_attribute, 'name': ('text', 'description')}

__credential_authentication_mapping = {'authentication_type': ('text', 'value', 'type'),
                                       'authentication_data': ('text', 'value', 'password'),
                                       'structured_authentication_mechanism': ('text', 'description.value', 'format')}

__email_mapping = {'from_': ("email-src", "address_value.value", "from"),
                   'reply_to': ("email-reply-to", 'address_value.value', "reply-to"),
                   'subject': ("email-subject", 'value', "subject"),
                   'x_mailer': ("email-x-mailer", 'value', "x-mailer"),
                   'boundary': ("email-mime-boundary", 'value', "mime-boundary"),
                   'user_agent': ("text", 'value', "user-agent")}

__file_mapping = {'file_path': ('text', 'file_path.value', 'path'),
                  'file_format': ('mime-type', 'file_format.value', 'mimetype'),
                  'byte_runs': ('pattern-in-file', 'byte_runs[0].byte_run_data', 'pattern-in-file'),
                  'size_in_bytes': ('size-in-bytes', 'size_in_bytes.value', 'size-in-bytes'),
                  'peak_entropy': ('float', 'peak_entropy.value', 'entropy')}

__network_socket_mapping = {'protocol': ('text', 'protocol', 'protocol'),
                            'address_family': ('text', 'address_family', 'address-family'),
                            'domain': ('text', 'domain', 'domain-family')}

__process_mapping = {'creation_time': ('datetime', 'creation-time'),
                     'start_time': ('datetime', 'start-time'),
                     'name': ('text', 'name'),
                     'pid': ('text', 'pid'),
                     'parent_pid': ('text', 'parent-pid')}

__regkey_mapping = {'hive': ('text', 'hive'), 'key': ('regkey', 'key')}

__regkey_value_mapping = {'data': ('text', 'data'), 'datatype': ('text', 'data-type'), 'name': ('text', 'name')}

__socket_mapping = {'ip_address': ('ip-{}', 'address_value', 'ip-{}'),
                    'port': ('port', 'port_value', '{}-port'),
                    'hostname': ('hostname', 'hostname_value', 'hostname-{}')}

__whois_registrant_mapping = {'email_address': ('whois-registrant-email', 'address_value.value', 'registrant-email'),
                              'name': ('whois-registrant-name', 'value', 'registrant-name'),
                              'phone_number': ('whois-registrant-phone', 'value', 'registrant-phone'),
                              'organization': ('whois-registrant-org', 'value', 'registrant-org')}

__whois_mapping = {'registrar_info': ('whois-registrar', 'value', 'whois-registrar'),
                   'ip_address': ('ip-src', 'address_value.value', 'ip-address'),
                   'domain_name': ('domain', 'value.value', 'domain')}

def __handle_email_attachment(parent):
    properties = parent.related_objects[0].properties
    return "email-attachment", properties.file_name.value, "attachment"

# Parse a socket address object into a network connection or socket object,
# in order to add its attributes
def __handle_socket(attributes, socket, s_type):
    for prop, mapping in __socket_mapping.items():
        if getattr(socket, prop):
            attribute_type, properties_key, relation = mapping
            attribute_type, relation = [elem.format(s_type) for elem in (attribute_type, relation)]
            attributes.append([attribute_type, attrgetter('{}.{}.value'.format(prop, properties_key))(socket), relation])

def attributes_from_as(properties):
    attributes = []
    for prop, mapping in __as_mapping.items():
        if getattr(properties, prop):
            attribute_type, relation = mapping
            attributes.append([attribute_type, attrgetter('{}.value'.format(prop))(properties), relation])
    return attributes

def attributes_from_credential(properties):
    attributes = []
    if properties.description:
        attributes.append(["text", properties.description.value, "text"])
    if properties.authentication:
        for authentication in properties.authentication:
            for prop, mapping in __credential_authentication_mapping.items():
                if getattr(authentication, prop):
                    attribute_type, properties_key, relation = mapping
                    attributes.append([attribute_type, attrgetter('{}.{}'.format(prop, properties_key))(authentication), relation])
    if properties.custom_properties:
        for prop in properties.custom_properties:
            if prop.name in ("username", "origin", "notification"):
                attributes.append(["text", prop.value, prop.name])
    return attributes

def attributes_from_email(properties):
    attributes = []
    if properties.header:
        header = properties.header
        for prop, mapping in __email_mapping.items():
            if getattr(header, prop):
                attribute_type, properties_key, relation = mapping
                attributes.append([attribute_type, attrgetter("{}.{}".format(prop, properties_key))(header), relation])
        if header.to:
            for to in header.to:
                attributes.append(["email-dst", to.address_value.value, "to"])
        if header.cc:
            for cc in header.cc:
                attributes.append(["email-dst", cc.address_value.value, "cc"])
    if properties.attachments:
        attributes.append([__handle_email_attachment(properties.parent)])
    return attributes

def attributes_from_file(properties):
    attributes = []
    for prop, mapping in __file_mapping.items():
        if getattr(properties,prop):
            attribute_type, properties_key, relation = mapping
            attributes.append([attribute_type, attrgetter(properties_key)(properties), relation])
    return attributes

def attributes_from_network_connection(properties):
    attributes = []
    for prop, s_type in zip(__network_connection_addresses, __s_types):
        address_property = getattr(properties, prop)
        if address_property:
            __handle_socket(attributes, address_property, s_type)
    return attributes

def attributes_from_network_socket(properties):
    attributes = []
    for prop, s_type in zip(__network_socket_addresses, __s_types):
        address_property = getattr(properties, prop)
        if address_property:
            __handle_socket(attributes, address_property, s_type)
    for prop, mapping in __network_socket_mapping.items():
        if getattr(properties, prop):
            attribute_type, properties_key, relation = mapping
            attributes.append([attribute_type, attrgetter("{}.value".format(properties_key))(properties), relation])
    return attributes

def attributes_from_process(properties):
    attributes = []
    for prop, mapping in __process_mapping.items():
        if getattr(properties, prop):
            attribute_type, relation = mapping
            attributes.append([attribute_type, attrgetter("{}.value".format(prop))(properties), relation])
    return attributes

def attributes_from_regkey(properties):
    attributes = []
    for prop, mapping in __regkey_mapping.items():
        if getattr(properties, prop):
            attribute_type, relation = mapping
            attributes.append([attribute_type, attrgetter('{}.value'.format(prop))(properties), relation])
    return attributes

def attributes_from_regkey_value(value):
    attributes = []
    for prop, mapping in __regkey_value_mapping.items():
        if getattr(value, prop):
            attribute_type, relation = mapping
            attributes.append([attribute_type, attrgetter('{}.value'.format(prop))(value), relation])
    return attributes

def attributes_from_whois(properties):
    attributes = []
    for prop, mapping in __whois_mapping.items():
        if getattr(properties, prop):
            attribute_type, properties_key, relation = mapping
            attributes.append([attribute_type, attrgetter('{}.{}'.format(prop, properties_key))(properties), relation])
    return attributes

def attributes_from_whois_registrant(registrant):
    attributes = []
    for prop, mapping in __whois_registrant_mapping.items():
        if getattr(registrant, prop):
            attribute_type, properties_key, relation = mapping
            attributes.append([attribute_type, attrgetter('{}.{}'.format(prop, properties_key))(registrant), relation])
    return attributes

def attributes_from_x509_certificate(certificate):
    attributes = []
    if certificate.validity:
        validity = certificate.validity
        for prop in ('not_before', 'not_after'):
            if getattr(validity, prop):
                attributes.append(['datetime', attrgetter('{}.value'.format(prop))(validity), 'validity-{}'.format(prop.replace('_', '-'))])
    if certificate.subject_public_key:
        subject_pubkey = certificate.subject_public_key
        if subject_pubkey.rsa_public_key:
            rsa_pubkey = subject_pubkey.rsa_public_key
            for prop in ('exponent', 'modulus'):
                if getattr(rsa_pubkey, prop):
                    attributes.append(['text', attrgetter('{}.value'.format(prop))(rsa_pubkey), 'pubkey-info-{}'.format(prop)])
        if subject_pubkey.public_key_algorithm:
            attributes.append(["text", subject_pubkey.public_key_algorithm.value, "pubkey-info-algorithm"])
    for prop in ('version', 'serial_number', 'issuer', 'subject'):
        if getattr(certificate, prop):
            attributes.append(['text', attrgetter('{}.value'.format(prop))(certificate), prop.replace('_', '-')])
    return attributes
