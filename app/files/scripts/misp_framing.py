#!/usr/bin/env python3

import sys, json

n_args = {'stix': 4, 'stix2': 2}
json_footer = "]}\n"
keys_to_return = ['header', 'separator', 'footer']

def stix_framing(*args):
    import datetime, re
    from stix.core import STIXPackage, STIXHeader
    from cybox.utils import Namespace
    # As python3 is forced anyway, mixbox is used and we don't need to try to import idgen from stix.utils
    from mixbox import idgen
    from stix import __version__ as STIXVER
    NS_DICT = {
        "http://cybox.mitre.org/common-2" : 'cyboxCommon',
        "http://cybox.mitre.org/cybox-2" : 'cybox',
        "http://cybox.mitre.org/default_vocabularies-2" : 'cyboxVocabs',
        "http://cybox.mitre.org/objects#AccountObject-2" : 'AccountObj',
        "http://cybox.mitre.org/objects#ASObject-1" : 'ASObj',
        "http://cybox.mitre.org/objects#AddressObject-2" : 'AddressObj',
        "http://cybox.mitre.org/objects#PortObject-2" : 'PortObj',
        "http://cybox.mitre.org/objects#DomainNameObject-1" : 'DomainNameObj',
        "http://cybox.mitre.org/objects#EmailMessageObject-2" : 'EmailMessageObj',
        "http://cybox.mitre.org/objects#FileObject-2" : 'FileObj',
        "http://cybox.mitre.org/objects#HTTPSessionObject-2" : 'HTTPSessionObj',
        "http://cybox.mitre.org/objects#HostnameObject-1" : 'HostnameObj',
        "http://cybox.mitre.org/objects#MutexObject-2" : 'MutexObj',
        "http://cybox.mitre.org/objects#PipeObject-2" : 'PipeObj',
        "http://cybox.mitre.org/objects#URIObject-2" : 'URIObj',
        "http://cybox.mitre.org/objects#WinRegistryKeyObject-2" : 'WinRegistryKeyObj',
        'http://cybox.mitre.org/objects#WinServiceObject-2' : 'WinServiceObj',
        "http://cybox.mitre.org/objects#NetworkConnectionObject-2" : 'NetworkConnectionObj',
        "http://cybox.mitre.org/objects#NetworkSocketObject-2" : 'NetworkSocketObj',
        "http://cybox.mitre.org/objects#SocketAddressObject-1" : 'SocketAddressObj',
        "http://cybox.mitre.org/objects#SystemObject-2" : 'SystemObj',
        "http://cybox.mitre.org/objects#ProcessObject-2" : 'ProcessObj',
        "http://cybox.mitre.org/objects#X509CertificateObject-2" : 'X509CertificateObj',
        "http://cybox.mitre.org/objects#WhoisObject-2" : 'WhoisObj',
        "http://cybox.mitre.org/objects#WinExecutableFileObject-2" : 'WinExecutableFileObj',
        "http://data-marking.mitre.org/Marking-1" : 'marking',
        "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" : 'tlpMarking',
        "http://stix.mitre.org/ExploitTarget-1" : 'et',
        "http://stix.mitre.org/Incident-1" : 'incident',
        "http://stix.mitre.org/Indicator-2" : 'indicator',
        "http://stix.mitre.org/TTP-1" : 'ttp',
        "http://stix.mitre.org/ThreatActor-1" : 'ta',
        "http://stix.mitre.org/common-1" : 'stixCommon',
        "http://stix.mitre.org/default_vocabularies-1" : 'stixVocabs',
        "http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1" : 'ciqIdentity',
        "http://stix.mitre.org/extensions/TestMechanism#Snort-1" : 'snortTM',
        "http://stix.mitre.org/stix-1" : 'stix',
        "http://www.w3.org/2001/XMLSchema-instance" : 'xsi',
        "urn:oasis:names:tc:ciq:xal:3" : 'xal',
        "urn:oasis:names:tc:ciq:xnl:3" : 'xnl',
        "urn:oasis:names:tc:ciq:xpil:3" : 'xpil',
    }
    SCHEMALOC_DICT = {
        'http://cybox.mitre.org/common-2': 'http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd',
        'http://cybox.mitre.org/cybox-2': 'http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd',
        'http://cybox.mitre.org/default_vocabularies-2': 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd',
        'http://cybox.mitre.org/objects#AccountObject-2': ' http://cybox.mitre.org/XMLSchema/objects/Account/2.1/Account_Object.xsd',
        'http://cybox.mitre.org/objects#ASObject-1': 'http://cybox.mitre.org/XMLSchema/objects/AS/1.0/AS_Object.xsd',
        'http://cybox.mitre.org/objects#AddressObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Address/2.1/Address_Object.xsd',
        'http://cybox.mitre.org/objects#PortObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Port/2.1/Port_Object.xsd',
        'http://cybox.mitre.org/objects#DomainNameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd',
        'http://cybox.mitre.org/objects#EmailMessageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.1/Email_Message_Object.xsd',
        'http://cybox.mitre.org/objects#FileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd',
        'http://cybox.mitre.org/objects#HTTPSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/HTTP_Session/2.1/HTTP_Session_Object.xsd',
        'http://cybox.mitre.org/objects#HostnameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Hostname/1.0/Hostname_Object.xsd',
        'http://cybox.mitre.org/objects#MutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Mutex/2.1/Mutex_Object.xsd',
        'http://cybox.mitre.org/objects#PipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Pipe/2.1/Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#URIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd',
        'http://cybox.mitre.org/objects#WinServiceObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Service/2.1/Win_Service_Object.xsd',
        'http://cybox.mitre.org/objects#WinRegistryKeyObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkConnectionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Connection/2.0.1/Network_Connection_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkSocketObject-2': 'https://cybox.mitre.org/XMLSchema/objects/Network_Socket/2.1/Network_Socket_Object.xsd',
        'http://cybox.mitre.org/objects#SystemObject-2': 'http://cybox.mitre.org/XMLSchema/objects/System/2.1/System_Object.xsd',
        'http://cybox.mitre.org/objects#SocketAddressObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Socket_Address/1.1/Socket_Address_Object.xsd',
        'http://cybox.mitre.org/objects#ProcessObject-2': 'https://cybox.mitre.org/XMLSchema/objects/Process/2.1/Process_Object.xsd',
        'http://cybox.mitre.org/objects#X509CertificateObject-2': 'http://cybox.mitre.org/XMLSchema/objects/X509_Certificate/2.1/X509_Certificate_Object.xsd',
        'http://cybox.mitre.org/objects#WhoisObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Whois/2.1/Whois_Object.xsd',
        'http://cybox.mitre.org/objects#WinExecutableFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/2.1/Win_Executable_File_Object.xsd',
        'http://data-marking.mitre.org/Marking-1': 'http://stix.mitre.org/XMLSchema/data_marking/1.1.1/data_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.1.1/tlp_marking.xsd',
        'http://stix.mitre.org/ExploitTarget-1': 'http://stix.mitre.org/XMLSchema/exploit_target/1.1.1/exploit_target.xsd',
        'http://stix.mitre.org/Incident-1': 'http://stix.mitre.org/XMLSchema/incident/1.1.1/incident.xsd',
        'http://stix.mitre.org/Indicator-2': 'http://stix.mitre.org/XMLSchema/indicator/2.1.1/indicator.xsd',
        'http://stix.mitre.org/TTP-1': 'http://stix.mitre.org/XMLSchema/ttp/1.1.1/ttp.xsd',
        'http://stix.mitre.org/ThreatActor-1': 'http://stix.mitre.org/XMLSchema/threat_actor/1.1.1/threat_actor.xsd',
        'http://stix.mitre.org/common-1': 'http://stix.mitre.org/XMLSchema/common/1.1.1/stix_common.xsd',
        'http://stix.mitre.org/default_vocabularies-1': 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.1.1/ciq_3.0_identity.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.1.1/snort_test_mechanism.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.1.1/stix_core.xsd',
        'urn:oasis:names:tc:ciq:xal:3': 'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xAL.xsd',
        'urn:oasis:names:tc:ciq:xnl:3': 'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xNL.xsd',
        'urn:oasis:names:tc:ciq:xpil:3': 'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xPIL.xsd',
    }

    baseurl, orgname, return_type = args
    if not baseurl:
        baseurl = 'https://www.misp-project.org'
    real_orgname = args[1]
    orgname = re.sub('[\W]+', '', orgname.replace(" ", "_"))
    NS_DICT[baseurl] = orgname
    try:
        idgen.set_id_namespace(Namespace(baseurl, orgname))
    except TypeError:
        idgen.set_id_namespace(Namespace(baseurl, orgname, "MISP"))
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title="Export from {} MISP".format(real_orgname)
    stix_header.package_intents="Threat Report"
    stix_package.stix_header = stix_header
    stix_package.version = "1.1.1"
    stix_package.timestamp = datetime.datetime.now()
    return stix_json_framing(stix_package) if return_type == 'json' else stix_xml_framing(stix_package, NS_DICT, SCHEMALOC_DICT)

def stix_json_framing(stix_package):
    header = '{}, "related_packages": ['.format(stix_package.to_json()[:-1])
    return header, ',', json_footer

def stix_xml_framing(stix_package, ns, schema):
    s_stix_package = "</stix:STIX_Package>\n"
    s_related_package = "stix:RelatedPackage"
    header = stix_package.to_xml(auto_namespace=False, ns_dict=ns, schemaloc_dict=schema)
    header = header.decode()
    header = "{0}    <{1}s>\n        <{1}>\n".format(header, s_related_package).replace(s_stix_package, "")
    footer = "        </{0}>\n    </{0}s>\n{1}".format(s_related_package, s_stix_package)
    separator = "        </{0}>\n        <{0}>\n".format(s_related_package)
    return header, separator, footer

def stix2_framing(*args):
    return '{"type": "bundle", "spec_version": "2.0", "id": "bundle--%s", "objects": [' % args[0], ',', json_footer

framing_mapping = {'stix': stix_framing, 'stix2': stix2_framing}

def main(args):
    framing_type = args[1]
    n = n_args[framing_type]
    if len(args) < n:
        sys.exit("Invalid parameters")
    args = args[2:]
    values_to_return = framing_mapping[framing_type](*args)
    print(json.dumps({keys: values for keys, values in zip(keys_to_return, values_to_return)}))

if __name__ == "__main__":
    main(sys.argv)
