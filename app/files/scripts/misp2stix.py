#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import json
import os
import datetime
import re
import ntpath
import socket
from pymisp import MISPEvent
from copy import deepcopy
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.indicator.valid_time import ValidTime
from stix.ttp import TTP, Behavior
from stix.ttp.malware_instance import MalwareInstance
from stix.incident import Incident, Time, ImpactAssessment, ExternalID, AffectedAsset, AttributedThreatActors
from stix.exploit_target import ExploitTarget, Vulnerability
from stix.incident.history import JournalEntry, History, HistoryItem
from stix.threat_actor import ThreatActor
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource, Identity
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.common.related import RelatedIndicator, RelatedObservable, RelatedThreatActor, RelatedTTP
from stix.common.confidence import Confidence
from stix.common.vocabs import IncidentStatus
from cybox.utils import Namespace
from cybox.core import Object, Observable, ObservableComposition, RelatedObject
from cybox.objects.file_object import File
from cybox.objects.address_object import Address
from cybox.objects.port_object import Port
from cybox.objects.hostname_object import Hostname
from cybox.objects.uri_object import URI
from cybox.objects.pipe_object import Pipe
from cybox.objects.mutex_object import Mutex
from cybox.objects.artifact_object import Artifact, RawArtifact
from cybox.objects.memory_object import Memory
from cybox.objects.email_message_object import EmailMessage, EmailHeader, EmailRecipients, Attachments
from cybox.objects.domain_name_object import DomainName
from cybox.objects.win_registry_key_object import RegistryValue, RegistryValues, WinRegistryKey
from cybox.objects.system_object import System, NetworkInterface, NetworkInterfaceList
from cybox.objects.http_session_object import HTTPClientRequest, HTTPRequestHeader, HTTPRequestHeaderFields, HTTPRequestLine, HTTPRequestResponse, HTTPSession
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.process_object import Process
from cybox.objects.whois_object import WhoisEntry, WhoisRegistrants, WhoisRegistrant, WhoisRegistrar, WhoisNameservers
from cybox.objects.win_service_object import WinService
from cybox.objects.win_executable_file_object import WinExecutableFile, PEHeaders, PEFileHeader, PESectionList, PESection, PESectionHeaderStruct, Entropy
from cybox.objects.x509_certificate_object import X509Certificate, X509CertificateSignature, X509Cert, SubjectPublicKey, RSAPublicKey, Validity
from cybox.objects.account_object import Account, Authentication, StructuredAuthenticationMechanism
from cybox.objects.custom_object import Custom
from cybox.common import Hash, HashList, ByteRun, ByteRuns
from cybox.common.object_properties import CustomProperties,  Property
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance, STIXCIQIdentity3_0, PartyName, ElectronicAddressIdentifier, FreeTextAddress
from stix.extensions.identity.ciq_identity_3_0 import Address as ciq_Address
from collections import defaultdict

try:
    from stix.utils import idgen
except ImportError:
    from mixbox import idgen

namespace = ['https://github.com/MISP/MISP', 'MISP']

this_module = sys.modules[__name__]

# mappings
status_mapping = {'0' : 'New', '1' : 'Open', '2' : 'Closed'}
threat_level_mapping = {'1' : 'High', '2' : 'Medium', '3' : 'Low', '4' : 'Undefined'}
TLP_mapping = {'0' : 'AMBER', '1' : 'GREEN', '2' : 'GREEN', '3' : 'GREEN', '4' : 'AMBER'}
TLP_order = {'RED' : 4, 'AMBER' : 3, 'GREEN' : 2, 'WHITE' : 1}
confidence_mapping = {False : 'None', True : 'High'}

not_implemented_attributes = ['yara', 'snort', 'pattern-in-traffic', 'pattern-in-memory']

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'vulnerability']

hash_type_attributes = {"single": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256", "ssdeep",
                                   "imphash", "authentihash", "pehash", "tlsh", "x509-fingerprint-sha1"],
                        "composite": ["filename|md5", "filename|sha1", "filename|sha224", "filename|sha256", "filename|sha384",
                                      "filename|sha512", "filename|sha512/224", "filename|sha512/256", "filename|authentihash",
                                      "filename|ssdeep", "filename|tlsh", "filename|imphash", "filename|pehash"]}

# mapping for the attributes that can go through the simpleobservable script
misp_cybox_name = {"domain" : "DomainName", "hostname" : "Hostname", "url" : "URI", "AS" : "AutonomousSystem", "mutex" : "Mutex",
                   "named pipe" : "Pipe", "link" : "URI", "network-connection": "NetworkConnection", "windows-service-name": "WinService"}
cybox_name_attribute = {"DomainName" : "value", "Hostname" : "hostname_value", "URI" : "value", "AutonomousSystem" : "number",
                        "Pipe" : "name", "Mutex" : "name", "WinService": "name"}
misp_indicator_type = {"AS" : "", "mutex" : "Host Characteristics", "named pipe" : "Host Characteristics",
                       "email-attachment": "Malicious E-mail", "url" : "URL Watchlist"}
misp_indicator_type.update(dict.fromkeys(hash_type_attributes["single"] + hash_type_attributes["composite"] + ["filename"] + ["attachment"], "File Hash Watchlist"))
misp_indicator_type.update(dict.fromkeys(["email-src", "email-dst", "email-subject", "email-reply-to",  "email-attachment"], "Malicious E-mail"))
misp_indicator_type.update(dict.fromkeys(["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"], "IP Watchlist"))
misp_indicator_type.update(dict.fromkeys(["domain", "domain|ip", "hostname"], "Domain Watchlist"))
misp_indicator_type.update(dict.fromkeys(["regkey", "regkey|value"], "Host Characteristics"))
cybox_validation = {"AutonomousSystem": "isInt"}

# mapping Windows Registry Hives and their abbreviations
# see https://cybox.mitre.org/language/version2.1/xsddocs/objects/Win_Registry_Key_Object_xsd.html#RegistryHiveEnum
# the dict keys must be UPPER CASE and end with \\
misp_reghive = {
    "HKEY_CLASSES_ROOT\\"                : "HKEY_CLASSES_ROOT",
    "HKCR\\"                             : "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG\\"              : "HKEY_CURRENT_CONFIG",
    "HKCC\\"                             : "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_USER\\"                : "HKEY_CURRENT_USER",
    "HKCU\\"                             : "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE\\"               : "HKEY_LOCAL_MACHINE",
    "HKLM\\"                             : "HKEY_LOCAL_MACHINE",
    "HKEY_USERS\\"                       : "HKEY_USERS",
    "HKU\\"                              : "HKEY_USERS",
    "HKEY_CURRENT_USER_LOCAL_SETTINGS\\" : "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKCULS\\"                           : "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKEY_PERFORMANCE_DATA\\"            : "HKEY_PERFORMANCE_DATA",
    "HKPD\\"                             : "HKEY_PERFORMANCE_DATA",
    "HKEY_PERFORMANCE_NLSTEXT\\"         : "HKEY_PERFORMANCE_NLSTEXT",
    "HKPN\\"                             : "HKEY_PERFORMANCE_NLSTEXT",
    "HKEY_PERFORMANCE_TEXT\\"            : "HKEY_PERFORMANCE_TEXT",
    "HKPT\\"                             : "HKEY_PERFORMANCE_TEXT",
}

class StixBuilder(object):
    def __init__(self, args):
        self.misp_event = MISPEvent()
        self.args = args
        if len(args) > 3:
            namespace[0] = args[3]
        if len(args) > 4:
            ns = args[4].replace(" ", "_")
            namespace[1] = re.sub('[\W]+', '', ns)
        if not namespace[0]:
            namespace[0] = 'https://www.misp-project.org'
        try:
            idgen.set_id_namespace({namespace[0]: namespace[1]})
        except ValueError:
            try:
                idgen.set_id_namespace(Namespace(namespace[0], namespace[1]))
            except TypeError:
                idgen.set_id_namespace(Namespace(namespace[0], namespace[1], "MISP"))
        self.namespace_prefix = idgen.get_id_namespace_alias()
        self.objects_to_parse = defaultdict(dict)
        ## MAPPING FOR ATTRIBUTES
        self.simple_type_to_method = {"port": self.generate_port_observable, "domain|ip": self.generate_domain_ip_observable}
        self.simple_type_to_method.update(dict.fromkeys(hash_type_attributes["single"] + hash_type_attributes["composite"] + ["filename"], self.resolve_file_observable))
        self.simple_type_to_method.update(dict.fromkeys(["ip-src", "ip-dst"], self.generate_ip_observable))
        self.simple_type_to_method.update(dict.fromkeys(["ip-src|port", "ip-dst|port", "hostname|port"], self.generate_socket_address_observable))
        self.simple_type_to_method.update(dict.fromkeys(["regkey", "regkey|value"], self.generate_regkey_observable))
        self.simple_type_to_method.update(dict.fromkeys(["hostname", "domain", "url", "AS", "mutex", "named pipe", "link", "windows-service-name"], self.generate_simple_observable))
        self.simple_type_to_method.update(dict.fromkeys(["email-src", "email-dst", "email-subject", "email-reply-to"], self.resolve_email_observable))
        self.simple_type_to_method.update(dict.fromkeys(["http-method", "user-agent"], self.resolve_http_observable))
        self.simple_type_to_method.update(dict.fromkeys(["pattern-in-file", "pattern-in-traffic", "pattern-in-memory"], self.resolve_pattern_observable))
        self.simple_type_to_method.update(dict.fromkeys(["mac-address"], self.resolve_system_observable))
        self.simple_type_to_method.update(dict.fromkeys(["attachment"], self.resolve_attachment))
        self.simple_type_to_method.update(dict.fromkeys(["email-attachment"], self.generate_email_attachment_observable))
        self.simple_type_to_method.update(dict.fromkeys(["malware-sample"], self.resolve_malware_sample))
        ## MAPPING FOR OBJECTS
        self.objects_mapping = {"asn": self.parse_asn_object,
                                "credential": self.parse_credential_object,
                                "domain-ip": self.parse_domain_ip_object,
                                "email": self.parse_email_object,
                                "file": self.parse_file_object,
                                "ip-port": self.parse_ip_port_object,
                                "network-connection": self.parse_network_connection_object,
                                "network-socket": self.parse_network_socket_object,
                                "pe": self.store_pe,
                                "pe-section": self.store_pe,
                                "process": self.parse_process_object,
                                "registry-key": self.parse_regkey_object,
                                "url": self.parse_url_object,
                                "whois": self.parse_whois,
                                "x509": self.parse_x509_object
                                }

    def loadEvent(self):
        pathname = os.path.dirname(self.args[0])
        filename = "{}/tmp/{}".format(pathname, self.args[1])
        self.misp_event.load_file(filename)
        self.filename = filename

    def generateEventPackage(self):
        package_name = "{}:STIXPackage-{}".format(namespace[1], self.misp_event.uuid)
        timestamp = self.misp_event.timestamp
        stix_package = STIXPackage(id_=package_name, timestamp=timestamp)
        stix_package.version = "1.1.1"
        stix_header = STIXHeader()
        stix_header.title = "Export from {} MISP".format(self.namespace_prefix)
        stix_header.package_intents = "Threat Report"
        stix_package.stix_header = stix_header
        incident = self.generate_stix_objects()
        stix_package.add_incident(incident)
        for ttp in self.ttps:
            stix_package.add_ttp(ttp)
        self.stix_package = stix_package

    def saveFile(self):
        outputfile = "{}.out".format(self.filename)
        if self.args[2] == 'json':
            with open(outputfile, 'w') as f:
                f.write('{"package": %s}' % self.stix_package.to_json())
        else:
            with open(outputfile, 'wb') as f:
                f.write(self.stix_package.to_xml(include_namespaces=False, include_schemalocs=False,
                                                 encoding='utf8'))

    def generate_stix_objects(self):
        incident = self.create_incident(namespace[1])
        self.history = History()
        threat_level_name = threat_level_mapping.get(str(self.misp_event.threat_level_id), None)
        if threat_level_name:
            threat_level_s = "Event Threat Level: {}".format(threat_level_name)
            self.add_journal_entry(threat_level_s)
        Tags = {}
        if self.misp_event.Tag:
            event_tags = self.misp_event.Tag
            Tags['event'] = event_tags
            labels = []
            for tag in event_tags:
                labels.append(tag.name)
            if 'misp:tool="misp2stix"' not in labels:
                self.add_journal_entry('MISP Tag: misp:tool="misp2stix"')
            for label in labels:
                tag_name = "MISP Tag: {}".format(label)
                self.add_journal_entry(tag_name)
        else:
            self.add_journal_entry('MISP Tag: misp:tool="misp2stix"')
        external_id = ExternalID(value=str(self.misp_event.id), source="MISP Event")
        incident.add_external_id(external_id)
        incident_status_name = status_mapping.get(str(self.misp_event.analysis), None)
        if incident_status_name is not None:
            incident.status = IncidentStatus(incident_status_name)
        try:
            incident.handling = self.set_tlp(self.misp_event.distribution, event_tags)
        except Exception:
            pass
        incident.information_source = self.set_src()
        self.orgc_name = self.misp_event.Orgc.get('name')
        incident.reporter = self.set_rep()
        self.ttps = []
        self.resolve_attributes(incident, Tags)
        self.resolve_objects(incident, Tags)
        self.add_related_indicators(incident)
        if self.history.history_items:
            incident.history = self.history
        return incident

    def convert_to_stix_date(self, date):
        # converts a date (YYYY-mm-dd) to the format used by stix
        return datetime.datetime(date.year, date.month, date.day)

    def create_incident(self, org):
        incident_id = "{}:incident-{}".format(org, self.misp_event.uuid)
        incident = Incident(id_=incident_id, title=self.misp_event.info)
        timestamp = self.misp_event.publish_timestamp
        incident.timestamp = timestamp
        incident_time = Time()
        incident_time.incident_discovery = self.convert_to_stix_date(self.misp_event.date)
        incident_time.incident_reported = timestamp
        incident.time = incident_time
        return incident

    def resolve_attributes(self, incident, tags):
        for attribute in self.misp_event.attributes:
            attribute_type = attribute.type
            if attribute_type in not_implemented_attributes:
                if attribute_type == "snort":
                    self.generate_TM(incident, attribute, tags)
                else:
                    journal_entry = "!Not implemented attribute category/type combination caught! attribute[{}][{}]: {}".format(attribute.category,
                    attribute_type, attribute.value)
                    self.add_journal_entry(journal_entry)
            elif attribute_type in non_indicator_attributes:
                self.handle_non_indicator_attribute(incident, attribute, tags)
            else:
                self.handle_attribute(incident, attribute, tags)

    def resolve_objects(self, incident, tags):
        for misp_object in self.misp_event.objects:
            category = misp_object.get('meta-category')
            name = misp_object.name
            try:
                to_ids, observable = self.objects_mapping[name](misp_object)
            except KeyError:
                to_ids, observable = self.create_custom_observable(name, misp_object.attributes, misp_object.uuid)
            except TypeError:
                continue
            if to_ids:
                indicator = self.create_indicator(misp_object, observable, tags)
                related_indicator = RelatedIndicator(indicator, relationship=category)
                incident.related_indicators.append(related_indicator)
            else:
                related_observable = RelatedObservable(observable, relationship=category)
                incident.related_observables.append(related_observable)
        if self.objects_to_parse:
            self.resolve_objects2parse(incident, tags)


    def resolve_objects2parse(self, incident, tags):
        for uuid, file_object in self.objects_to_parse['file'].items():
            category = file_object.get('meta-category')
            to_ids_file, file_dict = self.create_attributes_dict(file_object.attributes)
            to_ids_list = [to_ids_file]
            win_exec_file = WinExecutableFile()
            self.fill_file_object(win_exec_file, file_dict)
            for reference in file_object.references:
                if reference.relationship_type == "included-in" and reference.Object['name'] == "pe":
                    pe_uuid = reference.referenced_uuid
                    break
            pe_object = self.objects_to_parse['pe'][pe_uuid]
            to_ids_pe, pe_dict = self.create_attributes_dict(pe_object.attributes)
            to_ids_list.append(to_ids_pe)
            pe_headers, pe_sections = self.parse_pe_references(pe_object, to_ids_list)
            win_exec_file.sections = pe_sections
            if 'number-sections' in pe_dict:
                pe_headers.file_header.number_of_sections = pe_dict['number-sections']
            if not win_exec_file.file_name and ('internal-filename' in pe_dict or 'original-filename' in pe_dict):
                try:
                    win_exec_file.file_name = pe_dict['original-filename']
                except KeyError:
                    win_exec_file.file_name = pe_dict['internal-filename']
            win_exec_file.headers = pe_headers
            win_exec_file.parent.id_ = "{}:WinExecutableFileObject-{}".format(self.namespace_prefix, uuid)
            observable = Observable(win_exec_file)
            observable.id_ = "{}:WinExecutableFile-{}".format(self.namespace_prefix, uuid)
            to_ids = True if True in to_ids_list else False
            if to_ids:
                indicator = self.create_indicator(file_object, observable, tags)
                related_indicator = RelatedIndicator(indicator, relationship=category)
                incident.related_indicators.append(related_indicator)
            else:
                related_observable = RelatedObservable(observable, relationship=category)
                incident.related_observables.append(related_observable)

    def parse_pe_references(self, pe_object, to_ids_list):
        pe_headers = PEHeaders()
        pe_file_header = PEFileHeader()
        pe_sections = PESectionList()
        for reference in pe_object.references:
            if reference.Object['name'] == "pe-section":
                pe_section_object = self.objects_to_parse['pe-section'][reference.referenced_uuid]
                to_ids_section, section_dict = self.create_attributes_dict(pe_section_object.attributes)
                to_ids_list.append(to_ids_section)
                if reference.relationship_type == "included-in":
                    pe_sections.append(self.create_pe_section_object(section_dict))
                elif reference.relationship_type == "header-of":
                    entropy = self.create_pe_file_header(section_dict, pe_file_header)
                    if entropy:
                        pe_headers.entropy = Entropy()
                        pe_headers.entropy.value = entropy
        pe_headers.file_header = pe_file_header
        return pe_headers, pe_sections

    def create_indicator(self, misp_object, observable, tags):
        tlp_tags = deepcopy(tags)
        indicator = Indicator(timestamp=misp_object.timestamp)
        indicator.id_ = "{}:MISPObject-{}".format(namespace[1], misp_object.uuid)
        indicator.producer = self.set_prod(self.orgc_name)
        for attribute in misp_object.attributes:
            tlp_tags = self.merge_tags(tlp_tags, attribute)
        try:
            indicator.handling = self.set_tlp(misp_object.distribution, tlp_tags)
        except Exception:
            pass
        title = "{} (MISP Object #{})".format(misp_object.name, misp_object.id)
        indicator.title = title
        indicator.description = misp_object.comment if misp_object.comment else title
        indicator.add_indicator_type("Malware Artifacts")
        indicator.add_valid_time_position(ValidTime())
        indicator.add_observable(observable)
        return indicator

    def add_related_indicators(self, incident):
        for rindicator in incident.related_indicators:
            for ttp in self.ttps:
                ittp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
                rindicator.item.add_indicated_ttp(ittp)

    def handle_attribute(self, incident, attribute, tags):
        observable = self.generate_observable(attribute)
        if observable:
            if attribute.to_ids:
                indicator = self.generate_indicator(attribute, tags)
                indicator.add_indicator_type("Malware Artifacts")
                try:
                    indicator.add_indicator_type(misp_indicator_type[attribute.type])
                except Exception:
                    pass
                indicator.add_valid_time_position(ValidTime())
                indicator.add_observable(observable)
                related_indicator = RelatedIndicator(indicator, relationship=attribute.category)
                incident.related_indicators.append(related_indicator)
            else:
                related_observable = RelatedObservable(observable, relationship=attribute.category)
                incident.related_observables.append(related_observable)

    def handle_non_indicator_attribute(self, incident, attribute, tags):
        attribute_type = attribute.type
        attribute_category = attribute.category
        if attribute_type == "vulnerability":
            ttp = self.generate_vulnerability(attribute, tags)
            incident.leveraged_ttps.append(self.append_ttp(attribute_category, ttp))
        elif attribute_type == "link":
            self.add_reference(incident, attribute.value)
        elif attribute_type in ('comment', 'text', 'other'):
            if attribute_category == "Payload type":
                ttp = self.generate_ttp(attribute, tags)
                incident.leveraged_ttps.append(self.append_ttp(attribute_category, ttp))
            elif attribute_category == "Attribution":
                ta = self.generate_threat_actor(attribute)
                rta = RelatedThreatActor(ta, relationship="Attribution")
                if incident.attributed_threat_actors:
                    incident.attributed_threat_actors.append(rta)
                else:
                    ata = AttributedThreatActors()
                    ata.append(rta)
                    incident.attributed_threat_actors = ata
            else:
                entry_line = "attribute[{}][{}]: {}".format(attribute_category, attribute_type, attribute.value)
                self.add_journal_entry(entry_line)
        elif attribute_type == "target-machine":
            aa = AffectedAsset()
            description = attribute.value
            if attribute.comment:
                description += " ({})".format(attribute.comment)
            aa.description = description
            incident.affected_assets.append(aa)
        elif attribute_type.startswith('target-'):
            incident.add_victim(self.resolve_identity_attribute(attribute))

    def create_artifact_object(self, data, artifact=None):
        raw_artifact = RawArtifact(data)
        artifact = Artifact()
        artifact.raw_artifact = raw_artifact
        return artifact

    def generate_domain_ip_observable(self, attribute):
        domain, ip = attribute.value.split('|')
        address_object = self.create_ip_object(attribute.type, ip)
        address_object.parent.id_ = "{}:AddressObject-{}".format(self.namespace_prefix, attribute.uuid)
        address_observable = Observable(address_object)
        address_observable.id_ = "{}:Address-{}".format(self.namespace_prefix, attribute.uuid)
        domain_object = DomainName()
        domain_object.value = domain
        domain_object.value.condition = "Equals"
        domain_object.parent.id_ = "{}:DomainNameObject-{}".format(self.namespace_prefix, attribute.uuid)
        domain_observable = Observable(domain_object)
        domain_observable.id_ = "{}:DomainName-{}".format(self.namespace_prefix, attribute.uuid)
        composite_object = ObservableComposition(observables=[address_observable, domain_observable])
        composite_object.operator = "AND"
        observable = Observable(id_="{}:ObservableComposition-{}".format(self.namespace_prefix, attribute.uuid))
        observable.observable_composition = composite_object
        return observable

    def generate_email_attachment_observable(self, attribute):
        attribute_uuid = attribute.uuid
        file_object = File()
        file_object.file_name = attribute.value
        file_object.file_name.condition = "Equals"
        file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, attribute_uuid)
        email = EmailMessage()
        email.attachments = Attachments()
        email.add_related(file_object, "Contains", inline=True)
        email.attachments.append(file_object.parent.id_)
        email.parent.id_ = "{}:EmailMessageObject-{}".format(self.namespace_prefix, attribute_uuid)
        observable = Observable(email)
        observable.id_ = "{}:EmailMessage-{}".format(self.namespace_prefix, attribute_uuid)
        return observable

    def generate_file_observable(self, filename, h_value, fuzzy):
        file_object = File()
        if filename:
            self.resolve_filename(file_object, filename)
        if h_value:
            file_object.add_hash(Hash(hash_value=h_value, exact=True))
            if fuzzy:
                try:
                    self.resolve_fuzzy(file_object, h_value, "Hashes")
                except KeyError:
                    field_type = ""
                    for f in file_object._fields:
                        if f.name == "Hashes":
                            field_type = f
                            break
                    if field_type:
                        self.resolve_fuzzy(file_object, h_value, field_type)
        return file_object

    @staticmethod
    def resolve_fuzzy(file_object, h_value, field_type):
        file_object._fields[field_type]._inner[0].simple_hash_value = None
        file_object._fields[field_type]._inner[0].fuzzy_hash_value = h_value
        file_object._fields[field_type]._inner[0].fuzzy_hash_value.condition = "Equals"
        file_object._fields[field_type]._inner[0].type_ = Hash.TYPE_SSDEEP
        file_object._fields[field_type]._inner[0].type_.condition = "Equals"

    def generate_indicator(self, attribute, tags):
        indicator = Indicator(timestamp=attribute.timestamp)
        indicator.id_ = "{}:indicator-{}".format(namespace[1], attribute.uuid)
        indicator.producer = self.set_prod(self.orgc_name)
        if attribute.comment:
            indicator.description = attribute.comment
        indicator.handling = self.set_tlp(attribute.distribution, self.merge_tags(tags, attribute))
        indicator.title = "{}: {} (MISP Attribute #{})".format(attribute.category, attribute.value, attribute.id)
        indicator.description = indicator.title
        confidence_description = "Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none"
        confidence_value = confidence_mapping.get(attribute.to_ids, None)
        if confidence_value is None:
            return indicator
        indicator.confidence = Confidence(value=confidence_value, description=confidence_description, timestamp=attribute.timestamp)
        return indicator

    def generate_ip_observable(self, attribute):
        address_object = self.create_ip_object(attribute.type, attribute.value)
        address_object.parent.id_ = "{}:AddressObject-{}".format(self.namespace_prefix, attribute.uuid)
        address_observable = Observable(address_object)
        address_observable.id_ = "{}:Address-{}".format(self.namespace_prefix, attribute.uuid)
        return address_observable

    def generate_observable(self, attribute):
        attribute_type = attribute.type
        try:
            observable_property = self.simple_type_to_method[attribute_type](attribute)
        except KeyError:
            return False
        if isinstance(observable_property, Observable):
            return observable_property
        observable_property.condition = "Equals"
        observable_object = Object(observable_property)
        observable_object.id_ = "{}:{}-{}".format(self.namespace_prefix, observable_property.__class__.__name__, attribute.uuid)
        observable = Observable(observable_object)
        observable.id_ = "{}:observable-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    def generate_port_observable(self, attribute):
        port_object = self.create_port_object(attribute.value)
        port_object.parent.id_ = "{}:PortObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(port_object)
        observable.id_ = "{}:Port-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    def generate_regkey_observable(self, attribute, value=None):
        if attribute.type == "regkey|value":
            regkey, value = attribute.value.split('|')
        else:
            regkey = attribute.value
        reg_object = self.create_regkey_object(regkey)
        if value:
            reg_value_object = RegistryValue()
            reg_value_object.data = value.strip()
            reg_value_object.data.condition = "Equals"
            reg_object.values = RegistryValues(reg_value_object)
        reg_object.parent.id_ = "{}:WinRegistryKeyObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(reg_object)
        observable.id_ = "{}:WinRegistryKey-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    def generate_simple_observable(self, attribute):
        cybox_name = misp_cybox_name[attribute.type]
        if cybox_name == "AutonomousSystem":
            attribute_value = self.define_attribute_value(attribute.value, attribute.comment)
            stix_field = cybox_name_attribute[cybox_name] if not attribute_value.startswith('AS') else 'handle'
        else:
            attribute_value = attribute.value
            stix_field = cybox_name_attribute[cybox_name]
        constructor = getattr(this_module, cybox_name, None)
        new_object = constructor()
        setattr(new_object, stix_field, attribute_value)
        setattr(getattr(new_object, stix_field), "condition", "Equals")
        new_object.parent.id_ = "{}:{}Object-{}".format(self.namespace_prefix, cybox_name, attribute.uuid)
        observable = Observable(new_object)
        observable.id_ = "{}:{}-{}".format(self.namespace_prefix, cybox_name, attribute.uuid)
        return observable

    @staticmethod
    def define_attribute_value(value, comment):
        if comment.startswith("AS") and not value.startswith("AS"):
            return comment
        return value

    def generate_socket_address_observable(self, attribute):
        value1, port = attribute.value.split('|')
        type1, _ = attribute.type.split('|')
        socket_address_object = SocketAddress()
        if 'ip-' in type1:
            socket_address_object.ip_address = self.create_ip_object(type1, value1)
        else:
            socket_address_object.hostname = self.create_hostname_object(value1)
        socket_address_object.port = self.create_port_object(port)
        socket_address_object.parent.id_ = "{}:SocketAddressObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(socket_address_object)
        observable.id_ = "{}:SocketAddress-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    @staticmethod
    def generate_threat_actor(attribute):
        ta = ThreatActor(timestamp=attribute.timestamp)
        ta.id_ = "{}:threatactor-{}".format(namespace[1], attribute.uuid)
        ta.title = "{}: {} (MISP Attribute #{})".format(attribute.category, attribute.value, attribute.id)
        description = attribute.value
        if attribute.comment:
            description += " ({})".format(attribute.comment)
        ta.description = description
        return ta

    def generate_TM(self, incident, attribute, tags):
        if attribute.to_ids:
            tm = SnortTestMechanism()
            value = attribute.value.encode('utf-8')
            tm.rule = value
            indicator = self.generate_indicator(attribute, tags)
            indicator.add_indicator_type("Malware Artifacts")
            indicator.add_valid_time_position(ValidTime())
            indicator.add_test_mechanism(tm)
            related_indicator = RelatedIndicator(indicator, relationship=attribute.category)
            incident.related_indicators.append(related_indicator)

    def generate_ttp(self, attribute, tags):
        ttp = self.create_ttp(attribute, tags)
        malware = MalwareInstance()
        malware.add_name(attribute.value)
        ttp.behavior = Behavior()
        ttp.behavior.add_malware_instance(malware)
        if attribute.comment:
            ttp.description = attribute.comment
        return ttp

    def generate_vulnerability(self, attribute, tags):
        ttp = self.create_ttp(attribute, tags)
        vulnerability = Vulnerability()
        vulnerability.cve_id = attribute.value
        ET = ExploitTarget(timestamp=attribute.timestamp)
        ET.id_ = "{}:et-{}".format(namespace[1], attribute.uuid)
        if attribute.comment and attribute.comment != "Imported via the freetext import.":
            ET.title = attribute.comment
        else:
            ET.title = "Vulnerability {}".format(attribute.value)
        ET.add_vulnerability(vulnerability)
        ttp.exploit_targets.append(ET)
        return ttp

    def parse_asn_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict(misp_object.attributes)
        auto_sys = AutonomousSystem()
        if 'asn' in attributes_dict:
            asn = attributes_dict['asn']
            if asn.startswith('AS'):
                auto_sys.handle = asn
            else:
                auto_sys.number = asn
        if 'description' in attributes_dict:
            auto_sys.name = attributes_dict['description']
        uuid = misp_object.uuid
        auto_sys.parent.id_ = "{}:AutonomousSystemObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(auto_sys)
        observable.id_ = "{}:AutonomousSystem-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    def parse_credential_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict_multiple(misp_object.attributes)
        account = Account()
        if 'text' in attributes_dict:
            account.description = attributes_dict.pop('text')[0]
        if 'username' in attributes_dict or 'origin' in attributes_dict or 'notification' in attributes_dict:
            custom_properties = CustomProperties()
            for relation in ('username', 'origin', 'notification'):
                custom_properties.extend([self.add_credential_custom_property(attribute, relation) for attribute in attributes_dict.pop(relation) if relation in attributes_dict])
        if attributes_dict:
            authentication = Authentication()
            if 'format' in attributes_dict:
                struct_auth_meca = StructuredAuthenticationMechanism()
                struct_auth_meca.description = attributes_dict['format'][0]
                authentication.structured_authentication_mechanism = struct_auth_meca
            account.authentication = self.parse_credential_authentication(authentication, attributes_dict)
        uuid = misp_object.uuid
        account.parent.id_ = "{}:AccountObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(account)
        observable.id_ = "{}:Account-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    @staticmethod
    def add_credential_custom_property(attribute, relation):
        prop = Property()
        prop.name = attribute_relation
        prop.value = attribute
        return prop

    def parse_credential_authentication(self, authentication, attributes_dict):
        if len(attributes_dict['type']) == len(attributes_dict['password']):
            return self.parse_authentication_simple_case(authentication)
        authentication_list = []
        if 'type' in attributes_dict:
            credential_types = attributes_dict['type']
            authentication.authentication_type = credential_types.pop(0) if len(credential_types) == 1 else self.parse_credential_types(credential_types)
            if credential_types:
                for remaining_credential_type in credential_types:
                    auth = Authentication()
                    auth.authentication_type = remaining_credential_type
                    authentication_list.append(auth)
        if 'password' in attributes_dict:
            for password in attributes_dict['password']:
                auth = deepcopy(authentication)
                auth.authentication_data = password
                authentication_list.append(auth)
        else:
            authentication_list.append(authentication)
        return authentication_list

    @staticmethod
    def parse_authentication_simple_case(authentication, attributes_dict):
        authentication_list = []
        for p_type, password in zip(attributes_dict['type'], attributes_dict['password']):
            auth = deepcopy(authentication)
            auth.authentication_type = p_type
            auth.authentication_data = password
            authentication_list.append(auth)
        return authentication_list

    @staticmethod
    def parse_credential_types(credential_types):
        misp_credential_types = ('password', 'api-key', 'encryption-key', 'unknown')
        for _type in credential_types:
            if _type in misp_credential_types:
                return credential_types.pop(credential_types.index(_types))
        return credential_types.pop(0)

    def parse_domain_ip_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict_multiple(misp_object.attributes, with_uuid=True)
        composition = []
        if 'domain' in attributes_dict:
            domain = attributes_dict['domain'][0]
            composition.append(self.create_domain_observable(domain['value'], domain['uuid']))
        if 'ip' in attributes_dict:
            for ip in attributes_dict['ip']:
                composition.append(self.create_ip_observable(ip['value'], ip['uuid']))
        if len(composition) == 1:
            return to_ids, composition[0]
        return to_ids, self.create_observable_composition(composition, misp_object.uuid, "domain-ip")

    def parse_email_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict_multiple(misp_object.attributes, with_uuid=True)
        email_object = EmailMessage()
        email_header = EmailHeader()
        if 'from' in attributes_dict:
            email_header.from_ = attributes_dict['from'][0]['value']
            email_header.from_.condition = "Equals"
        if 'to' in attributes_dict:
            to_recipient = EmailRecipients()
            for to in attributes_dict['to']:
                to_recipient.append(to['value'])
            email_header.to = to_recipient
        if 'cc' in attributes_dict:
            cc_recipient = EmailRecipients()
            for cc in attributes_dict['cc']:
                cc_recipient.append(cc['value'])
            email_header.cc = cc_recipient
        if 'reply-to' in attributes_dict:
            email_header.reply_to = attributes_dict['reply-to'][0]['value']
            email_header.reply_to.condition = "Equals"
        if 'subject' in attributes_dict:
            email_header.subject = attributes_dict['subject'][0]['value']
            email_header.subject.condition = "Equals"
        if 'x-mailer' in attributes_dict:
            email_header.x_mailer = attributes_dict['x-mailer'][0]['value']
            email_header.x_mailer.condition = "Equals"
        if 'mime-boundary' in attributes_dict:
            email_header.boundary = attributes_dict['mime-boundary'][0]['value']
            email_header.boundary.condition = "Equals"
        if 'user-agent' in attributes_dict:
            email_header.user_agent = attributes_dict['user-agent'][0]['value']
            email_header.user_agent.condition = "Equals"
        if 'email-attachment' in attributes_dict:
            email.attachments = Attachments()
            for attachment in attributes_dict['email-attachment']:
                attachment_file = self.create_file_attachment(attachment['value'], attachment['uuid'])
                email_object.add_related(attachment_file, "Contains", inline=True)
                email_object.attachments.append(attachment_file.parent.id_)
        uuid = misp_object.uuid
        email_object.header = email_header
        email_object.parent.id_ = "{}:EmailMessageObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(email_object)
        observable.id_ = "{}:EmailMessage-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    def parse_file_object(self, misp_object):
        uuid = misp_object.uuid
        if misp_object.references:
            to_parse = False
            for reference in misp_object.references:
                if reference.relationship_type == 'included-in' and reference.Object['name'] == "pe":
                    self.objects_to_parse[misp_object.name][uuid] = misp_object
                    to_parse = True
                    break
            if to_parse:
                return
        to_ids, attributes_dict = self.create_attributes_dict(misp_object.attributes)
        file_object = File()
        self.fill_file_object(file_object, attributes_dict)
        file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, uuid)
        file_observable = Observable(file_object)
        file_observable.id_ = "{}:File-{}".format(self.namespace_prefix, uuid)
        return to_ids, file_observable

    def parse_ip_port_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict_multiple(misp_object.attributes, with_uuid=True)
        composition = []
        if 'domain' in attributes_dict:
            for domain in attributes_dict['domain']:
                composition.append(self.create_domain_observable(domain['value'], domain['uuid']))
        if 'src-port' in attributes_dict:
            src_port = attributes_dict['src-port'][0]
            composition.append(self.create_port_observable(src_port['value'], src_port['uuid'], "src"))
        if 'dst-port' in attributes_dict:
            for dst_port in attributes_dict['dst-port']:
                composition.append(self.create_port_observable(dst_port['value'], dst_port['uuid'], "dst"))
        if 'hostname' in attributes_dict:
            for hostname in attributes_dict['hostname']:
                composition.append(self.create_hostname_observable(hostname['value'], hostname['uuid']))
        if 'ip' in attributes_dict:
            for ip in attributes_dict['ip']:
                composition.append(self.create_ip_observable(ip['value'], ip['uuid']))
        if len(composition) == 1:
            return to_ids, composition[0]
        return to_ids, self.create_observable_composition(composition, misp_object.uuid, "ip-port")

    def parse_network_connection_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict(misp_object.attributes)
        network_connection_object = NetworkConnection()
        src_args, dst_args = self.parse_src_dst_args(attributes_dict)
        if src_args:
            network_connection_object.source_socket_address = self.create_socket_address_object('src', **src_args)
        if dst_args:
            network_connection_object.destination_socket_address = self.create_socket_address_object('dst', **dst_args)
        if 'layer3-protocol' in attributes_dict:
            network_connection_object.layer3_protocol = attributes_dict['layer3-protocol']
        if 'layer4-protocol' in attributes_dict:
            network_connection_object.layer4_protocol = attributes_dict['layer4-protocol']
        if 'layer7-protocol' in attributes_dict:
            network_connection_object.layer7_protocol = attributes_dict['layer7-protocol']
        uuid = misp_object.uuid
        network_connection_object.parent.id_ = "{}:NetworkConnectionObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(network_connection_object)
        observable.id_ = "{}:NetworkConnection-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    def parse_network_socket_object(self, misp_object):
        listening, blocking = [False] * 2
        attributes = misp_object.attributes
        for attribute in attributes:
            if attribute.object_relation == "state":
                if attribute.value == "listening":
                    listening = True
                if attribute.value == "blocking":
                    blocking = True
        to_ids, attributes_dict = self.create_attributes_dict(attributes)
        network_socket_object = NetworkSocket()
        src_args, dst_args = self.parse_src_dst_args(attributes_dict)
        if src_args:
            network_socket_object.local_address = self.create_socket_address_object('src', **src_args)
        if dst_args:
            network_socket_object.remote_address = self.create_socket_address_object('dst', **dst_args)
        if 'protocol' in attributes_dict:
            network_socket_object.protocol = attributes_dict['protocol']
        network_socket_object.is_listening = True if listening else False
        network_socket_object.is_blocking = True if blocking else False
        if 'address-family' in  attributes_dict:
            network_socket_object.address_family = attributes_dict['address-family']
        if 'domain-family' in attributes_dict:
            network_socket_object.domain = attributes_dict['domain-family']
        uuid = misp_object.uuid
        network_socket_object.parent.id_ = "{}:NetworkSocketObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(network_socket_object)
        observable.id_ = "{}:NetworkSocket-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    def parse_process_object(self, misp_object):
        attributes = misp_object.attributes
        to_ids, attributes_dict = self.create_attributes_dict_multiple(attributes)
        process_object = Process()
        if 'creation-time' in attributes_dict:
            process_object.creation_time = attributes_dict['creation-time'][0]
        if 'start-time' in attributes_dict:
            process_object.start_time = attributes_dict['start-time'][0]
        if 'name' in attributes_dict:
            process_object.name = attributes_dict['name'][0]
        if 'pid' in attributes_dict:
            process_object.pid = attributes_dict['pid'][0]
        if 'parent-pid' in attributes_dict:
            process_object.parent_pid = attributes_dict['parent-pid'][0]
        if 'child-pid' in attributes_dict:
            # child-pid = attributes['child-pid']
            for child in attributes['child-pid']:
                process_object.child_pid_list.append(child)
        # if 'port' in attributes_dict:
        #     for port in attributes['port']:
        #         process_object.port_list.append(self.create_port_object(port['value']))
        uuid = misp_object.uuid
        process_object.parent.id_ = "{}:ProcessObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(process_object)
        observable.id_ = "{}:Process-{}".format(self.namespace_prefix, uuid)
        if misp_object.references:
            for reference in misp_object.references:
                if reference.relationship_type == "connected-to":
                    related_object = RelatedObject()
                    try:
                        referenced_attribute_type = reference.Object['name']
                    except AttributeError:
                        references_attribute_type = reference.Attribute['type']
                    related_object.idref = "{}:{}-{}".format(self.namespace_prefix, referenced_attribute_type, reference.referenced_uuid)
                    related_object.relationship = "Connected_To"
                    observable.object_.related_objects.append(related_object)
        return to_ids, observable

    def parse_regkey_object(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict(misp_object.attributes)
        registry_values = False
        reg_value_object = RegistryValue()
        reg_object = self.create_regkey_object(attributes_dict['key']) if 'key' in attributes_dict else WinRegistryKey()
        if 'last-modified' in attributes_dict:
            reg_object.modified_time = attributes_dict['last-modified']
            reg_object.modified_time.condition = "Equals"
        if 'name' in attributes_dict:
            reg_value_object.name = attributes_dict['name']
            reg_value_object.name.condition = "Equals"
            registry_values = True
        if 'data' in attributes_dict:
            reg_value_object.data = attributes_dict['data'].strip()
            reg_value_object.data.condition = "Equals"
            registry_values = True
        if 'data-type' in attributes_dict:
            reg_value_object.datatype = attributes_dict['data-type']
            reg_value_object.datatype.condition = "Equals"
            registry_values = True
        if registry_values:
            reg_object.values = RegistryValues(reg_value_object)
        uuid = misp_object.uuid
        reg_object.parent.id_ = "{}:WinRegistryKeyObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(reg_object)
        observable.id_ = "{}:WinRegistryKey-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    def parse_url_object(self, misp_object):
        observables = []
        to_ids, attributes_dict = self.create_attributes_dict(misp_object.attributes, with_uuid=True)
        if 'url' in attributes_dict:
            url = attributes_dict['url']
            observables.append(self.create_url_observable(url['value'], url['uuid']))
        if 'domain' in attributes_dict:
            domain = attributes_dict['domain']
            observables.append(self.create_domain_observable(domain['value'], domain['uuid']))
        if 'host' in attributes_dict:
            hostname = attributes_dict['host']
            observables.append(self.create_hostname_observable(hostname['value'], hostname['uuid']))
        if len(observables) == 1:
            return observables[0]
        return to_ids, self.create_observable_composition(observables, misp_object.uuid, "url")

    def parse_whois(self, misp_object):
        to_ids, attributes_dict = self.create_attributes_dict_multiple(misp_object.attributes)
        n_attribute = len(attributes_dict)
        whois_object = WhoisEntry()
        for attribute in attributes_dict:
            if attribute and "registrant-" in attribute:
                whois_object.registrants = self.fill_whois_registrants(attributes_dict)
                break
        if  'registrar' in attributes_dict:
            whois_registrar = WhoisRegistrar()
            whois_registrar.name = attributes_dict['registrar'][0]
            whois_object.registrar_info = whois_registrar
        if 'creation-date' in attributes_dict:
            whois_object.creation_date = attributes_dict['creation-date'][0]
        if 'modification-date' in attributes_dict:
            whois_object.updated_date = attributes_dict['modification-date'][0]
        if 'expiration-date' in attributes_dict:
            whois_object.expiration_date = attributes_dict['expiration-date'][0]
        if 'nameserver' in attributes_dict:
            whois_nameservers = WhoisNameservers()
            for nameserver in attributes_dict['nameserver']:
                whois_nameservers.append(URI(value=nameserver))
            whois_object.nameservers = whois_nameservers
        if 'domain' in attributes_dict:
            whois_object.domain_name = URI(value=attributes_dict['domain'][0])
        if 'ip-address' in attributes_dict:
            whois_object.ip_address = Address(address_value=attributes_dict['ip-address'][0])
        if 'comment' in attributes_dict:
            whois_object.remarks = attributes_dict['comment']
        elif 'text' in attributes_dict:
            whois_object.remarks = attributes_dict['text']
        uuid = misp_object.uuid
        whois_object.parent.id_ = "{}:WhoisObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(whois_object)
        observable.id_ = "{}:Whois-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    def store_pe(self, misp_object):
        self.objects_to_parse[misp_object.name][misp_object.uuid] = misp_object

    @staticmethod
    def fill_whois_registrants(attributes):
        registrants = WhoisRegistrants()
        registrant = WhoisRegistrant()
        if 'registrant-name' in attributes:
            registrant.name = attributes['registrant-name'][0]
        if 'registrant-phone' in attributes:
            registrant.phone_number = attributes['registrant-phone'][0]
        if 'registrant-email' in attributes:
            registrant.email_address = attributes['registrant-email'][0]
        if 'registrant-org' in attributes:
            registrant.organization = attributes['registrant-org'][0]
        registrants.append(registrant)
        return registrants

    def parse_x509_object(self, misp_object):
        to_ids, attributes_dict = self.create_x509_attributes_dict(misp_object.attributes)
        x509_object = X509Certificate()
        if 'raw_certificate' in attributes_dict:
            raw_certificate = attributes_dict.pop('raw_certificate')
            x509_object.raw_certificate = raw_certificate['pem'] if 'pem' in raw_certificate else raw_certificate['raw-base64']
        if 'signature' in attributes_dict:
            signature = attributes_dict.pop('signature')
            x509_object.certificate_signature = self.fill_x509_signature(signature)
        if 'contents' in attributes_dict or 'validity' in attributes_dict or 'rsa_pubkey' in attributes_dict or 'subject_pubkey' in attributes_dict:
            x509_cert = X509Cert()
            try:
                contents = attributes_dict.pop('contents')
                self.fill_x509_contents(x509_cert, contents)
            except Exception:
                pass
            try:
                validity = attributes_dict.pop('validity')
                x509_cert.validity = self.fill_x509_validity(validity)
            except Exception:
                pass
            if attributes_dict:
                x509_cert.subject_public_key = self.fill_x509_pubkey(**attributes_dict)
            x509_object.certificate = x509_cert
        uuid = misp_object.uuid
        x509_object.parent.id_ = "{}:x509CertificateObject-{}".format(self.namespace_prefix, uuid)
        observable = Observable(x509_object)
        observable.id_ = "{}:x509Certificate-{}".format(self.namespace_prefix, uuid)
        return to_ids, observable

    @staticmethod
    def fill_x509_contents(x509_cert, contents):
        if 'version' in contents:
            x509_cert.version = contents['version']
        if 'serial-number' in contents:
            x509_cert.serial_number = contents['serial-number']
        if 'issuer' in contents:
            x509_cert.issuer = contents['issuer']
        if 'subject' in contents:
            x509_cert.subject = contents['subject']

    @staticmethod
    def fill_x509_pubkey(**attributes):
        pubkey = SubjectPublicKey()
        if 'subject_pubkey' in attributes:
            pubkey.public_key_algorithm = attributes['subject_pubkey']['pubkey-info-algorithm']
        if 'rsa_pubkey' in attributes:
            rsa_pubkey = attributes['rsa_pubkey']
            rsa_public_key = RSAPublicKey()
            if 'pubkey-info-exponent' in rsa_pubkey:
                rsa_public_key.exponent = rsa_pubkey['pubkey-info-exponent']
            if 'pubkey-info-modulus' in rsa_pubkey:
                rsa_public_key.modulus = rsa_pubkey['pubkey-info-modulus']
            pubkey.rsa_public_key = rsa_public_key
        return pubkey

    @staticmethod
    def fill_x509_signature(signature):
        x509_signature = X509CertificateSignature()
        if 'x509-fingerprint-sha256' in signature:
            x509_signature.signature_algorithm = "SHA256"
            x509_signature.signature = signature['x509-fingerprint-sha256']
        elif 'x509-fingerprint-sha1' in signature:
            x509_signature.signature_algorithm = "SHA1"
            x509_signature.signature = signature['x509-fingerprint-sha1']
        elif 'x509-fingerprint-md5' in signature:
            x509_signature.signature_algorithm = "MD5"
            x509_signature.signature = signature['x509-fingerprint-md5']
        return x509_signature

    @staticmethod
    def fill_x509_validity(validity):
        x509_validity = Validity()
        if 'validity-not-before' in validity:
            x509_validity.not_before = validity['validity-not-before']
        if 'validity-not-after' in validity:
            x509_validity.not_after = validity['validity-not-after']
        return x509_validity

    def resolve_attachment(self, attribute):
        attribute_uuid = attribute.uuid
        if 'data' in attribute and attribute.data:
            artifact_object = self.create_artifact_object(attribute.to_dict()['data'])
            artifact_object.parent.id_ = "{}:ArtifactObject-{}".format(self.namespace_prefix, attribute_uuid)
            observable = Observable(artifact_object)
            observable.id_ = "{}:Artifact-{}".format(self.namespace_prefix, attribute_uuid)
            observable.title = attribute.value
        else:
            file_object = File()
            file_object.file_name = attribute.value
            file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, attribute_uuid)
            observable = Observable(file_object)
            observable.id_ = "{}:File-{}".format(self.namespace_prefix, attribute_uuid)
        return observable

    def resolve_email_observable(self, attribute):
        attribute_type = attribute.type
        email_object = EmailMessage()
        email_header = EmailHeader()
        if attribute_type == 'email-src':
            email_header.from_ = attribute.value
            email_header.from_.condition = "Equals"
        elif attribute_type == 'email-dst':
            email_header.to = attribute.value
            email_header.to.condition = "Equals"
        elif attribute_type == 'email-reply-to':
            email_header.reply_to = attribute.value
            email_header.reply_to.condition = "Equals"
        else:
            email_header.subject = attribute.value
            email_header.subject.condition = "Equals"
        email_object.header = email_header
        email_object.parent.id_ = "{}:EmailMessageObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(email_object)
        observable.id_ = "{}:EmailMessage-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    def resolve_file_observable(self, attribute):
        fuzzy = False
        f, h = [""] * 2
        attribute_type = attribute.type
        if attribute_type in hash_type_attributes['composite'] or attribute_type == "malware-sample":
            f, h = attribute.value.split('|')
            composite = attribute_type.split('|')
            if len(composite) > 1 and composite[1] == "ssdeep":
                fuzzy = True
        else:
            if attribute_type in ('filename', 'attachment'):
                f = attribute.value
            else:
                h = attribute.value
            if attribute_type == "ssdeep":
                  fuzzy = True
        file_object = self.generate_file_observable(f, h, fuzzy)
        file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(file_object)
        observable.id_ = "{}:File-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    def resolve_http_observable(self, attribute):
        request_response = HTTPRequestResponse()
        client_request = HTTPClientRequest()
        if attribute.type == 'user-agent':
            header = HTTPRequestHeader()
            header_fields = HTTPRequestHeaderFields()
            header_fields.user_agent = attribute.value
            header.parsed_header = header_fields
            client_request.http_request_header = header
        else:
            line = HTTPRequestLine()
            line.http_method = attribute.value
            line.http_method.condition = "Equals"
            client_request.http_request_line = line
        request_response.http_client_request = client_request
        http_object = HTTPSession()
        request_response.to_xml()
        http_object.http_request_response = [request_response]
        http_object.parent.id_ = "{}:HTTPSessionObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(http_object)
        observable.id_ = "{}:HTTPSession-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    @staticmethod
    def resolve_identity_attribute(attribute):
        attribute_type = attribute.type
        ciq_identity = CIQIdentity3_0Instance()
        identity_spec = STIXCIQIdentity3_0()
        if attribute_type == "target-user":
            identity_spec.party_name = PartyName(person_names=[attribute.value])
        if attribute_type == "target-external":
            # we don't know if target-external is a person or an organisation, so as described at http://docs.oasis-open.org/ciq/v3.0/prd03/specs/ciq-specs-v3-prd3.html#_Toc207716018, use NameLine
            identity_spec.party_name = PartyName(name_lines=["External target: {}".format(attribute.value)])
        elif attribute_type == 'target-org':
            identity_spec.party_name = PartyName(organisation_names=[attribute.value])
        elif attribute_type == 'target-location':
            identity_spec.add_address(ciq_Address(FreeTextAddress(address_lines=[attribute.value])))
        elif attribute_type == 'target-email':
            identity_spec.add_electronic_address_identifier(ElectronicAddressIdentifier(value=attribute.value))
        ciq_identity.specification = identity_spec
        ciq_identity.id_ = "{}:Identity-{}".format(namespace[1], attribute.uuid)
        # is this a good idea?
        ciq_identity.name = "{}: {} (MISP Attribute #{})".format(attribute_type, attribute.value, attribute.id)
        return ciq_identity

    def resolve_malware_sample(self, attribute):
        if 'data' in attribute and attribute.data:
            attribute_uuid = attribute.uuid
            filename, h_value = attribute.value.split('|')
            artifact_object = self.create_artifact_object(attribute.to_dict()['data'])
            artifact_object.hashes = HashList(Hash(hash_value=h_value, exact=True))
            artifact_object.parent.id_ = "{}:ArtifactObject-{}".format(self.namespace_prefix, attribute_uuid)
            observable = Observable(artifact_object)
            observable.id_ = "{}:Artifact-{}".format(self.namespace_prefix, attribute_uuid)
            observable.title = filename
            return observable
        return self.resolve_file_observable(attribute)

    def resolve_pattern_observable(self, attribute):
        if attribute.type == "pattern-in-file":
            byte_run = ByteRun()
            byte_run.byte_run_data = attribute.value
            file_object = File()
            file_object.byte_runs = ByteRuns(byte_run)
            file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, attribute.uuid)
            observable = Observable(file_object)
            observable.id_ = "{}:File-{}".format(self.namespace_prefix, attribute.uuid)
            return observable
        return None

    def resolve_system_observable(self, attribute):
        system_object = System()
        network_interface = NetworkInterface()
        network_interface.mac = attribute.value
        network_interface_list = NetworkInterfaceList()
        network_interface_list.append(network_interface)
        system_object.network_interface_list = network_interface_list
        system_object.parent.id_ = "{}:SystemObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(system_object)
        observable.id_ = "{}:System-{}".format(self.namespace_prefix, attribute.uuid)
        return observable

    def set_rep(self):
        identity = Identity(name=self.orgc_name)
        information_source = InformationSource(identity=identity)
        return information_source

    def set_tlp(self, distribution, tags):
        marking_specification = MarkingSpecification()
        marking_specification.controlled_structure = "../../../descendant-or-self::node()"
        tlp = TLPMarkingStructure()
        attr_colors = self.fetch_colors(tags.get('attributes')) if 'attributes' in tags else []
        if attr_colors:
            color = self.set_color(attr_colors)
        else:
            event_colors = self.fetch_colors(tags.get('event')) if 'event' in tags else []
            if event_colors:
                color = self.set_color(event_colors)
            else:
                color = TLP_mapping.get(str(distribution), None)
        if color is not None:
            tlp.color = color
            marking_specification.marking_structures.append(tlp)
            handling = Marking()
            handling.add_marking(marking_specification)
            return handling
        return

    def add_journal_entry(self, entry_line):
        hi = HistoryItem()
        hi.journal_entry = entry_line
        self.history.append(hi)

    @staticmethod
    def add_reference(target, reference):
        if hasattr(target.information_source, 'references'):
            try:
                target.information_source.add_reference(reference)
            except AttributeError:
                target.information_source.references = [reference]

    def append_ttp(self, category, ttp):
        self.ttps.append(ttp)
        rttp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
        related_ttp = RelatedTTP(rttp, relationship=category)
        return related_ttp

    def create_ttp(self, attribute, tags):
        ttp = TTP(timestamp=attribute.timestamp)
        ttp.id_ = "{}:ttp-{}".format(namespace[1], attribute.uuid)
        try:
            ttp.handling = self.set_tlp(attribute.distribution, self.merge_tags(tags, attribute))
        except Exception:
            pass
        ttp.title = "{}: {} (MISP Attribute #{})".format(attribute.category, attribute.value, attribute.id)
        return ttp

    def create_attributes_dict(self, attributes, with_uuid=False):
        to_ids = self.fetch_ids_flags(attributes)
        attributes_dict = {}
        if with_uuid:
            for attribute in attributes:
                attributes_dict[attribute.object_relation] = {'value': attribute.value, 'uuid': attribute.uuid}
        else:
            for attribute in attributes:
                attributes_dict[attribute.object_relation] = attribute.value
        return to_ids, attributes_dict

    def create_attributes_dict_multiple(self, attributes, with_uuid=False):
        to_ids = self.fetch_ids_flags(attributes)
        attributes_dict = defaultdict(list)
        if with_uuid:
            for attribute in attributes:
                attribute_dict = {'value': attribute.value, 'uuid': attribute.uuid}
                attributes_dict[attribute.object_relation].append(attribute_dict)
        else:
            for attribute in attributes:
                attributes_dict[attribute.object_relation].append(attribute.value)
        return to_ids, attributes_dict

    def create_x509_attributes_dict(self, attributes):
        to_ids = self.fetch_ids_flags(attributes)
        attributes_dict = defaultdict(dict)
        for attribute in attributes:
            relation = attribute.object_relation
            if relation in ('version', 'serial-number', 'issuer', 'subject'):
                attributes_dict['contents'][relation] = attribute.value
            elif relation in ('validity-not-before', 'validity-not-after'):
                attributes_dict['validity'][relation] = attribute.value
            elif relation in ('pubkey-info-exponent', 'pubkey-info-modulus'):
                attributes_dict['rsa_pubkey'][relation] = attribute.value
            elif relation in ('x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256'):
                attributes_dict['signature'][relation] = attribute.value
            elif relation in ('raw-base64', 'pem'):
                attributes_dict['raw_certificate'][relation] = attribute.value
            elif relation == 'pubkey-info-algorithm':
                attributes_dict['subject_pubkey'][relation] = attribute.value
        return to_ids, attributes_dict

    def create_custom_observable(self, name, attributes, uuid):
        to_ids, custom_object = self.create_custom_object(attributes, name)
        custom_object.parent.id_ = "{}:{}CustomObject-{}".format(self.namespace_prefix, name, uuid)
        observable = Observable(custom_object)
        observable.id_ = "{}:{}Custom-{}".format(self.namespace_prefix, name, uuid)
        return to_ids, observable

    def create_domain_observable(self, value, uuid):
        domain_object = DomainName()
        domain_object.value = value
        domain_object.value.condition = "Equals"
        domain_object.parent.id_ = "{}:DomainNameObject-{}".format(self.namespace_prefix, uuid)
        domain_observable = Observable(domain_object)
        domain_observable.id_ = "{}:DomainName-{}".format(self.namespace_prefix, uuid)
        return domain_observable

    def create_file_attachment(self, value, uuid):
        file_object = File(file_name=value)
        file_object.file_name.condition = "Equals"
        file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, uuid)
        return file_object

    def create_hostname_observable(self, value, uuid):
        hostname_object = self.create_hostname_object(value)
        hostname_object.parent.id_ = "{}:HostnameObject-{}".format(self.namespace_prefix, uuid)
        hostname_observable = Observable(hostname_object)
        hostname_observable.id_ = "{}:Hostname-{}".format(self.namespace_prefix, uuid)
        return hostname_observable

    def create_ip_observable(self, value, uuid):
        address_object = self.create_ip_object("ip-dst", value)
        address_object.parent.id_ = "{}:AddressObject-{}".format(self.namespace_prefix, uuid)
        address_observable = Observable(address_object)
        address_observable.id_ = "{}:Address-{}".format(self.namespace_prefix, uuid)
        return address_observable

    def create_observable_composition(self, composition, uuid, name):
        observable_composition = ObservableComposition(observables=composition)
        observable_composition.operator = "AND"
        observable = Observable(id_="{}:{}_ObservableComposition-{}".format(self.namespace_prefix, name, uuid))
        observable.observable_composition = observable_composition
        return observable

    def create_port_observable(self, value, uuid, port_type):
        port_object = self.create_port_object(value)
        port_object.parent.id_ = "{}:PortObject-{}".format(self.namespace_prefix, uuid)
        port_observable = Observable(port_object)
        port_observable.id_ = "{}:{}Port-{}".format(self.namespace_prefix, port_type, uuid)
        return port_observable

    def create_regkey_object(self, regkey):
        reghive, regkey = self.resolve_reg_hive(regkey)
        reg_object = WinRegistryKey()
        reg_object.key = regkey.strip()
        reg_object.key.condition = "Equals"
        if reghive:
            reg_object.hive = reghive.strip()
            reg_object.hive.condition = "Equals"
        return reg_object

    def create_socket_address_object(self, sao_type, **kwargs):
        socket_address_object = SocketAddress()
        ip_type, port_type, hostname_type = [arg.format(sao_type) for arg in ('ip-{}', '{}-port', 'hostname-{}')]
        if ip_type in kwargs:
            socket_address_object.ip_address = self.create_ip_object(ip_type, kwargs[ip_type])
        if port_type in kwargs:
            socket_address_object.port = self.create_port_object(kwargs[port_type])
        if hostname_type in kwargs:
            socket_address_object.hostname = self.create_hostname_object(kwargs[hostname_type])
        return socket_address_object

    def create_url_observable(self, value, uuid):
        url_object = URI(value=value)
        url_object.value.condition = "Equals"
        url_object.parent.id_ = "{}:URIObject-{}".format(self.namespace_prefix, uuid)
        url_observable = Observable(url_object)
        url_observable.id_ = "{}:URI-{}".format(self.namespace_prefix, uuid)
        return url_observable

    @staticmethod
    def create_custom_object(attributes, name):
        to_ids = False
        custom_object = Custom()
        custom_object.custom_properties = CustomProperties()
        for attribute in attributes:
            prop = Property()
            prop.name = "{} {}: {}".format(name, attribute.type, attribute.object_relation)
            prop.value = attribute.value
            custom_object.custom_properties.append(prop)
            if attribute.to_ids:
                to_ids = True
        return to_ids, custom_object

    @staticmethod
    def create_hostname_object(hostname):
        hostname_object = Hostname()
        hostname_object.hostname_value = hostname
        hostname_object.hostname_value.condition = "Equals"
        return hostname_object

    @staticmethod
    def create_ip_object(attribute_type, attribute_value):
        address_object = Address()
        if '|' in attribute_value:
            attribute_value = attribute_value.split('|')[0]
        if '/' in attribute_value:
            attribute_value = attribute_value.split('/')[0]
            address_object.category = "cidr"
            condition = "Contains"
        else:
            try:
                socket.inet_aton(attribute_value)
                address_object.category = "ipv4-addr"
            except socket.error:
                address_object.category = "ipv6-addr"
            condition = "Equals"
        if attribute_type.startswith("ip-src"):
            address_object.is_source = True
            address_object.is_destination = False
        else:
            address_object.is_source = False
            address_object.is_destination = True
        address_object.address_value = attribute_value
        address_object.condition = condition
        return address_object

    @staticmethod
    def create_pe_file_header(header_dict, pe_file_header):
        hashlist = []
        entropy = header_dict.pop('entropy') if 'entropy' in header_dict else None
        if 'size-in-bytes' in header_dict:
            pe_file_header.size_of_optional_header = header_dict.pop('size-in-bytes')
        for key, value in header_dict.items():
            if key in hash_type_attributes['single']:
                hashlist.append(Hash(hash_value=value, exact=True))
        if hashlist:
            pe_file_header.hashes = HashList()
            pe_file_header.hashes.hashes = hashlist
        return entropy

    @staticmethod
    def create_pe_section_object(section_dict):
        section = PESection()
        hashlist = []
        if 'entropy' in section_dict:
            section.entropy = Entropy()
            section.entropy.value = section_dict.pop('entropy')
        if 'name' in section_dict or 'size-in-bytes' in section_dict:
            section.section_header = PESectionHeaderStruct()
            try:
                section.section_header.name = section_dict.pop('name')
            except KeyError:
                pass
            try:
                section.section_header.size_of_raw_data = section_dict.pop('size-in-bytes')
            except KeyError:
                pass
        for key, value in section_dict.items():
            if key in hash_type_attributes['single']:
                hashlist.append(Hash(hash_value=value, exact=True))
        if hashlist:
            section.header_hashes = HashList()
            section.header_hashes.hashes = hashlist
        return section

    @staticmethod
    def create_port_object(port):
        port_object = Port()
        port_object.port_value = port
        port_object.port_value.condition = "Equals"
        return port_object

    def fill_file_object(self, file_object, attributes_dict):
        if 'filename' in attributes_dict:
            # for filename in attributes_dict['filename'][1:]:
            #     custom_property = CustomProp
            #     filename.custom_properties.append()
            self.resolve_filename(file_object, attributes_dict.pop('filename'))
        if 'path' in attributes_dict:
            file_object.full_path = attributes_dict.pop('path')
            file_object.full_path.condition = "Equals"
        if 'size-in-bytes' in attributes_dict:
            file_object.size_in_bytes = attributes_dict.pop('size-in-bytes')
            file_object.size_in_bytes.condition = "Equals"
        if 'entropy' in attributes_dict:
            file_object.peak_entropy = attributes_dict.pop('entropy')
            file_object.peak_entropy.condition = "Equals"
        for key, value in attributes_dict.items():
            if key in hash_type_attributes['single']:
                file_object.add_hash(Hash(hash_value=value, exact=True))

    @staticmethod
    def fetch_colors(tags):
        colors = []
        for tag in tags:
            if tag['name'].startswith("tlp:") and tag['name'].count(':') == 1:
                colors.append(tag['name'][4:].upper())
        return colors

    @staticmethod
    def fetch_ids_flags(attributes):
        for attribute in attributes:
            if attribute.to_ids:
                return True
        return False

    @staticmethod
    def merge_tags(tags, attribute):
        result = deepcopy(tags)
        if attribute.Tag:
            if 'attributes' in tags:
                for tag in attribute.Tag:
                    result['attributes'].append(tag)
            else:
                result['attributes'] = attribute.Tag
        return result

    @staticmethod
    def parse_src_dst_args(attributes_dict):
        src_args = {}
        for relation in ('ip-src', 'src-port', 'hostname-src'):
            if relation in attributes_dict:
                src_args[relation] = attributes_dict[relation]
        dst_args = {}
        for relation in ('ip-dst', 'dst-port', 'hostname-dst'):
            if relation in attributes_dict:
                dst_args[relation] = attributes_dict[relation]
        return src_args, dst_args

    @staticmethod
    def resolve_filename(file_object, filename):
        if '/' in filename or '\\' in filename:
            file_object.file_path = ntpath.dirname(filename)
            file_object.file_path.condition = "Equals"
            file_object.file_name = ntpath.basename(filename)
            file_object.file_name.condition = "Equals"
        else:
            file_object.file_name = filename
            file_object.file_name.condition = "Equals"

    @staticmethod
    def resolve_reg_hive(reg):
        reg = reg.lstrip('\\')
        upper_reg = reg.upper()
        for hive in misp_reghive:
            if upper_reg.startswith(hive):
                return misp_reghive[hive], reg[len(hive):].lstrip('\\').replace('\\\\', '\\')
        return None, reg

    @staticmethod
    def set_color(colors):
        tlp_color = 0
        color = None
        for color in colors:
            color_num = TLP_order[color]
            if color_num > tlp_color:
                tlp_color = color_num
                color_value = color
        return color_value

    @staticmethod
    def set_prod(org):
        identity = Identity(name=org)
        information_source = InformationSource(identity=identity)
        return information_source

    def set_src(self):
        identity = Identity(name=self.misp_event.Org.get('name'))
        information_source = InformationSource(identity=identity)
        return information_source

def main(args):
    stix_builder = StixBuilder(args)
    stix_builder.loadEvent()
    stix_builder.generateEventPackage()
    stix_builder.saveFile()
    print(json.dumps({'success': 1, 'message': ''}))

if __name__ == "__main__":
    main(sys.argv)
