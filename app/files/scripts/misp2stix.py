import sys, json, uuid, os, time, datetime, re, ntpath, socket
import pymisp
from copy import deepcopy
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.indicator.valid_time import ValidTime
from stix.ttp import TTP, Behavior
from stix.ttp.malware_instance import MalwareInstance
from stix.incident import Incident, Time, ImpactAssessment, ExternalID, AffectedAsset
from stix.exploit_target import ExploitTarget, Vulnerability
from stix.incident.history import JournalEntry, History, HistoryItem
from stix.threat_actor import ThreatActor
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource, Identity, Confidence
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.common.related import *
from stix.common.confidence import Confidence
from stix.common.vocabs import IncidentStatus
from cybox.utils import Namespace
from cybox.core import Object, Observable, ObservableComposition
from cybox.objects.file_object import File
from cybox.objects.address_object import Address
from cybox.objects.port_object import Port
from cybox.objects.hostname_object import Hostname
from cybox.objects.uri_object import URI
from cybox.objects.pipe_object import Pipe
from cybox.objects.mutex_object import Mutex
from cybox.objects.artifact_object import Artifact
from cybox.objects.memory_object import Memory
from cybox.objects.email_message_object import EmailMessage, EmailHeader, Attachments
from cybox.objects.domain_name_object import DomainName
from cybox.objects.win_registry_key_object import *
from cybox.objects.system_object import System, NetworkInterface, NetworkInterfaceList
from cybox.objects.http_session_object import *
from cybox.objects.as_object import AutonomousSystem
from cybox.common import Hash, ByteRun, ByteRuns
from stix.extensions.test_mechanism.snort_test_mechanism import *
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

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'vulnerability', 'attachment']

hash_type_attributes = {"single":["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256", "ssdeep", "imphash", "authentihash", "pehash", "tlsh", "x509-fingerprint-sha1"], "composite": ["filename|md5", "filename|sha1", "filename|sha224", "filename|sha256", "filename|sha384", "filename|sha512", "filename|sha512/224", "filename|sha512/256", "filename|authentihash", "filename|ssdeep", "filename|tlsh", "filename|imphash", "filename|pehash", "malware-sample"]}

# mapping for the attributes that can go through the simpleobservable script
misp_cybox_name = {"domain" : "DomainName", "hostname" : "Hostname", "url" : "URI", "AS" : "AutonomousSystem", "mutex" : "Mutex", "named pipe" : "Pipe", "link" : "URI"}
cybox_name_attribute = {"DomainName" : "value", "Hostname" : "hostname_value", "URI" : "value", "AutonomousSystem" : "number", "Pipe" : "name", "Mutex" : "name"}
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
        self.misp_event = pymisp.MISPEvent()
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
        ## MAPPING FOR ATTRIBUTES
        self.simple_type_to_method = {"port": self.generate_port_observable, "domain|ip": self.generate_domain_ip_observable}
        self.simple_type_to_method.update(dict.fromkeys(hash_type_attributes["single"] + hash_type_attributes["composite"] + ["filename"] + ["attachment"], self.resolve_file_observable))
        self.simple_type_to_method.update(dict.fromkeys(["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"], self.generate_ip_observable))
        self.simple_type_to_method.update(dict.fromkeys(["regkey", "regkey|value"], self.generate_regkey_observable))
        self.simple_type_to_method.update(dict.fromkeys(["hostname", "domain", "url", "AS", "mutex", "named pipe", "link"], self.generate_simple_observable))
        self.simple_type_to_method.update(dict.fromkeys(["email-src", "email-dst", "email-subject", "email-reply-to"], self.resolve_email_observable))
        self.simple_type_to_method.update(dict.fromkeys(["http-method", "user-agent"], self.resolve_http_observable))
        self.simple_type_to_method.update(dict.fromkeys(["pattern-in-file", "pattern-in-traffic", "pattern-in-memory"], self.resolve_pattern_observable))
        self.simple_type_to_method.update(dict.fromkeys(["mac-address"], self.resolve_system_observable))

    def loadEvent(self):
        pathname = os.path.dirname(self.args[0])
        filename = "{}/tmp/{}".format(pathname, self.args[1])
        self.misp_event.load_file(filename)
        self.filename = filename

    def generateEventPackage(self):
        package_name = "{}:STIXPackage-{}".format(namespace[1], self.misp_event.uuid)
        # timestamp = self.get_date_from_timestamp(int(str(self.misp_event.timestamp)))
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
        try:
            outputfile = "{}.out".format(self.filename)
            with open(outputfile, 'w') as f:
                if self.args[2] == 'json':
                    f.write('{"package": %s}' % self.stix_package.to_json())
                else:
                    f.write(self.stix_package.to_xml(include_namespaces=False, include_schemalocs=False,
                                                     encoding=None))
        except:
            print(json.dumps({'success' : 0, 'message' : 'The STIX file could not be written'}))
            sys.exit(1)

    def generate_stix_objects(self):
        incident_id = "{}:incident-{}".format(namespace[1], self.misp_event.uuid)
        incident = Incident(id_=incident_id, title=self.misp_event.info)
        self.set_dates(incident, self.misp_event.date, self.misp_event.publish_timestamp)
        threat_level_name = threat_level_mapping.get(str(self.misp_event.threat_level_id), None)
        if threat_level_name:
            threat_level_s = "Event Threat Level: {}".format(threat_level_name)
            self.add_journal_entry(incident, threat_level_s)
        Tags = {}
        event_tags = self.misp_event.Tag
        if event_tags:
            Tags['event'] = event_tags
        for tag in event_tags:
            tag_name = "MISP Tag: {}".format(tag['name'])
            self.add_journal_entry(incident, tag_name)
        external_id = ExternalID(value=str(self.misp_event.id), source="MISP Event")
        incident.add_external_id(external_id)
        incident_status_name = status_mapping.get(str(self.misp_event.analysis), None)
        if incident_status_name is not None:
            incident.status = IncidentStatus(incident_status_name)
        try:
            incident.handling = self.set_tlp(self.misp_event.distribution, event_tags)
        except:
            pass
        incident.information_source = self.set_src()
        self.orgc_name = self.misp_event.Orgc.get('name')
        incident.reporter = self.set_rep()
        self.ttps = []
        self.resolve_attributes(incident, Tags)
        self.resolve_objects(incident, Tags)
        self.add_related_indicators(incident)
        return incident

    def convert_to_stix_date(self, date):
        # converts a date (YYYY-mm-dd) to the format used by stix
        return datetime.datetime(date.year, date.month, date.day)

    def set_dates(self, incident, date, published):
        timestamp = published
        incident.timestamp = timestamp
        incident_time = Time()
        incident_time.incident_discovery = self.convert_to_stix_date(date)
        incident_time.incident_reported = timestamp
        incident.time = incident_time

    def resolve_attributes(self, incident, tags):
        for attribute in self.misp_event.attributes:
            attribute_type = attribute.type
            if attribute_type in not_implemented_attributes:
                if attribute_type == "snort":
                    self.generate_TM(incident, attribute, tags)
                else:
                    journal_entry = "!Not implemented attribute category/type combination caught! attribute[{}][{}]: {}".format(attribute.category,
                    attribute_type, attribute.value)
                    self.add_journal_entry(incident, journal_entry)
            elif attribute_type in non_indicator_attributes:
                self.handle_non_indicator_attribute(incident, attribute, tags)
            else:
                self.handle_indicator_attribute(incident, attribute, tags)

    def resolve_objects(self, incident, tags):
        for misp_object in self.misp_event.objects:
            tlp_tags = None
            tmp_incident = Incident()
            tlp_tags = deepcopy(tags)
            self.resolve_attributes(tmp_incident, misp_object.attributes, tags)
            indicator = Indicator(timestamp=self.get_date_from_timestamp(int(misp_object.timestamp)))
            indicator.id_ = "{}:MispObject-{}".format(namespace[1], misp_object.uuid)
            self.set_prod(indicator, self.orgc_name)
            for attribute in misp_object.attributes:
                tlp_tags = self.merge_tags(tlp_tags, attribute)
            self.set_tlp(indicator, misp_object.distribution, tlp_tags)
            title = "{} (MISP Object #{})".format(misp_object.name, misp_object.id)
            indicator.title = title
            indicator.description = misp_object.comment if misp_object.comment else title
            indicator.add_indicator_type("Malware Artifacts")
            indicator.add_valid_time_position(ValidTime())
            indicator.observable_composition_operator = "AND"
            for rindicator in tmp_incident.related_indicators:
                if rindicator.item.observable:
                    indicator.add_observable(rindicator.item.observable)
            relatedIndicator = RelatedIndicator(indicator, relationship=misp_object['meta-category'])
            incident.related_indicators.append(relatedIndicator)

    def add_related_indicators(self, incident):
        for rindicator in incident.related_indicators:
            for ttp in self.ttps:
                ittp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
                rindicator.item.add_indicated_ttp(ittp)

    def handle_indicator_attribute(self, incident, attribute, tags):
        if attribute.to_ids:
            indicator = self.generate_indicator(attribute, tags)
            indicator.add_indicator_type("Malware Artifacts")
            try:
                indicator.add_indicator_type(misp_indicator_type[attribute.type])
            except:
                pass
            indicator.add_valid_time_position(ValidTime())
            observable = self.handle_attribute(attribute)
            indicator.add_observable(observable)
            if 'data' in attribute and attribute.type == "malware-sample":
                artifact = self.create_artifact_object(attribute)
                indicator.add_observable(artifact)
            related_indicator = RelatedIndicator(indicator, relationship=attribute.category)
            incident.related_indicators.append(related_indicator)
        else:
            observable = self.handle_attribute(attribute)
            related_observable = RelatedObservable(observable, relationship=attribute.category)
            incident.related_observables.append(related_observable)
            if attribute.data and attribute.type == "malware-sample":
                artifact = self.create_artifact_object(attribute)
                related_artifact = RelatedObservable(artifact)
                incident.related_observables.append(related_artifact)

    def handle_attribute(self, attribute):
        if attribute.type == 'email-attachment':
            observable = self.generate_email_attachment_object(attribute)
        else:
            observable = self.generate_observable(attribute)
        return observable

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
                incident.attributed_threat_actors.append(rta)
            else:
                entry_line = "attribute[{}][{}]: {}".format(attribute_category, attribute_type, attribute.value)
                self.add_journal_entry(incident, entry_line)
        elif attribute_type == "target-machine":
            aa = AffectedAsset()
            description = attribute.value
            if attribute.comment:
                description += " ({})".format(attribute.comment)
            aa.description = description
            incident.affected_assets.append(aa)
        elif attribute_type.startswith('target-'):
            incident.add_victim(self.resolve_identity_attribute(attribute))
        elif attribute_type == "attachment":
            observable = self.return_attachment_composition(attribute)
            related_observable = RelatedObservable(observable,  relationship=attribute.category)
            incident.related_observables.append(related_observable)

    def create_artifact_object(self, attribute, artifact=None):
        try:
            artifact = Artifact(data=bytes(attribute.data, encoding='utf-8'))
        except TypeError:
            artifact = Artifact(data=bytes(attribute.data))
        artifact.parent.id_ = "{}:ArtifactObject-{}".format(self.namespace_prefix, attribute.uuid)
        observable = Observable(artifact)
        id_type = "observable"
        if artifact is not None:
            id_type += "-artifact"
        observable.id_ = "{}:{}-{}".format(self.namespace_prefix, id_type, attribute.uuid)
        return observable

    def generate_domain_ip_observable(self, attribute):
        domain, ip = attribute.value.split('|')
        address_object = self.resolve_ip_type(attribute.type, ip)
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

    def generate_email_attachment_object(self, attribute):
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
        observable.id_ = "{}:observable-{}".format(self.namespace_prefix, attribute_uuid)
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
        address_object = self.resolve_ip_type(attribute.type, attribute.value)
        address_object.parent.id_ = "{}:AddressObject-{}".format(self.namespace_prefix, attribute.uuid)
        if '|' in attribute.value:
            port = attribute.value.split('|')[1]
            address_observable = Observable(address_object)
            address_observable.id_ = "{}:Address-{}".format(self.namespace_prefix, attribute.uuid)
            port_object = Port()
            port_object.port_value = port
            port_object.port_value.condition = "Equals"
            port_object.parent.id_ = "{}:PortObject-{}".format(self.namespace_prefix, attribute.uuid)
            port_observable = Observable(port_object)
            port_observable.id_ = "{}:Port-{}".format(self.namespace_prefix, attribute.uuid)
            compositeObject = ObservableComposition(observables=[address_observable, port_observable])
            compositeObject.operator = "AND"
            observable = Observable(id_ = "{}:ObservableComposition-{}".format(self.namespace_prefix, attribute.uuid))
            observable.observable_composition = compositeObject
            return observable
        else:
            return address_object

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
        port_object = Port()
        port_object.port_value = attribute.value
        port_object.port_value.condition = "Equals"
        port_object.parent.id_ = "{}:PortObject-{}".format(self.namespace_prefix, attribute.uuid)
        return port_object

    def generate_regkey_observable(self, attribute, value=None):
        if attribute.type == "regkey|value":
            regkey, value = attribute.value.split('|')
        else:
            regkey = attribute.value
        reghive, regkey = self.resolve_reg_hive(regkey)
        reg_object = WinRegistryKey()
        reg_object.key = regkey
        reg_object.key.condition = "Equals"
        if reghive:
            reg_object.hive = reghive
            reg_object.hive.condition = "Equals"
        if value:
            reg_value_object = RegistryValue()
            reg_value_object.data = value
            reg_value_object.data.condition = "Equals"
            reg_object.values = RegistryValues(reg_value_object)
        return reg_object

    @staticmethod
    def generate_simple_observable(attribute):
        cybox_name = misp_cybox_name[attribute.type]
        if cybox_name == "AutonomousSystem":
            if not attribute.value.isdigit():
                return False
        constructor = getattr(this_module, cybox_name, None)
        new_object = constructor()
        setattr(new_object, cybox_name_attribute[cybox_name], attribute.value)
        setattr(getattr(new_object, cybox_name_attribute[cybox_name]), "condition", "Equals")
        return new_object

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
            indicator.test_mechanisms = [tm]
            related_indicator = RelatedIndicator(indicator, relationship=category)
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

    @staticmethod
    def resolve_email_observable(attribute):
        attribute_type = attribute.type
        new_object = EmailMessage()
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
        new_object.header = email_header
        return new_object

    def resolve_file_observable(self, attribute):
        fuzzy = False
        f, h = [""] * 2
        attribute_type = attribute.type
        if attribute_type in hash_type_attributes['composite']:
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
        return self.generate_file_observable(f, h, fuzzy)

    @staticmethod
    def resolve_http_observable(attribute):
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
        new_object = HTTPSession()
        request_response.to_xml()
        new_object.http_request_response = [request_response]
        return new_object

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

    @staticmethod
    def resolve_pattern_observable(attribute):
        if attribute.type == "pattern-in-file":
            byte_run = ByteRun()
            byte_run.byte_run_data = attribute.value
            new_object = File()
            new_object.byte_runs = ByteRuns(byte_run)
            return new_object
        return None

    @staticmethod
    def resolve_system_observable(attribute):
        system_object = System()
        network_interface = NetworkInterface()
        network_interface.mac = attribute.value
        network_interface_list = NetworkInterfaceList()
        network_interface_list.append(network_interface)
        system_object.network_interface_list = network_interface_list
        return system_object

    def return_attachment_composition(self, attribute):
        file_object = File()
        file_object.file_name = attribute.value
        file_object.parent.id_ = "{}:FileObject-{}".format(self.namespace_prefix, attribute.uuid)
        if 'data' in attribute:
            observable_artifact = self.create_artifact_object(attribute, artifact="a")
            observable_file = Observable(file_object)
            observable_file.id_ = "{}:observable-file-{}".format(self.namespace_prefix, attribute.uuid)
            observable = Observable()
            composition = ObservableComposition(observables=[observable_artifact, observable_file])
            observable.observable_composition = composition
        else:
            observable = Observable(file_object)
        observable.id_ = "{}:observable-{}".format(self.namespace_prefix, attribute.uuid)
        if attribute.comment:
            observable.description = attribute.comment
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
                color = TLP_mapping.get(str(self.misp_event.distribution), None)
        if color is None:
            return
        tlp.color = color
        marking_specification.marking_structures.append(tlp)
        handling = Marking()
        handling.add_marking(marking_specification)
        return handling

    @staticmethod
    def add_journal_entry(incident, entry_line):
        hi = HistoryItem()
        hi.journal_entry = entry_line
        try:
            incident.history.append(hi)
        except AttributeError:
            incident.history = History(hi)

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
        except:
            pass
        ttp.title = "{}: {} (MISP Attribute #{})".format(attribute.category, attribute.value, attribute.id)
        return ttp

    @staticmethod
    def get_date_from_timestamp(timestamp):
        # converts timestamp to the format used by STIX
        return "{}+00:00".format(datetime.datetime.fromtimestamp(timestamp).isoformat())

    @staticmethod
    def fetch_colors(tags):
        colors = []
        for tag in tags:
            if tag['name'].startswith("tlp:") and tag['name'].count(':') == 1:
                colors.append(tag['name'][4:].upper())
        return colors

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
    def resolve_ip_type(attribute_type, attribute_value):
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
