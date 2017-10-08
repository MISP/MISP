import sys, json, uuid, os, time, datetime, re
from misp2cybox import *
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
# if you rely on old idgen from previous stix libraries, mixbox is not installed
try:
    from stix.utils import idgen
except ImportError:
    from mixbox import idgen

from stix import __version__ as STIXVER

NS_DICT = {
        "http://cybox.mitre.org/common-2" : 'cyboxCommon',
        "http://cybox.mitre.org/cybox-2" : 'cybox',
        "http://cybox.mitre.org/default_vocabularies-2" : 'cyboxVocabs',
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
	'http://cybox.mitre.org/objects#ASObject-1': 'http://cybox.mitre.org/XMLSchema/objects/AS/1.0/AS_Object.xsd',
	'http://cybox.mitre.org/objects#AddressObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Address/2.1/Address_Object.xsd',
	'http://cybox.mitre.org/objects#DomainNameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd',
	'http://cybox.mitre.org/objects#EmailMessageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.1/Email_Message_Object.xsd',
	'http://cybox.mitre.org/objects#FileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd',
	'http://cybox.mitre.org/objects#HTTPSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/HTTP_Session/2.1/HTTP_Session_Object.xsd',
	'http://cybox.mitre.org/objects#HostnameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Hostname/1.0/Hostname_Object.xsd',
	'http://cybox.mitre.org/objects#MutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Mutex/2.1/Mutex_Object.xsd',
	'http://cybox.mitre.org/objects#PipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Pipe/2.1/Pipe_Object.xsd',
	'http://cybox.mitre.org/objects#URIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd',
	'http://cybox.mitre.org/objects#WinRegistryKeyObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd',
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


def main(args):
    if len(sys.argv) < 4:
        sys.exit("Invalid parameters")

    baseURL = sys.argv[1]
    orgname = sys.argv[2]

    namespace = [baseURL, orgname.replace(" ", "_")]
    namespace[1] = re.sub('[\W]+', '', namespace[1])
    NS_DICT[namespace[0]]=namespace[1]

    try:
        idgen.set_id_namespace({baseURL: namespace[1]})
    except ValueError:
        # Some weird stix error that sometimes occurs if the stars
        # align and Mixbox is being mean to us
        # Glory to STIX, peace and good xmlns be upon it
        try:
            idgen.set_id_namespace(Namespace(baseURL, namespace[1]))
        except TypeError:
            # Ok this only occurs if the script is being run under py3
            # and if we're running a REALLY weird version of stix
            # May as well catch it
            idgen.set_id_namespace(Namespace(baseURL, namespace[1], "MISP"))


    stix_package = STIXPackage()
    stix_header = STIXHeader()

    stix_header.title="Export from " + orgname + " MISP"
    stix_header.package_intents="Threat Report"
    stix_package.stix_header = stix_header

    if sys.argv[3] == 'json':
        stix_string = stix_package.to_json()[:-1]
        stix_string += ', "related_packages": ['
    else:
        stix_string = stix_package.to_xml(auto_namespace=False, ns_dict=NS_DICT, schemaloc_dict=SCHEMALOC_DICT)
        stix_string = stix_string.decode()
        stix_string = stix_string.replace("</stix:STIX_Package>\n", "");
    print(stix_string)

if __name__ == "__main__":
    main(sys.argv)
