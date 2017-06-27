import sys, json, uuid, os, time, datetime, re
from misp2cybox import *
from misp2ciq import *
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

try:
    from stix.utils import idgen
except ImportError:
    from mixbox import idgen

namespace = ['https://github.com/MISP/MISP', 'MISP']

# mappings
status_mapping = {'0' : 'New', '1' : 'Open', '2' : 'Closed'}
TLP_mapping = {'0' : 'AMBER', '1' : 'GREEN', '2' : 'GREEN', '3' : 'GREEN'}
confidence_mapping = {False : 'None', True : 'High'}

not_implemented_attributes = ['yara', 'pattern-in-traffic', 'pattern-in-memory']	

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'email-target', 'vulnerability', 'attachment']

# Load the array from MISP. MISP will call this script with a parameter containing the temporary file it creates for the export (using a generated 12 char alphanumeric name)
def loadEvent(args, pathname):
    try:
        filename = pathname + "/tmp/" + args[1]
        tempFile = open(filename, 'r')
        events = json.loads(tempFile.read())
        return events
    except:
        print(json.dumps({'success' : 0, 'message' : 'The temporary MISP export file could not be read'}))
        sys.exit(1)

def saveFile(args, pathname, package):
    try:
        filename = pathname + "/tmp/" + args[1] + ".out"
        with open(filename, 'w') as f:
            if args[2] == 'json':
                f.write('{"package": ' + package.to_json() + "}")
            else:
                f.write(package.to_xml(include_namespaces=False, include_schemalocs=False))
    except:
        print(json.dumps({'success' : 0, 'message' : 'The STIX file could not be written'}))
        sys.exit(1)

#generate a package that will contain all of the event-packages
def generateMainPackage(events):
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title="Export from " + namespace[1] + " MISP"
    stix_header.package_intents="Threat Report"
    stix_package.stix_header = stix_header
    return stix_package

# generate a package for each event
def generateEventPackage(event):
    package_name = namespace[1] + ':STIXPackage-' + event["Event"]["uuid"]
    timestamp = getDateFromTimestamp(int(event["Event"]["timestamp"]))
    stix_package = STIXPackage(id_=package_name, timestamp=timestamp)
    stix_header = STIXHeader()
    stix_header.title=event["Event"]["info"] + " (MISP Event #" + event["Event"]["id"] + ")"
    stix_header.package_intents="Threat Report"
    stix_package.stix_header = stix_header
    objects = generateSTIXObjects(event)
    incident = objects[0]
    ttps = objects[1]
    stix_package.add_incident(incident)
    for ttp in ttps:
        stix_package.add_ttp(ttp)
    return stix_package

# generate the incident information. MISP events are currently mapped to incidents with the event metadata being stored in the incident information
def generateSTIXObjects(event):
    incident = Incident(id_ = namespace[1] + ":incident-" + event["Event"]["uuid"], title=event["Event"]["info"])
    setDates(incident, event["Event"]["date"], int(event["Event"]["publish_timestamp"]))
    addJournalEntry(incident, "Event Threat Level: " + event["ThreatLevel"]["name"])
    ttps = []
    external_id = ExternalID(value=event["Event"]["id"], source="MISP Event")
    incident.add_external_id(external_id)
    incident_status_name = status_mapping.get(event["Event"]["analysis"], None)
    if incident_status_name is not None:
        incident.status = IncidentStatus(incident_status_name)
    setTLP(incident, event["Event"]["distribution"])
    setOrg(incident, event["Org"]["name"])
    setTag(incident, event["Tag"])
    resolveAttributes(incident, ttps, event["Attribute"])
    return [incident, ttps]


# set up the dates for the incident
def setDates(incident, date, published):
    timestamp=getDateFromTimestamp(published)
    incident.timestamp=timestamp
    incident_time = Time()
    incident_time.incident_discovery = convertToStixDate(date)
    incident_time.incident_reported = timestamp
    incident.time = incident_time

# decide what to do with the attribute, as not all of them will become indicators
def resolveAttributes(incident, ttps, attributes):
    for attribute in attributes:
        if (attribute["type"] in not_implemented_attributes):
            addJournalEntry(incident, "!Not implemented attribute category/type combination caught! attribute[" + attribute["category"] + "][" + attribute["type"] + "]: " + attribute["value"])
        elif (attribute["type"] in non_indicator_attributes):
            #types that will definitely not become indicators
            handleNonIndicatorAttribute(incident, ttps, attribute)
        else:
            #types that may become indicators
            handleIndicatorAttribute(incident, ttps, attribute)
    for rindicator in incident.related_indicators:
        for ttp in ttps:
            ittp=TTP(idref=ttp.id_, timestamp=ttp.timestamp)
            rindicator.item.add_indicated_ttp(ittp)
    return [incident, ttps]

# Create the indicator and pass the attribute further for observable creation - this can be called from resolveattributes directly or from handleNonindicatorAttribute, for some special cases
def handleIndicatorAttribute(incident, ttps, attribute):
    indicator = generateIndicator(attribute)
    indicator.add_indicator_type("Malware Artifacts")
    indicator.add_valid_time_position(ValidTime())
    if attribute["type"] == "email-attachment":
        indicator.add_indicator_type("Malicious E-mail")
        generateEmailAttachmentObject(indicator, attribute)
    else:
        generateObservable(indicator, attribute)
    if "data" in attribute:
        if attribute["type"] == "malware-sample":
            createArtifactObject(indicator, attribute)
    relatedIndicator = RelatedIndicator(indicator, relationship=attribute["category"])
    incident.related_indicators.append(relatedIndicator)

# Handle the attributes that do not fit into an indicator
def handleNonIndicatorAttribute(incident, ttps, attribute):
    if attribute["type"] in ("comment", "text", "other"):
        if attribute["category"] == "Payload type":
            generateTTP(incident, attribute, ttps)
        elif attribute["category"] == "Attribution":
            ta = generateThreatActor(attribute)
            rta = RelatedThreatActor(ta, relationship="Attribution")
            incident.attributed_threat_actors.append(rta)
        else:
            entry_line = "attribute[" + attribute["category"] + "][" + attribute["type"] + "]: " + attribute["value"]
            addJournalEntry(incident, entry_line)
    elif attribute["type"] == "target-machine":
        aa = AffectedAsset()
        if attribute["comment"] != "":
            aa.description = attribute["value"] + " (" + attribute["comment"] + ")"
        else:
            aa.description = attribute["value"]
        incident.affected_assets.append(aa)
    elif attribute["type"] == "vulnerability":
        generateTTP(incident, attribute, ttps)
    elif attribute["type"] == "link":
        if attribute["category"] == "Payload delivery":
            handleIndicatorAttribute(incident, ttps, attribute)
        else:
            addReference(incident, attribute["value"])
    elif attribute["type"].startswith('target-'):
        resolveIdentityAttribute(incident, attribute, namespace[1])
    elif attribute["type"] == "attachment":
        observable = returnAttachmentComposition(attribute)
        related_observable = RelatedObservable(observable, relationship=attribute["category"])
        incident.related_observables.append(related_observable)
    return [incident, ttps]

# TTPs are only used to describe malware names currently (attribute with category Payload Type and type text/comment/other)
def generateTTP(incident, attribute, ttps):
    ttp = TTP(timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    ttp.id_= namespace[1] + ":ttp-" + attribute["uuid"]
    setTLP(ttp, attribute["distribution"])
    ttp.title = attribute["category"] + ": " + attribute["value"] + " (MISP Attribute #" + attribute["id"] + ")"
    if attribute["type"] == "vulnerability":
        vulnerability = Vulnerability()
        vulnerability.cve_id = attribute["value"]
        et = ExploitTarget(timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
        et.id_= namespace[1] + ":et-" + attribute["uuid"]
        if attribute["comment"] != "" and attribute["comment"] != "Imported via the freetext import.":
            et.title = attribute["comment"]
        else:
            et.title = "Vulnerability " + attribute["value"]
        et.add_vulnerability(vulnerability)
        ttp.exploit_targets.append(et)
    else:
        malware = MalwareInstance()
        malware.add_name(attribute["value"])
        ttp.behavior = Behavior()
        ttp.behavior.add_malware_instance(malware)
    if attribute["comment"] != "":
        ttp.description = attribute["comment"]
    ttps.append(ttp)
    rttp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
    relatedTTP = RelatedTTP(rttp, relationship=attribute["category"])
    incident.leveraged_ttps.append(relatedTTP)

# Threat actors are currently only used for the category:attribution / type:(text|comment|other) attributes
def generateThreatActor(attribute):
    ta = ThreatActor(timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    ta.id_= namespace[1] + ":threatactor-" + attribute["uuid"]
    ta.title = attribute["category"] + ": " + attribute["value"] + " (MISP Attribute #" + attribute["id"] + ")"
    if attribute["comment"] != "":
        ta.description = attribute["value"] + " (" + attribute["comment"] + ")"
    else:
        ta.description = attribute["value"]
    return ta

# generate the indicator and add the relevant information
def generateIndicator(attribute):
    indicator = Indicator(timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    indicator.id_= namespace[1] + ":indicator-" + attribute["uuid"]
    if attribute["comment"] != "":
        indicator.description = attribute["comment"]
    setTLP(indicator, attribute["distribution"])
    indicator.title = attribute["category"] + ": " + attribute["value"] + " (MISP Attribute #" + attribute["id"] + ")"
    indicator.description = indicator.title
    confidence_description = "Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none"
    confidence_value = confidence_mapping.get(attribute["to_ids"], None)
    if confidence_value is None:
        return indicator
    indicator.confidence = Confidence(value=confidence_value, description=confidence_description, timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    return indicator

# converts timestamp to the format used by STIX
def getDateFromTimestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).isoformat() + "+00:00"

# converts a date (YYYY-mm-dd) to the format used by stix
def convertToStixDate(date):
    return getDateFromTimestamp(time.mktime(datetime.datetime.strptime(date, "%Y-%m-%d").timetuple()))

# takes an object and adds the passed organisation as the information_source.identity to it.
def setOrg(target, org):
    ident = Identity(name=org)
    information_source = InformationSource(identity = ident)
    target.information_source = information_source

# takes an object and adds the passed tags as journal entries to it.
def setTag(target, tags):
    for tag in tags:
        addJournalEntry(target, "MISP Tag: " + tag["name"])

def addReference(target, reference):
    if hasattr(target.information_source, "references"):
        target.information_source.add_reference(reference)

# takes an object and applies a TLP marking based on the distribution passed along to it
def setTLP(target, distribution):
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "../../../descendant-or-self::node()"
    tlp = TLPMarkingStructure()
    colour = TLP_mapping.get(distribution, None)
    if colour is None:
        return target
    tlp.color = colour
    marking_specification.marking_structures.append(tlp)
    handling = Marking()
    handling.add_marking(marking_specification)
    target.handling = handling

# add a journal entry to an incident
def addJournalEntry(incident, entry_line):
    hi = HistoryItem()
    hi.journal_entry = entry_line
    incident.history.append(hi)

# main
def main(args):
    pathname = os.path.dirname(sys.argv[0])
    if len(sys.argv) > 3:
        namespace[0] = sys.argv[3]
    if len(sys.argv) > 4:
        namespace[1] = sys.argv[4].replace(" ", "_")
        namespace[1] = re.sub('[\W]+', '', namespace[1])
    try:
        idgen.set_id_namespace({namespace[0]: namespace[1]})
    except ValueError:
        try:
            idgen.set_id_namespace(Namespace(namespace[0], namespace[1]))
        except TypeError:
            idgen.set_id_namespace(Namespace(namespace[0], namespace[1], "MISP"))

    event = loadEvent(args, pathname)
    stix_package = generateEventPackage(event)
    saveFile(args, pathname, stix_package)
    print(json.dumps({'success' : 1, 'message' : ''}))

if __name__ == "__main__":
    main(sys.argv)
