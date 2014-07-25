import sys, json, uuid, os, time, datetime
from misp2cybox import *
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.ttp import TTP, Behavior
from stix.ttp.malware_instance import MalwareInstance
from stix.incident import Incident, Time, ImpactAssessment
from stix.threat_actor import ThreatActor
from stix.incident import ExternalID
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource, Identity, Confidence
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.common.related import *
from stix.common.confidence import Confidence
from stix.common.vocabs import IncidentStatus

# mappings
status_mapping = {'0' : 'New', '1' : 'Open', '2' : 'Closed'}
TLP_mapping = {'0' : 'AMBER', '1' : 'GREEN', '2' : 'GREEN', '3' : 'GREEN'}
confidence_mapping = {'0' : 'None', '1' : 'High'}

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email', 'target-machine', 'target-org', 'taget-location', 'target-external', 'email-target']

#special_type_category_method = {('link', 'Antivirus detection') : "generateIncidentReference"}
#special_type_category_method.update(dict.fromkeys([("comment", "Payload type"), ("text", "Payload type"), ("comment", "Payload type")], "generateIPObservable"))


# Load the array from MISP. MISP will call this script with a parameter containing the temporary file it creates for the export (using a generated 12 char alphanumeric name)
# return ERROR:1 if the file cannot be read or decoded
def loadEvent(args, pathname):
    try:
        filename = pathname + "/tmp/" + args[1]
        tempFile = open(filename, 'r')
        events = json.loads(tempFile.read())
        return events
    except:
        print "ERROR:1"
        sys.exit(1)

#generate a package that will contain all of the event-packages
def generateMainPackage(events):
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title="Export from MISP"
    stix_header.package_intents="Collective Threat Intelligence"
    stix_package.stix_header = stix_header
    return stix_package

# generate a package for each event
def generateEventPackage(event):
    package_name = 'example:STIXPackage-' + event["Event"]["uuid"]
    stix_package = STIXPackage(id_=package_name)
    stix_header = STIXHeader()
    stix_header.title="MISP event #" + event["Event"]["id"]
    stix_header.package_intents="Collective Threat Intelligence"
    stix_package.stix_header = stix_header
    objects = generateSTIXObjects(event)
    incident = objects[0]
    incident = setTLP(incident, event["Event"]["distribution"])
    ttps = objects[1]
    stix_package.add_incident(incident)
    for ttp in ttps:
        stix_package.add_ttp(ttp)
    return stix_package

# generate the incident information. MISP events are currently mapped to incidents with the event metadata being stored in the incident information
def generateSTIXObjects(event):
    incident = Incident(id_ = "example:STIXPackage-" + event["Event"]["uuid"], description=event["Event"]["info"])
    incident = setDates(incident, event["Event"]["date"], int(event["Event"]["publish_timestamp"]))
    ttps = []
    external_id = ExternalID(value=event["Event"]["id"], source="MISP Event")
    incident.add_external_id(external_id)
    incident_status_name = status_mapping.get(event["Event"]["analysis"], None)
    if incident_status_name is not None:
        incident.status = IncidentStatus(incident_status_name)
    incident = setTLP(incident, event["Event"]["distribution"])
    incident = setSources(incident, event["Event"]["org"], event["Event"]["id"])
    objects = resolveAttributes(incident, ttps, event["Attribute"])
    incident = objects[0]
    ttps = objects[1]
    return [incident, ttps]


# set up the dates for the incident
def setDates(incident, date, published):
    timestamp=getDateFromTimestamp(published)
    incident.timestamp=timestamp
    incident_time = Time()
    incident_time.incident_discovery = convertToStixDate(date)
    incident_time.incident_reported = timestamp
    incident.time = incident_time
    return incident

# decide what to do with the attribute, as not all of them will become indicators
def resolveAttributes(incident, ttps, attributes):
    for attribute in attributes:
        if (attribute["type"] in non_indicator_attributes):
            #types that will definitely not become indicators
            objects = handleNonIndicatorAttribute(incident, ttps, attribute)
            incident = objects[0]
            ttps = objects[1]
        else:
            #types that may become indicators
            objectRelationship = attribute["category"]
            indicator = generateIndicator(attribute)
            indicator.title = "MISP attribute #" + attribute["id"]
            indicator=generateObservable(indicator, attribute)
            relatedIndicator = RelatedIndicator(indicator, relationship=objectRelationship)
            incident.related_indicators.append(relatedIndicator)
    return [incident, ttps]


def handleNonIndicatorAttribute(incident, ttps, attribute):
    if attribute["type"] in ("comment", "text", "other"):
        if attribute["category"] == "Payload type":
            ttp = generateTTP(attribute)
            ttps.append(ttp)
            relatedTTP = RelatedTTP(TTP(idref=ttp.id_), relationship="Uses Malware")
            incident.leveraged_ttps.append(relatedTTP)
       # elif attribute["category"] == "Attribution":
           # ta = generateThreatActor(attribute)
            #relatedTTP
        #else:
    return [incident, ttps]

# TTPs are only used to describe malware names currently (attribute with category Payload Type and type text/comment/other)
def generateTTP(attribute):
    ttp = TTP()
    ttp.id_="example:indicator-" + attribute["uuid"]
    ttp = setTLP(ttp, attribute["distribution"])
    ttp.title = "MISP attribute #" + attribute["id"]
    # here comes the part that is specific to this cat/type combination, branch it out in the future if we want to store other types in here
    malware = MalwareInstance()
    malware.add_name(attribute["value"])
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(malware)
    return ttp

# Threat actors are currently only used for the category:attribution / type:(text|comment|other) attributes 
def generateThreatActor(attribute):
    ta = ThreatActor()
    ta.id_="example:threatactor-" + attribute["uuid"]
    ta.title = attribute["value"]
    return ta

# generate the indicator and add the relevant information
def generateIndicator(attribute):
    indicator = Indicator()
    indicator.id_="example:indicator-" + attribute["uuid"]
    indicator = setTLP(indicator, attribute["distribution"])
    indicator.information_source = setSourceDescription("Attribute", attribute["id"])
    confidence_description = "Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none"
    confidence_value = confidence_mapping.get(attribute["to_ids"], None)
    if confidence_value is None:
        return indicator
    indicator.confidence = Confidence(value=confidence_value, description=confidence_description)
    return indicator

# converts timestamp to the format used by STIX
def getDateFromTimestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).isoformat()

# converts a date (YYYY-mm-dd) to the format used by stix
def convertToStixDate(date):
    return getDateFromTimestamp(time.mktime(datetime.datetime.strptime(date, "%Y-%m-%d").timetuple()))

# takes an object and adds the passed organisation as the information_source.identity to it. 
def setSources(target, org, event_id):
    ident = Identity(name=org)
    information_source = setSourceDescription("Event", event_id)
    information_source.identity = ident
    target.information_source = information_source
    return target

def setSourceDescription(sourceObject, sourceID):
    return InformationSource(description = "MISP " + sourceObject + " #" + sourceID)

# takes an object and applies a TLP marking based on the distribution passed along to it
# Careful: Incidents do not have handling currently
def setTLP(target, distribution):
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "../../../descendant-or-self()"
    tlp = TLPMarkingStructure()
    colour = TLP_mapping.get(distribution, None)
    if colour is None:
        return target
    tlp.color = colour
    marking_specification.marking_structures.append(tlp)
    handling = Marking()
    handling.add_marking(marking_specification)
    target.handling = handling
    return target

# main
def main(args):
    pathname = os.path.dirname(sys.argv[0])
    events = loadEvent(args, pathname)
    stix_package = generateMainPackage(events)
    for event in events:
        sub_package = generateEventPackage(event)
        #stix_package.related_packages.append(sub_package)
    #print(stix_package.to_xml()) 
    print(sub_package.to_xml())
    #print(sub_package.to_json())

if __name__ == "__main__":
    main(sys.argv)

