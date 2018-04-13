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
from cybox.common import Hash, ByteRun, ByteRuns
from cybox.objects.http_session_object import *
from cybox.objects.as_object import AutonomousSystem
from stix.extensions.test_mechanism.snort_test_mechanism import *
import ntpath, socket, sys
from stix.indicator import Indicator

this_module = sys.modules[__name__]

hash_type_attributes = {"single":["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256", "ssdeep", "imphash", "authentihash", "pehash", "tlsh", "x509-fingerprint-sha1"], "composite": ["filename|md5", "filename|sha1", "filename|sha224", "filename|sha256", "filename|sha384", "filename|sha512", "filename|sha512/224", "filename|sha512/256", "filename|authentihash", "filename|ssdeep", "filename|tlsh", "filename|imphash", "filename|pehash", "malware-sample"]}

simple_type_to_method = {}
simple_type_to_method.update(dict.fromkeys(hash_type_attributes["single"] + hash_type_attributes["composite"] + ["filename"] + ["attachment"], "resolveFileObservable"))
simple_type_to_method.update(dict.fromkeys(["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"], "generateIPObservable"))
simple_type_to_method.update(dict.fromkeys(["port"], "generatePortObservable"))
simple_type_to_method.update(dict.fromkeys(["domain|ip"], "generateDomainIPObservable"))
simple_type_to_method.update(dict.fromkeys(["regkey", "regkey|value"], "generateRegkeyObservable"))
simple_type_to_method.update(dict.fromkeys(["hostname", "domain", "url", "AS", "mutex", "named pipe", "link"], "generateSimpleObservable"))
simple_type_to_method.update(dict.fromkeys(["email-src", "email-dst", "email-subject"], "resolveEmailObservable"))
simple_type_to_method.update(dict.fromkeys(["http-method", "user-agent"], "resolveHTTPObservable"))
simple_type_to_method.update(dict.fromkeys(["pattern-in-file", "pattern-in-traffic", "pattern-in-memory"], "resolvePatternObservable"))

# mapping for the attributes that can go through the simpleobservable script
misp_cybox_name = {"domain" : "DomainName", "hostname" : "Hostname", "url" : "URI", "AS" : "AutonomousSystem", "mutex" : "Mutex", "named pipe" : "Pipe", "link" : "URI"}
cybox_name_attribute = {"DomainName" : "value", "Hostname" : "hostname_value", "URI" : "value", "AutonomousSystem" : "number", "Pipe" : "name", "Mutex" : "name"}
misp_indicator_type = {"domain" : "Domain Watchlist", "hostname" : "Domain Watchlist", "url" : "URL Watchlist", "AS" : "", "mutex" : "Host Characteristics", "named pipe" : "Host Characteristics", "link" : ""}
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

def generateObservable(indicator, attribute):
    if (attribute["type"] in ("snort", "yara")):
        generateTM(indicator, attribute)
    else:
        observable = None;
        if (attribute["type"] in simple_type_to_method.keys()):
            action = getattr(this_module, simple_type_to_method[attribute["type"]], None)
            if (action != None):
                property = action(indicator, attribute)
                if property is False:
                    return False
                if isinstance(property, Observable):
                    return indicator.add_observable(property)
                property.condition = "Equals"
                object = Object(property)
                object.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":" + property.__class__.__name__ + "-" + attribute["uuid"]
                observable = Observable(object)
                observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":observable-" + attribute["uuid"]
                indicator.add_observable(observable)

def resolveFileObservable(indicator, attribute):
    hashValue = ""
    filenameValue = ""
    fuzzy = False
    if (attribute["type"] in hash_type_attributes["composite"]):
        values = attribute["value"].split('|')
        filenameValue = values[0]
        hashValue = values[1]
        indicator.add_indicator_type("File Hash Watchlist")
        composite = attribute["type"].split('|')
        if (len(composite) > 1 and composite[1] == "ssdeep"):
          fuzzy = True
    else:
        if (attribute["type"] in ("filename", "attachment")):
            filenameValue = attribute["value"]
        else:
            hashValue = attribute["value"]
            indicator.add_indicator_type("File Hash Watchlist")
            if (attribute["type"] == "ssdeep"):
              fuzzy = True
    observable = generateFileObservable(filenameValue, hashValue, fuzzy)
    return observable

def generateFileObservable(filenameValue, hashValue, fuzzy):
    file_object = File()
    if (filenameValue != ""):
        if (("/" in filenameValue) or ("\\" in filenameValue)):
            file_object.file_path = ntpath.dirname(filenameValue)
            file_object.file_path.condition = "Equals"
            file_object.file_name = ntpath.basename(filenameValue)
            file_object.file_name.condition = "Equals"
        else:
            file_object.file_name = filenameValue
            file_object.file_name.condition = "Equals"
    if (hashValue != ""):
        file_object.add_hash(Hash(hash_value=hashValue, exact=True))
        if (fuzzy):
            file_object._fields["Hashes"]._inner[0].simple_hash_value = None
            file_object._fields["Hashes"]._inner[0].fuzzy_hash_value = hashValue
            file_object._fields["Hashes"]._inner[0].fuzzy_hash_value.condition = "Equals"
            file_object._fields["Hashes"]._inner[0].type_ = Hash.TYPE_SSDEEP
            file_object._fields["Hashes"]._inner[0].type_.condition = "Equals"
    return file_object

def resolveIPType(attribute_value, attribute_type):
    address_object = Address()
    cidr = False
    if ("|" in attribute_value):
        attribute_value = attribute_value.split('|')[0]
    if ("/" in attribute_value):
        ip = attribute_value.split('/')[0]
        cidr = True
    else:
        ip = attribute_value
    try:
        socket.inet_aton(ip)
        ipv4 = True
    except socket.error:
        ipv4 = False
    if (cidr == True):
        address_object.category = "cidr"
        condition = "Contains"
    elif (ipv4 == True):
        address_object.category = "ipv4-addr"
        condition = "Equals"
    else:
        address_object.category = "ipv6-addr"
        condition = "Equals"
    if attribute_type.startswith("ip-src"):
        address_object.is_source = True
        address_object.is_destination = False
    if attribute_type.startswith("ip-dst"):
        address_object.is_source = False
        address_object.is_destination = True
    address_object.address_value = attribute_value
    address_object.condition = condition
    return address_object

def generateDomainIPObservable(indicator, attribute):
    indicator.add_indicator_type("Domain Watchlist")
    domain = attribute["value"].split('|')[0]
    ip = attribute["value"].split('|')[1]
    address_object = resolveIPType(ip, attribute["type"])
    address_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":AddressObject-" + attribute["uuid"]
    address_observable = Observable(address_object)
    address_observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":Address-" + attribute["uuid"]
    domain_object = DomainName()
    domain_object.value = domain
    domain_object.value.condition = "Equals"
    domain_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":DomainNameObject-" + attribute["uuid"]
    domain_observable = Observable(domain_object)
    domain_observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":DomainName-" + attribute["uuid"]
    compositeObject = ObservableComposition(observables = [address_observable, domain_observable])
    compositeObject.operator = "AND"
    observable = Observable(id_ = cybox.utils.idgen.__generator.namespace.prefix + ":ObservableComposition-" + attribute["uuid"])
    observable.observable_composition = compositeObject
    return observable

def generateIPObservable(indicator, attribute):
    indicator.add_indicator_type("IP Watchlist")
    address_object = resolveIPType(attribute["value"], attribute["type"])
    address_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":AddressObject-" + attribute["uuid"]
    if ("|" in attribute["value"]):
        port = attribute["value"].split('|')[1]
        address_observable = Observable(address_object)
        address_observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":Address-" + attribute["uuid"]
        port_object = Port()
        port_object.port_value = attribute["value"].split('|')[1]
        port_object.port_value.condition = "Equals"
        port_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":PortObject-" + attribute["uuid"]
        port_observable = Observable(port_object)
        port_observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":Port-" + attribute["uuid"]
        compositeObject = ObservableComposition(observables = [address_observable, port_observable])
        compositeObject.operator = "AND"
        observable = Observable(id_ = cybox.utils.idgen.__generator.namespace.prefix + ":ObservableComposition-" + attribute["uuid"])
        observable.observable_composition = compositeObject
        return observable
    else:
        return address_object

def generatePortObservable(indicator, attribute):
    port_object = Port()
    port_object.port_value = attribute["value"]
    port_object.port_value.condition = "Equals"
    port_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":PortObject-" + attribute["uuid"]
    return port_object

def generateRegkeyObservable(indicator, attribute):
    indicator.add_indicator_type("Host Characteristics")
    regkey = ""
    regvalue = ""
    if (attribute["type"] == "regkey|value"):
        regkey = attribute["value"].split('|')[0]
        regvalue = attribute["value"].split('|')[1]
    else:
        regkey = attribute["value"]
    reghive, regkey = resolveRegHive(regkey)
    reg_object = WinRegistryKey()
    reg_object.key = regkey
    reg_object.key.condition = "Equals"
    if (reghive != None):
        reg_object.hive = reghive
        reg_object.hive.condition = "Equals"
    if (regvalue != ""):
        reg_value_object = RegistryValue()
        reg_value_object.data = regvalue
        reg_value_object.data.condition = "Equals"
        reg_object.values = RegistryValues(reg_value_object)
    return reg_object

def generateSimpleObservable(indicator, attribute):
    cyboxName = misp_cybox_name[attribute["type"]]
    if cyboxName in cybox_validation:
        validator = getattr(this_module, cybox_validation[cyboxName], None)
        if not (validator(attribute["value"])):
            return False
    constructor = getattr(this_module, cyboxName, None)
    indicatorType = misp_indicator_type[attribute["type"]]
    if (indicatorType != ""):
        indicator.add_indicator_type(indicatorType)
    new_object = constructor()
    setattr(new_object, cybox_name_attribute[cyboxName], attribute["value"])
    setattr(getattr(new_object, cybox_name_attribute[cyboxName]), "condition", "Equals")
    return new_object

def generateTM(indicator, attribute):
    if (attribute["type"] == "snort"):
        tm = SnortTestMechanism()
        attribute["value"] = attribute["value"].encode('utf-8')
        tm.rules = [attribute["value"]]
    else:
        # remove the following line and uncomment the code below once yara test mechanisms get added to python-stix
        return indicator
        #tm = SnortTestMechanism()
        #tm.rules = [attribute["value"]]
    indicator.test_mechanisms = [tm]

def resolveEmailObservable(indicator, attribute):
    indicator.add_indicator_type("Malicious E-mail")
    new_object = EmailMessage()
    email_header = EmailHeader()
    if (attribute["type"] == "email-src"):
        email_header.from_ = attribute["value"]
        email_header.from_.condition = "Equals"
    elif(attribute["type"] == "email-dst"):
        email_header.to = attribute["value"]
        email_header.to.condition = "Equals"
    else:
        email_header.subject = attribute["value"]
        email_header.subject.condition = "Equals"
    new_object.header = email_header
    return new_object

def resolveHTTPObservable(indicator, attribute):
    request_response = HTTPRequestResponse()
    client_request = HTTPClientRequest()
    if (attribute["type"] == "user-agent"):
        header = HTTPRequestHeader()
        header_fields = HTTPRequestHeaderFields()
        header_fields.user_agent = attribute["value"]
        header.parsed_header = header_fields
        client_request.http_request_header = header
    else:
        line = HTTPRequestLine()
        line.http_method = attribute["value"]
        line.http_method.condition = "Equals"
        client_request.http_request_line = line
    request_response.http_client_request = client_request
    new_object = HTTPSession()
    request_response.to_xml()
    new_object.http_request_response = [request_response]
    return new_object

# use this when implementing pattern in memory and pattern in traffic
def resolvePatternObservable(indicator, attribute):
    new_object = None
    if attribute["type"] == "pattern-in-file":
        byte_run = ByteRun()
        byte_run.byte_run_data = attribute["value"]
        new_object = File()
        new_object.byte_runs = ByteRuns(byte_run)
    # custom properties are not implemented in the API yet
    # elif attribute["type"] == "pattern-in-memory":
    # elif attribute["type"] == "pattern-in-traffic":
    return new_object

# create an artifact object for the malware-sample type.
def createArtifactObject(indicator, attribute):
    artifact = Artifact(data = attribute["data"])
    artifact.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":ArtifactObject-" + attribute["uuid"]
    observable = Observable(artifact)
    observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":observable-artifact-" + attribute["uuid"]
    indicator.add_observable(observable)

# return either a composition if data is set in attribute, or just an observable with a filename if it's not set
def returnAttachmentComposition(attribute):
    file_object = File()
    file_object.file_name = attribute["value"]
    file_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":FileObject-" + attribute["uuid"]
    observable = Observable()
    if "data" in attribute:
        artifact = Artifact(data = attribute["data"])
        artifact.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":ArtifactObject-" + attribute["uuid"]
        observable_artifact = Observable(artifact)
        observable_artifact.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":observable-artifact-" + attribute["uuid"]
        observable_file = Observable(file_object)
        observable_file.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":observable-file-" + attribute["uuid"]
        composition = ObservableComposition(observables = [observable_artifact, observable_file])
        observable.observable_composition = composition
    else:
        observable = Observable(file_object)
    observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":observable-" + attribute["uuid"]
    if attribute["comment"] != "":
        observable.description = attribute["comment"]
    return observable

# email-attachment are mapped to an email message observable that contains the attachment as a file object
def generateEmailAttachmentObject(indicator, attribute):
    file_object = File()
    file_object.file_name = attribute["value"]
    file_object.file_name.condition = "Equals"
    email = EmailMessage()
    email.attachments = Attachments()
    email.add_related(file_object, "Contains", inline=True)
    file_object.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":FileObject-" + attribute["uuid"]
    email.attachments.append(file_object.parent.id_)
    email.parent.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":EmailMessageObject-" + attribute["uuid"]
    observable = Observable(email)
    observable.id_ = cybox.utils.idgen.__generator.namespace.prefix + ":observable-" + attribute["uuid"]
    indicator.observable = observable

# split registry string into hive and key
def resolveRegHive(regStr):
    regStr = regStr.lstrip('\\')
    regStrU = regStr.upper()
    for hive in misp_reghive.iterkeys():
        if regStrU.startswith(hive):
            return misp_reghive[hive], regStr[len(hive):]
    return None, regStr

def isInt(var):
    if var.isdigit():
        return True
    return False
    
