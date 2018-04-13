from stix.extensions.identity.ciq_identity_3_0 import (CIQIdentity3_0Instance, STIXCIQIdentity3_0, OrganisationInfo, PartyName, Address, ElectronicAddressIdentifier, FreeTextAddress)
from stix.common import Identity

def resolveIdentityAttribute(incident, attribute, namespace):
    ciq_identity = CIQIdentity3_0Instance()
    identity_spec = STIXCIQIdentity3_0()
    if attribute["type"] == 'target-user':
            identity_spec.party_name = PartyName(person_names = [attribute["value"]])
    elif attribute["type"] == 'target-external':
        # we don't know if target-external is a person or an organisation, so as described at http://docs.oasis-open.org/ciq/v3.0/prd03/specs/ciq-specs-v3-prd3.html#_Toc207716018, use NameLine
        identity_spec.party_name = PartyName(name_lines = ["External target: " + attribute["value"]])
    elif attribute["type"] == 'target-org':
        identity_spec.party_name = PartyName(organisation_names = [attribute["value"]])
    elif attribute["type"] == 'target-location':
        identity_spec.add_address(Address(FreeTextAddress(address_lines = [attribute["value"]])))
    elif attribute["type"] == 'target-email':
        identity_spec.add_electronic_address_identifier(ElectronicAddressIdentifier(value = attribute["value"]))
    ciq_identity.specification = identity_spec

    ciq_identity.id_ = namespace + ":Identity-" + attribute["uuid"]

    # is this a good idea?
    ciq_identity.name = attribute["type"] + ": " + attribute["value"] + " (MISP Attribute #" + attribute["id"] + ")"
    incident.add_victim(ciq_identity)
    return incident
