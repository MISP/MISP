# MISP privacy statement

MISP is open source software that organisations install and operate in their
own environments. The MISP project provides the software, but it does not
control how a particular MISP instance is configured, which information is
entered into it, who can access it, how long information is retained, or with
whom it is shared.

Consequently, the privacy and data-protection obligations associated with a
MISP deployment are primarily tied to that deployment and to the organisation
or organisations operating and using it. The applicable requirements depend on
factors such as the jurisdictions involved, the people whose data is processed,
the operator's role and mandate, and the purposes of processing. Depending on
those factors, the GDPR, another privacy or data-protection regime, multiple
regimes, or no general privacy law may apply.

Each operator must determine which requirements apply, publish or provide its
own privacy information where required, and ensure that its use of MISP complies
with applicable laws, mandates, contracts, community rules, and policies. This
document is a general project statement, not a privacy notice for every MISP
instance and not legal advice.

## Privacy is specific to each instance and sharing community

An organisation operating a MISP instance decides, among other things:

- the purposes for which threat intelligence and related information are
  collected and processed;
- the legal authority or other basis for processing personal data, where one is
  required;
- which users, organisations, and connected MISP instances may receive data;
- the distribution settings, sharing groups, access controls, and other
  technical and organisational safeguards to apply;
- how data quality, correction, deletion, and retention are managed; and
- how data-subject requests, incidents, and applicable notification duties are
  handled.

Users seeking information about the processing of their personal data, or
wishing to exercise rights available under applicable law, should contact the
operator of the relevant MISP instance. The instance operator, rather than the
MISP software project, is best placed to identify its role, explain its
processing, and respond to a request. Operators should make their identity and
privacy contact details available to their users and, where appropriate, to
data subjects.

MISP supports decentralised and peer-to-peer sharing. Sending information to
another organisation or instance may create a separate processing activity for
the sender and the recipient. Operators remain responsible for choosing what
they share, selecting recipients, applying suitable distribution controls, and
establishing the necessary agreements and safeguards. Installing MISP does not
itself establish compliance or supply a lawful basis for processing.

## Personal data in threat intelligence

Threat intelligence can contain personal data even when identifying a person is
not its main purpose. Depending on context, examples may include IP addresses,
email addresses, account identifiers, domain-registration information,
financial identifiers, information about victims, and combinations of
otherwise indirect identifiers. MISP objects can also associate attributes in
ways that make identification easier.

Operators should therefore assess the data and context of their own use case,
collect and share only what is necessary for defined purposes, limit access and
retention, keep information appropriately accurate, and protect its
confidentiality and integrity. Pseudonymisation or an attribute's lack of a
direct name can reduce risk, but does not necessarily mean that the information
is anonymous or outside data-protection law.

## Applicable privacy and data-protection frameworks

Privacy and data-protection rules differ across jurisdictions and sectors.
Operators should assess all frameworks relevant to their deployment and sharing
community rather than assume that the GDPR applies universally or is the only
applicable framework. Other national, regional, state, or sector-specific rules
may impose different requirements concerning transparency, legal authority,
individual rights, security, transfers, retention, or breach notification.

### GDPR guidance for organisations to which it applies

The MISP project's detailed paper on
[information sharing and cooperation enabled by the GDPR](https://www.misp-project.org/compliance/GDPR/)
explains how GDPR concepts can apply to threat-intelligence sharing. This
guidance is relevant when an organisation's processing falls within the GDPR's
scope; it should not be read as stating that every MISP operator is subject to
the GDPR. In summary:

- in a distributed sharing environment, an entity may act as a controller for
  the personal data it collects, uses, or shares; a recipient processing shared
  information for its own purposes may have its own controller obligations;
- cyber-threat indicators can be personal data, and their classification
  depends on whether a natural person is identifiable in the relevant context;
- network and information security can provide a legitimate purpose for
  processing and sharing, but necessity, proportionality, and an applicable
  lawful basis must still be assessed by the organisation responsible;
- processing should follow the principles of lawfulness, fairness and
  transparency, purpose limitation, data minimisation, accuracy, storage
  limitation, and integrity and confidentiality; and
- MISP features such as distribution controls, sharing groups, proposals,
  deletion, IDS flags, and sightings can support an operator's policies, but
  legal compliance depends on how those features and the overall deployment
  are governed and used.

Under the GDPR, the appropriate roles and obligations can vary with the
deployment, relationships between participating organisations, applicable
jurisdiction, and purposes of processing. Similar questions may arise under
other frameworks, but their terminology and requirements may differ. Operators
should obtain qualified legal advice when needed and periodically review their
configuration, sharing arrangements, retention rules, security measures, and
privacy notices against every requirement applicable to them.

## Scope of this statement

This statement concerns the MISP software in this repository. Separate services
and websites used by the project or community may have their own privacy terms.
Likewise, every independently operated MISP instance should be treated according
to the privacy information supplied by its operator.

Questions about an independently operated instance, data stored in it, or data
shared through it must be directed to that instance's operator. Security issues
in the MISP software itself should be reported as described in the
[MISP security policy](SECURITY.md).
