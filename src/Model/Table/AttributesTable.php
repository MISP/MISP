<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class AttributesTable extends AppTable
{
    public $_typeDefinitions = null;
    public $_categoryDefinitions = null;

    public function __get($name)
    {
        if ($name === 'typeDefinitions') {
            $this->_typeDefinitions = $this->generateTypeDefinitions();
            return $this->_typeDefinitions;
        } else if ($name === 'categoryDefinitions') {
            $this->_categoryDefinitions = $this->generateCategoryDefinitions();
            return $this->_categoryDefinitions;
        }
        return parent::__get($name);
    }

    /**
     * Generate just when really need
     * NOTE WHEN MODIFYING: please ensure to run the script 'tools/gen_misp_types_categories.py' to update the new definitions everywhere. (docu, website, RFC, ... )
     * @return array[]
     */
    private function generateCategoryDefinitions()
    {
        return array(
            'Internal reference' => array(
                'desc' => __('Reference used by the publishing party (e.g. ticket number)'),
                'types' => array('text', 'link', 'comment', 'other', 'hex', 'anonymised', 'git-commit-id')
            ),
            'Targeting data' => array(
                'desc' => __('Internal Attack Targeting and Compromise Information'),
                'formdesc' => __('Targeting information to include recipient email, infected machines, department, and or locations.'),
                'types' => array('target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'comment', 'anonymised')
            ),
            'Antivirus detection' => array(
                'desc' => __('All the info about how the malware is detected by the antivirus products'),
                'formdesc' => __('List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%). Attachment with list of detection or link to VirusTotal could be placed here as well.'),
                'types' => array('link', 'comment', 'text', 'hex', 'attachment', 'other', 'anonymised')
            ),
            'Payload delivery' => array(
                'desc' => __('Information about how the malware is delivered'),
                'formdesc' => __('Information about the way the malware payload is initially delivered, for example information about the email or web-site, vulnerability used, originating IP etc. Malware sample itself should be attached here.'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'mac-address', 'mac-eui-64', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'hostname', 'domain', 'email', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'email-body', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'mime-type', 'attachment', 'malware-sample', 'link', 'malware-type', 'comment', 'text', 'hex', 'vulnerability', 'cpe', 'weakness', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hostname|port', 'email-dst-display-name', 'email-src-display-name', 'email-header', 'email-reply-to', 'email-x-mailer', 'email-mime-boundary', 'email-thread-index', 'email-message-id', 'azure-application-id', 'mobile-application-id', 'chrome-extension-id', 'whois-registrant-email', 'anonymised')
            ),
            'Artifacts dropped' => array(
                'desc' => __('Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory', 'filename-pattern', 'pdb', 'stix2-pattern', 'yara', 'sigma', 'attachment', 'malware-sample', 'named pipe', 'mutex', 'process-state', 'windows-scheduled-task', 'windows-service-name', 'windows-service-displayname', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'cookie', 'gene', 'kusto-query', 'mime-type', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            ),
            'Payload installation' => array(
                'desc' => __('Info on where the malware gets installed in the system'),
                'formdesc' => __('Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'vulnerability', 'cpe', 'weakness', 'attachment', 'malware-sample', 'malware-type', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'azure-application-id', 'azure-application-id', 'mobile-application-id', 'chrome-extension-id', 'other', 'mime-type', 'anonymised')
            ),
            'Persistence mechanism' => array(
                'desc' => __('Mechanisms used by the malware to start at boot'),
                'formdesc' => __('Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup'),
                'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other', 'hex', 'anonymised')
            ),
            'Network activity' => array(
                'desc' => __('Information about network traffic generated by the malware'),
                'types' => array('ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'port', 'hostname', 'domain', 'domain|ip', 'mac-address', 'mac-eui-64', 'email', 'email-dst', 'email-src', 'eppn', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'filename-pattern', 'stix2-pattern', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hex', 'cookie', 'hostname|port', 'bro', 'zeek', 'anonymised', 'community-id', 'email-subject', 'favicon-mmh3', 'dkim', 'dkim-signature', 'ssh-fingerprint')
            ),
            'Payload type' => array(
                'desc' => __('Information about the final payload(s)'),
                'formdesc' => __('Information about the final payload(s). Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.'),
                'types' => array('comment', 'text', 'other', 'anonymised')
            ),
            'Attribution' => array(
                'desc' => __('Identification of the group, organisation, or country behind the attack'),
                'types' => array('threat-actor', 'campaign-name', 'campaign-id', 'whois-registrant-phone', 'whois-registrant-email', 'whois-registrant-name', 'whois-registrant-org', 'whois-registrar', 'whois-creation-date', 'comment', 'text', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'dns-soa-email', 'anonymised', 'email')
            ),
            'External analysis' => array(
                'desc' => __('Any other result from additional analysis of the malware like tools output'),
                'formdesc' => __('Any other result from additional analysis of the malware like tools output Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.'),
                'types' => array('md5', 'sha1', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'mac-address', 'mac-eui-64', 'hostname', 'domain', 'domain|ip', 'url', 'user-agent', 'regkey', 'regkey|value', 'AS', 'snort', 'bro', 'zeek', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern', 'vulnerability', 'cpe', 'weakness', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'github-repository', 'other', 'cortex', 'anonymised', 'community-id')
            ),
            'Financial fraud' => array(
                'desc' => __('Financial Fraud indicators'),
                'formdesc' => __('Financial Fraud indicators, for example: IBAN Numbers, BIC codes, Credit card numbers, etc.'),
                'types' => array('btc', 'dash', 'xmr', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number', 'comment', 'text', 'other', 'hex', 'anonymised'),
            ),
            'Support Tool' => array(
                'desc' => __('Tools supporting analysis or detection of the event'),
                'types' => array('link', 'text', 'attachment', 'comment', 'other', 'hex', 'anonymised')
            ),
            'Social network' => array(
                'desc' => __('Social networks and platforms'),
                // email-src and email-dst or should we go with a new email type that is neither / both?
                'types' => array('github-username', 'github-repository', 'github-organisation', 'jabber-id', 'twitter-id', 'email', 'email-src', 'email-dst', 'eppn', 'comment', 'text', 'other', 'whois-registrant-email', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            ),
            'Person' => array(
                'desc' => __('A human being - natural person'),
                'types' => array('first-name', 'middle-name', 'last-name', 'full-name', 'date-of-birth', 'place-of-birth', 'gender', 'passport-number', 'passport-country', 'passport-expiration', 'redress-number', 'nationality', 'visa-number', 'issue-date-of-the-visa', 'primary-residence', 'country-of-residence', 'special-service-request', 'frequent-flyer-number', 'travel-details', 'payment-details', 'place-port-of-original-embarkation', 'place-port-of-clearance', 'place-port-of-onward-foreign-destination', 'passenger-name-record-locator-number', 'comment', 'text', 'other', 'phone-number', 'identity-card-number', 'anonymised', 'email', 'pgp-public-key', 'pgp-private-key')
            ),
            'Other' => array(
                'desc' => __('Attributes that are not part of any other category or are meant to be used as a component in MISP objects in the future'),
                'types' => array('comment', 'text', 'other', 'size-in-bytes', 'counter', 'datetime', 'cpe', 'port', 'float', 'hex', 'phone-number', 'boolean', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            )
        );
    }

    /**
     * Generate just when really need
     * NOTE WHEN MODIFYING: please ensure to run the script 'tools/gen_misp_types_categories.py' to update the new definitions everywhere. (docu, website, RFC, ... )
     * @return array[]
     */
    private function generateTypeDefinitions()
    {
        return array(
            'md5' => array('desc' => __('A checksum in MD5 format'), 'formdesc' => __("You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha1' => array('desc' => __('A checksum in SHA1 format'), 'formdesc' => __("You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha256' => array('desc' => __('A checksum in SHA256 format'), 'formdesc' => __("You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename' => array('desc' => __('Filename'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'pdb' => array('desc' => __('Microsoft Program database (PDB) path information'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'filename|md5' => array('desc' => __('A filename and an MD5 hash separated by a |'), 'formdesc' => __("A filename and an md5 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha1' => array('desc' => __('A filename and an SHA1 hash separated by a |'), 'formdesc' => __("A filename and an sha1 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha256' => array('desc' => __('A filename and an SHA256 hash separated by a |'), 'formdesc' => __("A filename and an sha256 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'ip-src' => array('desc' => __("A source IP address of the attacker"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'ip-dst' => array('desc' => __('A destination IP address of the attacker or C&C server'), 'formdesc' => __("A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hostname' => array('desc' => __('A full host/dnsname of an attacker'), 'formdesc' => __("A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'domain' => array('desc' => __('A domain name used in the malware'), 'formdesc' => __("A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'domain|ip' => array('desc' => __('A domain name and its IP address (as found in DNS lookup) separated by a |'), 'formdesc' => __("A domain name and its IP address (as found in DNS lookup) separated by a | (no spaces)"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email' => array('desc' => ('An email address'), 'default_category' => 'Social network', 'to_ids' => 1),
            'email-src' => array('desc' => __("The source email address. Used to describe the sender when describing an e-mail."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'eppn' => array('desc' => __("eduPersonPrincipalName - eppn - the NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email-dst' => array('desc' => __("The destination email address. Used to describe the recipient when describing an e-mail."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email-subject' => array('desc' => __("The subject of the email"), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-attachment' => array('desc' => __("File name of the email attachment."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'email-body' => array('desc' => __('Email body'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'float' => array('desc' => __("A floating point value."), 'default_category' => 'Other', 'to_ids' => 0),
            'git-commit-id' => array('desc' => __("A Git commit ID."), 'default_category' => 'Internal reference', 'to_ids' => 0),
            'url' => array('desc' => __('Uniform Resource Locator'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'http-method' => array('desc' => __("HTTP method used by the malware (e.g. POST, GET, ...)."), 'default_category' => 'Network activity', 'to_ids' => 0),
            'user-agent' => array('desc' => __("The user-agent used by the malware in the HTTP request."), 'default_category' => 'Network activity', 'to_ids' => 0),
            'ja3-fingerprint-md5' => array('desc' => __("JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'jarm-fingerprint' => array('desc' => __("JARM is a method for creating SSL/TLS server fingerprints."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'favicon-mmh3' => array('desc' => __("favicon-mmh3 is the murmur3 hash of a favicon as used in Shodan."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hassh-md5' => array('desc' => __("hassh is a network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hasshserver-md5' => array('desc' => __("hasshServer is a network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'regkey' => array('desc' => __("Registry key or value"), 'default_category' => 'Persistence mechanism', 'to_ids' => 1),
            'regkey|value' => array('desc' => __("Registry value + data separated by |"), 'default_category' => 'Persistence mechanism', 'to_ids' => 1),
            'AS' => array('desc' => __('Autonomous system'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'snort' => array('desc' => __('An IDS rule in Snort rule-format'), 'formdesc' => __("An IDS rule in Snort rule-format. This rule will be automatically rewritten in the NIDS exports."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'bro' => array('desc' => __('An NIDS rule in the Bro rule-format'), 'formdesc' => __("An NIDS rule in the Bro rule-format."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'zeek' => array('desc' => __('An NIDS rule in the Zeek rule-format'), 'formdesc' => __("An NIDS rule in the Zeek rule-format."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'community-id' => array('desc' => __('A community ID flow hashing algorithm to map multiple traffic monitors into common flow id'), 'formdesc' => __("a community ID flow hashing algorithm to map multiple traffic monitors into common flow id"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'pattern-in-file' => array('desc' => __('Pattern in file that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pattern-in-traffic' => array('desc' => __('Pattern in network traffic that identifies the malware'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'pattern-in-memory' => array('desc' => __('Pattern in memory dump that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'filename-pattern' => array('desc' => __('A pattern in the name of a file'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pgp-public-key' => array('desc' => __('A PGP public key'), 'default_category' => 'Person', 'to_ids' => 0),
            'pgp-private-key' => array('desc' => __('A PGP private key'), 'default_category' => 'Person', 'to_ids' => 0),
            'ssh-fingerprint' => array('desc' => __('A fingerprint of SSH key material'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'yara' => array('desc' => __('YARA signature'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'stix2-pattern' => array('desc' => __('STIX 2 pattern'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'sigma' => array('desc' => __('Sigma - Generic Signature Format for SIEM Systems'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'gene' => array('desc' => __('GENE - Go Evtx sigNature Engine'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'kusto-query' => array('desc' => __('Kusto query - Kusto from Microsoft Azure is a service for storing and running interactive analytics over Big Data.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'mime-type' => array('desc' => __('A media type (also MIME type and content type) is a two-part identifier for file formats and format contents transmitted on the Internet'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'identity-card-number' => array('desc' => __('Identity card number'), 'default_category' => 'Person', 'to_ids' => 0),
            'cookie' => array('desc' => __('HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie.'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'vulnerability' => array('desc' => __('A reference to the vulnerability used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'cpe' => array('desc' => __('Common Platform Enumeration - structured naming scheme for information technology systems, software, and packages.'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'weakness' => array('desc' => __('A reference to the weakness (CWE) used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'attachment' => array('desc' => __('Attachment with external information'), 'formdesc' => __("Please upload files using the <em>Upload Attachment</em> button."), 'default_category' => 'External analysis', 'to_ids' => 0),
            'malware-sample' => array('desc' => __('Attachment containing encrypted malware sample'), 'formdesc' => __("Please upload files using the <em>Upload Attachment</em> button."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'link' => array('desc' => __('Link to an external information'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'comment' => array('desc' => __('Comment or description in a human language'), 'formdesc' => __('Comment or description in a human language.  This will not be correlated with other attributes'), 'default_category' => 'Other', 'to_ids' => 0),
            'text' => array('desc' => __('Name, ID or a reference'), 'default_category' => 'Other', 'to_ids' => 0),
            'hex' => array('desc' => __('A value in hexadecimal format'), 'default_category' => 'Other', 'to_ids' => 0),
            'other' => array('desc' => __('Other attribute'), 'default_category' => 'Other', 'to_ids' => 0),
            'named pipe' => array('desc' => __('Named pipe, use the format \\.\pipe\<PipeName>'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'mutex' => array('desc' => __('Mutex, use the format \BaseNamedObjects\<Mutex>'), 'default_category' => 'Artifacts dropped', 'to_ids' => 1),
            'process-state' => array('desc' => __('State of a process'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'target-user' => array('desc' => __('Attack Targets Username(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-email' => array('desc' => __('Attack Targets Email(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-machine' => array('desc' => __('Attack Targets Machine Name(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-org' => array('desc' => __('Attack Targets Department or Organization(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-location' => array('desc' => __('Attack Targets Physical Location(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-external' => array('desc' => __('External Target Organizations Affected by this Attack'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'btc' => array('desc' => __('Bitcoin Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'dash' => array('desc' => __('Dash Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'xmr' => array('desc' => __('Monero Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'iban' => array('desc' => __('International Bank Account Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'bic' => array('desc' => __('Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'bank-account-nr' => array('desc' => __('Bank account number without any routing number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'aba-rtn' => array('desc' => __('ABA routing transit number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'bin' => array('desc' => __('Bank Identification Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'cc-number' => array('desc' => __('Credit-Card Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'prtn' => array('desc' => __('Premium-Rate Telephone Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'phone-number' => array('desc' => __('Telephone Number'), 'default_category' => 'Person', 'to_ids' => 0),
            'threat-actor' => array('desc' => __('A string identifying the threat actor'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'campaign-name' => array('desc' => __('Associated campaign name'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'campaign-id' => array('desc' => __('Associated campaign ID'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'malware-type' => array('desc' => '', 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'uri' => array('desc' => __('Uniform Resource Identifier'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'authentihash' => array('desc' => __('Authenticode executable signature hash'), 'formdesc' => __("You are encouraged to use filename|authentihash instead. Authenticode executable signature hash, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'vhash' => array('desc' => __('A VirusTotal checksum'), 'formdesc' => __("You are encouraged to use filename|vhash instead. A checksum from VirusTotal, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'ssdeep' => array('desc' => __('A checksum in ssdeep format'), 'formdesc' => __("You are encouraged to use filename|ssdeep instead. A checksum in the SSDeep format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'imphash' => array('desc' => __('Import hash - a hash created based on the imports in the sample.'), 'formdesc' => __("You are encouraged to use filename|imphash instead. A hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'telfhash' => array('desc' => __('telfhash is symbol hash for ELF files, just like imphash is imports hash for PE files.'), 'formdesc' => __("You are encouraged to use a file object with telfash"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'pehash' => array('desc' => __('peHash - a hash calculated based of certain pieces of a PE executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'impfuzzy' => array('desc' => __('A fuzzy hash of import table of Portable Executable format'), 'formdesc' => __("You are encouraged to use filename|impfuzzy instead. A fuzzy hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha224' => array('desc' => __('A checksum in SHA-224 format'), 'formdesc' => __("You are encouraged to use filename|sha224 instead. A checksum in sha224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha384' => array('desc' => __('A checksum in SHA-384 format'), 'formdesc' => __("You are encouraged to use filename|sha384 instead. A checksum in sha384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512' => array('desc' => __('A checksum in SHA-512 format'), 'formdesc' => __("You are encouraged to use filename|sha512 instead. A checksum in sha512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512/224' => array('desc' => __('A checksum in the SHA-512/224 format'), 'formdesc' => __("You are encouraged to use filename|sha512/224 instead. A checksum in sha512/224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512/256' => array('desc' => __('A checksum in the SHA-512/256 format'), 'formdesc' => __("You are encouraged to use filename|sha512/256 instead. A checksum in sha512/256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-224' => array('desc' => __('A checksum in SHA3-224 format'), 'formdesc' => __("You are encouraged to use filename|sha3-224 instead. A checksum in sha3-224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-256' => array('desc' => __('A checksum in SHA3-256 format'), 'formdesc' => __("You are encouraged to use filename|sha3-256 instead. A checksum in sha3-256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-384' => array('desc' => __('A checksum in SHA3-384 format'), 'formdesc' => __("You are encouraged to use filename|sha3-384 instead. A checksum in sha3-384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-512' => array('desc' => __('A checksum in SHA3-512 format'), 'formdesc' => __("You are encouraged to use filename|sha3-512 instead. A checksum in sha3-512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'tlsh' => array('desc' => __('A checksum in the Trend Micro Locality Sensitive Hash format'), 'formdesc' => __("You are encouraged to use filename|tlsh instead. A checksum in the Trend Micro Locality Sensitive Hash format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'cdhash' => array('desc' => __('An Apple Code Directory Hash, identifying a code-signed Mach-O executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|authentihash' => array('desc' => __('A filename and Authenticode executable signature hash'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|vhash' => array('desc' => __('A filename and a VirusTotal hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|ssdeep' => array('desc' => __('A checksum in ssdeep format'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|imphash' => array('desc' => __('Import hash - a hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|impfuzzy' => array('desc' => __('Import fuzzy hash - a fuzzy hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|pehash' => array('desc' => __('A filename and a peHash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha224' => array('desc' => __('A filename and a SHA-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha384' => array('desc' => __('A filename and a SHA-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512' => array('desc' => __('A filename and a SHA-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512/224' => array('desc' => __('A filename and a SHa-512/224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512/256' => array('desc' => __('A filename and a SHA-512/256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-224' => array('desc' => __('A filename and an SHA3-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-256' => array('desc' => __('A filename and an SHA3-256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-384' => array('desc' => __('A filename and an SHA3-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-512' => array('desc' => __('A filename and an SHA3-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|tlsh' => array('desc' => __('A filename and a Trend Micro Locality Sensitive Hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'windows-scheduled-task' => array('desc' => __('A scheduled task in windows'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'windows-service-name' => array('desc' => __('A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'windows-service-displayname' => array('desc' => __('A windows service\'s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service\'s name in applications.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'whois-registrant-email' => array('desc' => __('The e-mail of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrant-phone' => array('desc' => __('The phone number of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrant-name' => array('desc' => __('The name of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrant-org' => array('desc' => __('The org of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrar' => array('desc' => __('The registrar of the domain, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-creation-date' => array('desc' => __('The date of domain\'s creation, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            // 'targeted-threat-index' => array('desc' => ''), // currently not mapped!
            // 'mailslot' => array('desc' => 'MailSlot interprocess communication'), // currently not mapped!
            // 'pipe' => array('desc' => 'Pipeline (for named pipes use the attribute type "named pipe")'), // currently not mapped!
            // 'ssl-cert-attributes' => array('desc' => 'SSL certificate attributes'), // currently not mapped!
            'x509-fingerprint-sha1' => array('desc' => __('X509 fingerprint in SHA-1 format'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'x509-fingerprint-md5' => array('desc' => __('X509 fingerprint in MD5 format'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'x509-fingerprint-sha256' => array('desc' => __('X509 fingerprint in SHA-256 format'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'dns-soa-email' => array('desc' => __('RFC 1035 mandates that DNS zones should have a SOA (Statement Of Authority) record that contains an email address where a PoC for the domain could be contacted. This can sometimes be used for attribution/linkage between different domains even if protected by whois privacy'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'size-in-bytes' => array('desc' => __('Size expressed in bytes'), 'default_category' => 'Other', 'to_ids' => 0),
            'counter' => array('desc' => __('An integer counter, generally to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'datetime' => array('desc' => __('Datetime in the ISO 8601 format'), 'default_category' => 'Other', 'to_ids' => 0),
            'port' => array('desc' => __('Port number'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'ip-dst|port' => array('desc' => __('IP destination and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'ip-src|port' => array('desc' => __('IP source and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hostname|port' => array('desc' => __('Hostname and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'mac-address' => array('desc' => __('MAC address'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'mac-eui-64' => array('desc' => __('MAC EUI-64 address'), 'default_category' => 'Network activity', 'to_ids' => 0),
            // verify IDS flag defaults for these
            'email-dst-display-name' => array('desc' => __('Email destination display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-src-display-name' => array('desc' => __('Email source display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-header' => array('desc' => __('Email header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-reply-to' => array('desc' => __('Email reply to header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-x-mailer' => array('desc' => __('Email x-mailer header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-mime-boundary' => array('desc' => __('The email mime boundary separating parts in a multipart email'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-thread-index' => array('desc' => __('The email thread index header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-message-id' => array('desc' => __('The email message ID'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'github-username' => array('desc' => __('A GitHub user name'), 'default_category' => 'Social network', 'to_ids' => 0),
            'github-repository' => array('desc' => __('A Github repository'), 'default_category' => 'Social network', 'to_ids' => 0),
            'github-organisation' => array('desc' => __('A GitHub organisation'), 'default_category' => 'Social network', 'to_ids' => 0),
            'jabber-id' => array('desc' => __('Jabber ID'), 'default_category' => 'Social network', 'to_ids' => 0),
            'twitter-id' => array('desc' => __('Twitter ID'), 'default_category' => 'Social network', 'to_ids' => 0),
            'dkim' => array('desc' => __('DKIM public key'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'dkim-signature' => array('desc' => __('DKIM signature'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'first-name' => array('desc' => __('First name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'middle-name' => array('desc' => __('Middle name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'last-name' => array('desc' => __('Last name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'full-name' => array('desc' => __('Full name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'date-of-birth' => array('desc' => __('Date of birth of a natural person (in YYYY-MM-DD format)'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-of-birth' => array('desc' => __('Place of birth of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'gender' => array('desc' => __('The gender of a natural person (Male, Female, Other, Prefer not to say)'), 'default_category' => 'Person', 'to_ids' => 0),
            'passport-number' => array('desc' => __('The passport number of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'passport-country' => array('desc' => __('The country in which the passport was issued'), 'default_category' => 'Person', 'to_ids' => 0),
            'passport-expiration' => array('desc' => __('The expiration date of a passport'), 'default_category' => 'Person', 'to_ids' => 0),
            'redress-number' => array('desc' => __('The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems'), 'default_category' => 'Person', 'to_ids' => 0),
            'nationality' => array('desc' => __('The nationality of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'visa-number' => array('desc' => __('Visa number'), 'default_category' => 'Person', 'to_ids' => 0),
            'issue-date-of-the-visa' => array('desc' => __('The date on which the visa was issued'), 'default_category' => 'Person', 'to_ids' => 0),
            'primary-residence' => array('desc' => __('The primary residence of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'country-of-residence' => array('desc' => __('The country of residence of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'special-service-request' => array('desc' => __('A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers. '), 'default_category' => 'Person', 'to_ids' => 0),
            'frequent-flyer-number' => array('desc' => __('The frequent flyer number of a passenger'), 'default_category' => 'Person', 'to_ids' => 0),
            // Do we really need remarks? Or just use comment/text for this?
            //'remarks' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
            'travel-details' => array('desc' => __('Travel details'), 'default_category' => 'Person', 'to_ids' => 0),
            'payment-details' => array('desc' => __('Payment details'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-port-of-original-embarkation' => array('desc' => __('The original port of embarkation'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-port-of-clearance' => array('desc' => __('The port of clearance'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-port-of-onward-foreign-destination' => array('desc' => __('A Port where the passenger is transiting to'), 'default_category' => 'Person', 'to_ids' => 0),
            'passenger-name-record-locator-number' => array('desc' => __('The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers.'), 'default_category' => 'Person', 'to_ids' => 0),
            'mobile-application-id' => array('desc' => __('The application id of a mobile application'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'azure-application-id' => array('desc' => __('Azure Application ID.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'chrome-extension-id' => array('desc' => __('Chrome extension id'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'cortex' => array('desc' => __('Cortex analysis result'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'boolean' => array('desc' => __('Boolean value - to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'anonymised' => array('desc' => __('Anonymised value - described with the anonymisation object via a relationship'),  'formdesc' => __('Anonymised value - described with the anonymisation object via a relationship.'), 'default_category' => 'Other', 'to_ids' => 0)
            // Not convinced about this.
            //'url-regex' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
        );
    }
}
