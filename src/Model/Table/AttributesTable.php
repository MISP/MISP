<?php

namespace App\Model\Table;

use App\Model\Entity\Attribute;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\InternalErrorException;
use Cake\Utility\Text;

class AttributesTable extends AppTable
{
    public $_typeDefinitions = null;
    public $_categoryDefinitions = null;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->belongsTo(
            'Events',
            [
                'propertyName' => 'Event'
            ]
        );
        $this->belongsTo(
            'SharingGroups',
            [
                'className' => 'SharingGroups',
                'foreignKey' => 'sharing_group_id'
            ]
        );
        $this->belongsTo(
            'Objects',
            [
                'propertyName' => 'MispObject',
                'foreignKey' => 'object_id'
            ]
        );

        $this->hasMany(
            'AttributeTags',
            [
                'dependent' => true,
                'propertyName' => 'AttributeTag',
            ]
        );
        $this->hasMany(
            'Correlations',
            [
                'dependent' => false,
                'propertyName' => 'Correlation',
            ]
        );
        $this->hasMany(
            'Sightings',
            [
                'dependent' => true,
                'propertyName' => 'Sighting',
            ]
        );
    }

    public function beforeSave(EventInterface $event, EntityInterface $attribute, ArrayObject $options)
    {
        // TODO: [3.x-MIGRATION] this is a simplified version of the old beforeSave, fix it when moving Attributes to 3.x see #9383
        $attribute->sharing_group_id ??= $attribute->Events->sharing_group_id ?? 0;

        if ($attribute->uuid === null) {
            $attribute->uuid = Text::uuid();
        }

        $attribute->event_id ??= $attribute->Events->id;

        if (!empty($attribute['type'])) {
            // explode composite types in value1 and value2
            if (in_array($attribute['type'], $this->getCompositeTypes(), true)) {
                $pieces = explode('|', $attribute['value']);
                if (2 !== count($pieces)) {
                    throw new InternalErrorException(__('Composite type, but value not explodable'));
                }
                $attribute['value1'] = $pieces[0];
                $attribute['value2'] = $pieces[1];
            } else {
                $attribute['value1'] = $attribute['value'];
                $attribute['value2'] = '';
            }
        }

        return true;
    }

    public function getCompositeTypes()
    {
        static $compositeTypes;

        if ($compositeTypes === null) {
            // build the list of composite Attribute.type dynamically by checking if type contains a |
            // default composite types
            $compositeTypes = ['malware-sample'];  // TODO hardcoded composite
            // dynamically generated list
            foreach ($this->typeDefinitions as $type => $foo) {
                if (strpos($type, '|') !== false) {
                    $compositeTypes[] = $type;
                }
            }
        }
        return $compositeTypes;
    }

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
        return [
            'Internal reference' => [
                'desc' => __('Reference used by the publishing party (e.g. ticket number)'),
                'types' => ['text', 'link', 'comment', 'other', 'hex', 'anonymised', 'git-commit-id']
            ],
            'Targeting data' => [
                'desc' => __('Internal Attack Targeting and Compromise Information'),
                'formdesc' => __('Targeting information to include recipient email, infected machines, department, and or locations.'),
                'types' => ['target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'comment', 'anonymised']
            ],
            'Antivirus detection' => [
                'desc' => __('All the info about how the malware is detected by the antivirus products'),
                'formdesc' => __('List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%). Attachment with list of detection or link to VirusTotal could be placed here as well.'),
                'types' => ['link', 'comment', 'text', 'hex', 'attachment', 'other', 'anonymised']
            ],
            'Payload delivery' => [
                'desc' => __('Information about how the malware is delivered'),
                'formdesc' => __('Information about the way the malware payload is initially delivered, for example information about the email or web-site, vulnerability used, originating IP etc. Malware sample itself should be attached here.'),
                'types' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'mac-address', 'mac-eui-64', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'hostname', 'domain', 'email', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'email-body', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'mime-type', 'attachment', 'malware-sample', 'link', 'malware-type', 'comment', 'text', 'hex', 'vulnerability', 'cpe', 'weakness', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hostname|port', 'email-dst-display-name', 'email-src-display-name', 'email-header', 'email-reply-to', 'email-x-mailer', 'email-mime-boundary', 'email-thread-index', 'email-message-id', 'azure-application-id', 'mobile-application-id', 'chrome-extension-id', 'whois-registrant-email', 'anonymised']
            ],
            'Artifacts dropped' => [
                'desc' => __('Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system'),
                'types' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory', 'filename-pattern', 'pdb', 'stix2-pattern', 'yara', 'sigma', 'attachment', 'malware-sample', 'named pipe', 'mutex', 'process-state', 'windows-scheduled-task', 'windows-service-name', 'windows-service-displayname', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'cookie', 'gene', 'kusto-query', 'mime-type', 'anonymised', 'pgp-public-key', 'pgp-private-key']
            ],
            'Payload installation' => [
                'desc' => __('Info on where the malware gets installed in the system'),
                'formdesc' => __('Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.'),
                'types' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'vulnerability', 'cpe', 'weakness', 'attachment', 'malware-sample', 'malware-type', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'azure-application-id', 'azure-application-id', 'mobile-application-id', 'chrome-extension-id', 'other', 'mime-type', 'anonymised']
            ],
            'Persistence mechanism' => [
                'desc' => __('Mechanisms used by the malware to start at boot'),
                'formdesc' => __('Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup'),
                'types' => ['filename', 'regkey', 'regkey|value', 'comment', 'text', 'other', 'hex', 'anonymised']
            ],
            'Network activity' => [
                'desc' => __('Information about network traffic generated by the malware'),
                'types' => ['ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'port', 'hostname', 'domain', 'domain|ip', 'mac-address', 'mac-eui-64', 'email', 'email-dst', 'email-src', 'eppn', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'filename-pattern', 'stix2-pattern', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hex', 'cookie', 'hostname|port', 'bro', 'zeek', 'anonymised', 'community-id', 'email-subject', 'favicon-mmh3', 'dkim', 'dkim-signature', 'ssh-fingerprint']
            ],
            'Payload type' => [
                'desc' => __('Information about the final payload(s)'),
                'formdesc' => __('Information about the final payload(s). Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.'),
                'types' => ['comment', 'text', 'other', 'anonymised']
            ],
            'Attribution' => [
                'desc' => __('Identification of the group, organisation, or country behind the attack'),
                'types' => ['threat-actor', 'campaign-name', 'campaign-id', 'whois-registrant-phone', 'whois-registrant-email', 'whois-registrant-name', 'whois-registrant-org', 'whois-registrar', 'whois-creation-date', 'comment', 'text', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'dns-soa-email', 'anonymised', 'email']
            ],
            'External analysis' => [
                'desc' => __('Any other result from additional analysis of the malware like tools output'),
                'formdesc' => __('Any other result from additional analysis of the malware like tools output Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.'),
                'types' => ['md5', 'sha1', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'mac-address', 'mac-eui-64', 'hostname', 'domain', 'domain|ip', 'url', 'user-agent', 'regkey', 'regkey|value', 'AS', 'snort', 'bro', 'zeek', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern', 'vulnerability', 'cpe', 'weakness', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'github-repository', 'other', 'cortex', 'anonymised', 'community-id']
            ],
            'Financial fraud' => [
                'desc' => __('Financial Fraud indicators'),
                'formdesc' => __('Financial Fraud indicators, for example: IBAN Numbers, BIC codes, Credit card numbers, etc.'),
                'types' => ['btc', 'dash', 'xmr', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number', 'comment', 'text', 'other', 'hex', 'anonymised'],
            ],
            'Support Tool' => [
                'desc' => __('Tools supporting analysis or detection of the event'),
                'types' => ['link', 'text', 'attachment', 'comment', 'other', 'hex', 'anonymised']
            ],
            'Social network' => [
                'desc' => __('Social networks and platforms'),
                // email-src and email-dst or should we go with a new email type that is neither / both?
                'types' => ['github-username', 'github-repository', 'github-organisation', 'jabber-id', 'twitter-id', 'email', 'email-src', 'email-dst', 'eppn', 'comment', 'text', 'other', 'whois-registrant-email', 'anonymised', 'pgp-public-key', 'pgp-private-key']
            ],
            'Person' => [
                'desc' => __('A human being - natural person'),
                'types' => ['first-name', 'middle-name', 'last-name', 'full-name', 'date-of-birth', 'place-of-birth', 'gender', 'passport-number', 'passport-country', 'passport-expiration', 'redress-number', 'nationality', 'visa-number', 'issue-date-of-the-visa', 'primary-residence', 'country-of-residence', 'special-service-request', 'frequent-flyer-number', 'travel-details', 'payment-details', 'place-port-of-original-embarkation', 'place-port-of-clearance', 'place-port-of-onward-foreign-destination', 'passenger-name-record-locator-number', 'comment', 'text', 'other', 'phone-number', 'identity-card-number', 'anonymised', 'email', 'pgp-public-key', 'pgp-private-key']
            ],
            'Other' => [
                'desc' => __('Attributes that are not part of any other category or are meant to be used as a component in MISP objects in the future'),
                'types' => ['comment', 'text', 'other', 'size-in-bytes', 'counter', 'datetime', 'cpe', 'port', 'float', 'hex', 'phone-number', 'boolean', 'anonymised', 'pgp-public-key', 'pgp-private-key']
            ]
        ];
    }

    /**
     * Generate just when really need
     * NOTE WHEN MODIFYING: please ensure to run the script 'tools/gen_misp_types_categories.py' to update the new definitions everywhere. (docu, website, RFC, ... )
     * @return array[]
     */
    private function generateTypeDefinitions()
    {
        return [
            'md5' => ['desc' => __('A checksum in MD5 format'), 'formdesc' => __("You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha1' => ['desc' => __('A checksum in SHA1 format'), 'formdesc' => __("You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha256' => ['desc' => __('A checksum in SHA256 format'), 'formdesc' => __("You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename' => ['desc' => __('Filename'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'pdb' => ['desc' => __('Microsoft Program database (PDB) path information'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'filename|md5' => ['desc' => __('A filename and an MD5 hash separated by a |'), 'formdesc' => __("A filename and an md5 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha1' => ['desc' => __('A filename and an SHA1 hash separated by a |'), 'formdesc' => __("A filename and an sha1 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha256' => ['desc' => __('A filename and an SHA256 hash separated by a |'), 'formdesc' => __("A filename and an sha256 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'ip-src' => ['desc' => __("A source IP address of the attacker"), 'default_category' => 'Network activity', 'to_ids' => 1],
            'ip-dst' => ['desc' => __('A destination IP address of the attacker or C&C server'), 'formdesc' => __("A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1],
            'hostname' => ['desc' => __('A full host/dnsname of an attacker'), 'formdesc' => __("A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1],
            'domain' => ['desc' => __('A domain name used in the malware'), 'formdesc' => __("A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'domain|ip' => ['desc' => __('A domain name and its IP address (as found in DNS lookup) separated by a |'), 'formdesc' => __("A domain name and its IP address (as found in DNS lookup) separated by a | (no spaces)"), 'default_category' => 'Network activity', 'to_ids' => 1],
            'email' => ['desc' => ('An email address'), 'default_category' => 'Social network', 'to_ids' => 1],
            'email-src' => ['desc' => __("The source email address. Used to describe the sender when describing an e-mail."), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'eppn' => ['desc' => __("eduPersonPrincipalName - eppn - the NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'email-dst' => ['desc' => __("The destination email address. Used to describe the recipient when describing an e-mail."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'email-subject' => ['desc' => __("The subject of the email"), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-attachment' => ['desc' => __("File name of the email attachment."), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'email-body' => ['desc' => __('Email body'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'float' => ['desc' => __("A floating point value."), 'default_category' => 'Other', 'to_ids' => 0],
            'git-commit-id' => ['desc' => __("A Git commit ID."), 'default_category' => 'Internal reference', 'to_ids' => 0],
            'url' => ['desc' => __('Uniform Resource Locator'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'http-method' => ['desc' => __("HTTP method used by the malware (e.g. POST, GET, ...)."), 'default_category' => 'Network activity', 'to_ids' => 0],
            'user-agent' => ['desc' => __("The user-agent used by the malware in the HTTP request."), 'default_category' => 'Network activity', 'to_ids' => 0],
            'ja3-fingerprint-md5' => ['desc' => __("JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'jarm-fingerprint' => ['desc' => __("JARM is a method for creating SSL/TLS server fingerprints."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'favicon-mmh3' => ['desc' => __("favicon-mmh3 is the murmur3 hash of a favicon as used in Shodan."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'hassh-md5' => ['desc' => __("hassh is a network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'hasshserver-md5' => ['desc' => __("hasshServer is a network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'regkey' => ['desc' => __("Registry key or value"), 'default_category' => 'Persistence mechanism', 'to_ids' => 1],
            'regkey|value' => ['desc' => __("Registry value + data separated by |"), 'default_category' => 'Persistence mechanism', 'to_ids' => 1],
            'AS' => ['desc' => __('Autonomous system'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'snort' => ['desc' => __('An IDS rule in Snort rule-format'), 'formdesc' => __("An IDS rule in Snort rule-format. This rule will be automatically rewritten in the NIDS exports."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'bro' => ['desc' => __('An NIDS rule in the Bro rule-format'), 'formdesc' => __("An NIDS rule in the Bro rule-format."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'zeek' => ['desc' => __('An NIDS rule in the Zeek rule-format'), 'formdesc' => __("An NIDS rule in the Zeek rule-format."), 'default_category' => 'Network activity', 'to_ids' => 1],
            'community-id' => ['desc' => __('A community ID flow hashing algorithm to map multiple traffic monitors into common flow id'), 'formdesc' => __("a community ID flow hashing algorithm to map multiple traffic monitors into common flow id"), 'default_category' => 'Network activity', 'to_ids' => 1],
            'pattern-in-file' => ['desc' => __('Pattern in file that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1],
            'pattern-in-traffic' => ['desc' => __('Pattern in network traffic that identifies the malware'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'pattern-in-memory' => ['desc' => __('Pattern in memory dump that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1],
            'filename-pattern' => ['desc' => __('A pattern in the name of a file'), 'default_category' => 'Payload installation', 'to_ids' => 1],
            'pgp-public-key' => ['desc' => __('A PGP public key'), 'default_category' => 'Person', 'to_ids' => 0],
            'pgp-private-key' => ['desc' => __('A PGP private key'), 'default_category' => 'Person', 'to_ids' => 0],
            'ssh-fingerprint' => ['desc' => __('A fingerprint of SSH key material'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'yara' => ['desc' => __('YARA signature'), 'default_category' => 'Payload installation', 'to_ids' => 1],
            'stix2-pattern' => ['desc' => __('STIX 2 pattern'), 'default_category' => 'Payload installation', 'to_ids' => 1],
            'sigma' => ['desc' => __('Sigma - Generic Signature Format for SIEM Systems'), 'default_category' => 'Payload installation', 'to_ids' => 1],
            'gene' => ['desc' => __('GENE - Go Evtx sigNature Engine'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'kusto-query' => ['desc' => __('Kusto query - Kusto from Microsoft Azure is a service for storing and running interactive analytics over Big Data.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'mime-type' => ['desc' => __('A media type (also MIME type and content type) is a two-part identifier for file formats and format contents transmitted on the Internet'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'identity-card-number' => ['desc' => __('Identity card number'), 'default_category' => 'Person', 'to_ids' => 0],
            'cookie' => ['desc' => __('HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie.'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'vulnerability' => ['desc' => __('A reference to the vulnerability used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0],
            'cpe' => ['desc' => __('Common Platform Enumeration - structured naming scheme for information technology systems, software, and packages.'), 'default_category' => 'External analysis', 'to_ids' => 0],
            'weakness' => ['desc' => __('A reference to the weakness (CWE) used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0],
            'attachment' => ['desc' => __('Attachment with external information'), 'formdesc' => __("Please upload files using the <em>Upload Attachment</em> button."), 'default_category' => 'External analysis', 'to_ids' => 0],
            'malware-sample' => ['desc' => __('Attachment containing encrypted malware sample'), 'formdesc' => __("Please upload files using the <em>Upload Attachment</em> button."), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'link' => ['desc' => __('Link to an external information'), 'default_category' => 'External analysis', 'to_ids' => 0],
            'comment' => ['desc' => __('Comment or description in a human language'), 'formdesc' => __('Comment or description in a human language.  This will not be correlated with other attributes'), 'default_category' => 'Other', 'to_ids' => 0],
            'text' => ['desc' => __('Name, ID or a reference'), 'default_category' => 'Other', 'to_ids' => 0],
            'hex' => ['desc' => __('A value in hexadecimal format'), 'default_category' => 'Other', 'to_ids' => 0],
            'other' => ['desc' => __('Other attribute'), 'default_category' => 'Other', 'to_ids' => 0],
            'named pipe' => ['desc' => __('Named pipe, use the format \\.\pipe\<PipeName>'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'mutex' => ['desc' => __('Mutex, use the format \BaseNamedObjects\<Mutex>'), 'default_category' => 'Artifacts dropped', 'to_ids' => 1],
            'process-state' => ['desc' => __('State of a process'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'target-user' => ['desc' => __('Attack Targets Username(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0],
            'target-email' => ['desc' => __('Attack Targets Email(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0],
            'target-machine' => ['desc' => __('Attack Targets Machine Name(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0],
            'target-org' => ['desc' => __('Attack Targets Department or Organization(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0],
            'target-location' => ['desc' => __('Attack Targets Physical Location(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0],
            'target-external' => ['desc' => __('External Target Organizations Affected by this Attack'), 'default_category' => 'Targeting data', 'to_ids' => 0],
            'btc' => ['desc' => __('Bitcoin Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'dash' => ['desc' => __('Dash Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'xmr' => ['desc' => __('Monero Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'iban' => ['desc' => __('International Bank Account Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'bic' => ['desc' => __('Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'bank-account-nr' => ['desc' => __('Bank account number without any routing number'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'aba-rtn' => ['desc' => __('ABA routing transit number'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'bin' => ['desc' => __('Bank Identification Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'cc-number' => ['desc' => __('Credit-Card Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'prtn' => ['desc' => __('Premium-Rate Telephone Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1],
            'phone-number' => ['desc' => __('Telephone Number'), 'default_category' => 'Person', 'to_ids' => 0],
            'threat-actor' => ['desc' => __('A string identifying the threat actor'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'campaign-name' => ['desc' => __('Associated campaign name'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'campaign-id' => ['desc' => __('Associated campaign ID'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'malware-type' => ['desc' => '', 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'uri' => ['desc' => __('Uniform Resource Identifier'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'authentihash' => ['desc' => __('Authenticode executable signature hash'), 'formdesc' => __("You are encouraged to use filename|authentihash instead. Authenticode executable signature hash, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'vhash' => ['desc' => __('A VirusTotal checksum'), 'formdesc' => __("You are encouraged to use filename|vhash instead. A checksum from VirusTotal, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'ssdeep' => ['desc' => __('A checksum in ssdeep format'), 'formdesc' => __("You are encouraged to use filename|ssdeep instead. A checksum in the SSDeep format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'imphash' => ['desc' => __('Import hash - a hash created based on the imports in the sample.'), 'formdesc' => __("You are encouraged to use filename|imphash instead. A hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'telfhash' => ['desc' => __('telfhash is symbol hash for ELF files, just like imphash is imports hash for PE files.'), 'formdesc' => __("You are encouraged to use a file object with telfash"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'pehash' => ['desc' => __('peHash - a hash calculated based of certain pieces of a PE executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'impfuzzy' => ['desc' => __('A fuzzy hash of import table of Portable Executable format'), 'formdesc' => __("You are encouraged to use filename|impfuzzy instead. A fuzzy hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha224' => ['desc' => __('A checksum in SHA-224 format'), 'formdesc' => __("You are encouraged to use filename|sha224 instead. A checksum in sha224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha384' => ['desc' => __('A checksum in SHA-384 format'), 'formdesc' => __("You are encouraged to use filename|sha384 instead. A checksum in sha384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha512' => ['desc' => __('A checksum in SHA-512 format'), 'formdesc' => __("You are encouraged to use filename|sha512 instead. A checksum in sha512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha512/224' => ['desc' => __('A checksum in the SHA-512/224 format'), 'formdesc' => __("You are encouraged to use filename|sha512/224 instead. A checksum in sha512/224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha512/256' => ['desc' => __('A checksum in the SHA-512/256 format'), 'formdesc' => __("You are encouraged to use filename|sha512/256 instead. A checksum in sha512/256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha3-224' => ['desc' => __('A checksum in SHA3-224 format'), 'formdesc' => __("You are encouraged to use filename|sha3-224 instead. A checksum in sha3-224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha3-256' => ['desc' => __('A checksum in SHA3-256 format'), 'formdesc' => __("You are encouraged to use filename|sha3-256 instead. A checksum in sha3-256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha3-384' => ['desc' => __('A checksum in SHA3-384 format'), 'formdesc' => __("You are encouraged to use filename|sha3-384 instead. A checksum in sha3-384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'sha3-512' => ['desc' => __('A checksum in SHA3-512 format'), 'formdesc' => __("You are encouraged to use filename|sha3-512 instead. A checksum in sha3-512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'tlsh' => ['desc' => __('A checksum in the Trend Micro Locality Sensitive Hash format'), 'formdesc' => __("You are encouraged to use filename|tlsh instead. A checksum in the Trend Micro Locality Sensitive Hash format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'cdhash' => ['desc' => __('An Apple Code Directory Hash, identifying a code-signed Mach-O executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|authentihash' => ['desc' => __('A filename and Authenticode executable signature hash'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|vhash' => ['desc' => __('A filename and a VirusTotal hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|ssdeep' => ['desc' => __('A checksum in ssdeep format'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|imphash' => ['desc' => __('Import hash - a hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|impfuzzy' => ['desc' => __('Import fuzzy hash - a fuzzy hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|pehash' => ['desc' => __('A filename and a peHash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha224' => ['desc' => __('A filename and a SHA-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha384' => ['desc' => __('A filename and a SHA-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha512' => ['desc' => __('A filename and a SHA-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha512/224' => ['desc' => __('A filename and a SHa-512/224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha512/256' => ['desc' => __('A filename and a SHA-512/256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha3-224' => ['desc' => __('A filename and an SHA3-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha3-256' => ['desc' => __('A filename and an SHA3-256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha3-384' => ['desc' => __('A filename and an SHA3-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|sha3-512' => ['desc' => __('A filename and an SHA3-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'filename|tlsh' => ['desc' => __('A filename and a Trend Micro Locality Sensitive Hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'windows-scheduled-task' => ['desc' => __('A scheduled task in windows'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'windows-service-name' => ['desc' => __('A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'windows-service-displayname' => ['desc' => __('A windows service\'s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service\'s name in applications.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0],
            'whois-registrant-email' => ['desc' => __('The e-mail of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'whois-registrant-phone' => ['desc' => __('The phone number of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'whois-registrant-name' => ['desc' => __('The name of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'whois-registrant-org' => ['desc' => __('The org of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'whois-registrar' => ['desc' => __('The registrar of the domain, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'whois-creation-date' => ['desc' => __('The date of domain\'s creation, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0],
            // 'targeted-threat-index' => array('desc' => ''), // currently not mapped!
            // 'mailslot' => array('desc' => 'MailSlot interprocess communication'), // currently not mapped!
            // 'pipe' => array('desc' => 'Pipeline (for named pipes use the attribute type "named pipe")'), // currently not mapped!
            // 'ssl-cert-attributes' => array('desc' => 'SSL certificate attributes'), // currently not mapped!
            'x509-fingerprint-sha1' => ['desc' => __('X509 fingerprint in SHA-1 format'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'x509-fingerprint-md5' => ['desc' => __('X509 fingerprint in MD5 format'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'x509-fingerprint-sha256' => ['desc' => __('X509 fingerprint in SHA-256 format'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'dns-soa-email' => ['desc' => __('RFC 1035 mandates that DNS zones should have a SOA (Statement Of Authority) record that contains an email address where a PoC for the domain could be contacted. This can sometimes be used for attribution/linkage between different domains even if protected by whois privacy'), 'default_category' => 'Attribution', 'to_ids' => 0],
            'size-in-bytes' => ['desc' => __('Size expressed in bytes'), 'default_category' => 'Other', 'to_ids' => 0],
            'counter' => ['desc' => __('An integer counter, generally to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0],
            'datetime' => ['desc' => __('Datetime in the ISO 8601 format'), 'default_category' => 'Other', 'to_ids' => 0],
            'port' => ['desc' => __('Port number'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'ip-dst|port' => ['desc' => __('IP destination and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'ip-src|port' => ['desc' => __('IP source and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'hostname|port' => ['desc' => __('Hostname and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1],
            'mac-address' => ['desc' => __('MAC address'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'mac-eui-64' => ['desc' => __('MAC EUI-64 address'), 'default_category' => 'Network activity', 'to_ids' => 0],
            // verify IDS flag defaults for these
            'email-dst-display-name' => ['desc' => __('Email destination display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-src-display-name' => ['desc' => __('Email source display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-header' => ['desc' => __('Email header'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-reply-to' => ['desc' => __('Email reply to header'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-x-mailer' => ['desc' => __('Email x-mailer header'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-mime-boundary' => ['desc' => __('The email mime boundary separating parts in a multipart email'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-thread-index' => ['desc' => __('The email thread index header'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'email-message-id' => ['desc' => __('The email message ID'), 'default_category' => 'Payload delivery', 'to_ids' => 0],
            'github-username' => ['desc' => __('A GitHub user name'), 'default_category' => 'Social network', 'to_ids' => 0],
            'github-repository' => ['desc' => __('A Github repository'), 'default_category' => 'Social network', 'to_ids' => 0],
            'github-organisation' => ['desc' => __('A GitHub organisation'), 'default_category' => 'Social network', 'to_ids' => 0],
            'jabber-id' => ['desc' => __('Jabber ID'), 'default_category' => 'Social network', 'to_ids' => 0],
            'twitter-id' => ['desc' => __('Twitter ID'), 'default_category' => 'Social network', 'to_ids' => 0],
            'dkim' => ['desc' => __('DKIM public key'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'dkim-signature' => ['desc' => __('DKIM signature'), 'default_category' => 'Network activity', 'to_ids' => 0],
            'first-name' => ['desc' => __('First name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'middle-name' => ['desc' => __('Middle name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'last-name' => ['desc' => __('Last name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'full-name' => ['desc' => __('Full name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'date-of-birth' => ['desc' => __('Date of birth of a natural person (in YYYY-MM-DD format)'), 'default_category' => 'Person', 'to_ids' => 0],
            'place-of-birth' => ['desc' => __('Place of birth of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'gender' => ['desc' => __('The gender of a natural person (Male, Female, Other, Prefer not to say)'), 'default_category' => 'Person', 'to_ids' => 0],
            'passport-number' => ['desc' => __('The passport number of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'passport-country' => ['desc' => __('The country in which the passport was issued'), 'default_category' => 'Person', 'to_ids' => 0],
            'passport-expiration' => ['desc' => __('The expiration date of a passport'), 'default_category' => 'Person', 'to_ids' => 0],
            'redress-number' => ['desc' => __('The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems'), 'default_category' => 'Person', 'to_ids' => 0],
            'nationality' => ['desc' => __('The nationality of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'visa-number' => ['desc' => __('Visa number'), 'default_category' => 'Person', 'to_ids' => 0],
            'issue-date-of-the-visa' => ['desc' => __('The date on which the visa was issued'), 'default_category' => 'Person', 'to_ids' => 0],
            'primary-residence' => ['desc' => __('The primary residence of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'country-of-residence' => ['desc' => __('The country of residence of a natural person'), 'default_category' => 'Person', 'to_ids' => 0],
            'special-service-request' => ['desc' => __('A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers. '), 'default_category' => 'Person', 'to_ids' => 0],
            'frequent-flyer-number' => ['desc' => __('The frequent flyer number of a passenger'), 'default_category' => 'Person', 'to_ids' => 0],
            // Do we really need remarks? Or just use comment/text for this?
            //'remarks' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
            'travel-details' => ['desc' => __('Travel details'), 'default_category' => 'Person', 'to_ids' => 0],
            'payment-details' => ['desc' => __('Payment details'), 'default_category' => 'Person', 'to_ids' => 0],
            'place-port-of-original-embarkation' => ['desc' => __('The original port of embarkation'), 'default_category' => 'Person', 'to_ids' => 0],
            'place-port-of-clearance' => ['desc' => __('The port of clearance'), 'default_category' => 'Person', 'to_ids' => 0],
            'place-port-of-onward-foreign-destination' => ['desc' => __('A Port where the passenger is transiting to'), 'default_category' => 'Person', 'to_ids' => 0],
            'passenger-name-record-locator-number' => ['desc' => __('The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers.'), 'default_category' => 'Person', 'to_ids' => 0],
            'mobile-application-id' => ['desc' => __('The application id of a mobile application'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'azure-application-id' => ['desc' => __('Azure Application ID.'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'chrome-extension-id' => ['desc' => __('Chrome extension id'), 'default_category' => 'Payload delivery', 'to_ids' => 1],
            'cortex' => ['desc' => __('Cortex analysis result'), 'default_category' => 'External analysis', 'to_ids' => 0],
            'boolean' => ['desc' => __('Boolean value - to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0],
            'anonymised' => ['desc' => __('Anonymised value - described with the anonymisation object via a relationship'),  'formdesc' => __('Anonymised value - described with the anonymisation object via a relationship.'), 'default_category' => 'Other', 'to_ids' => 0]
            // Not convinced about this.
            //'url-regex' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
        ];
    }

    // gets an attribute, saves it
    // handles encryption, attaching to event/object, logging of issues, tag capturing
    public function captureAttribute($attribute, $eventId, $user, $objectId = false, $log = false, $parentEvent = false, &$validationErrors = false, $params = [])
    {
        // TODO: [3.x-MIGRATION] this is a placeholder for the migration of the captureAttribute method
        $attribute['event_id'] = $eventId;
        $attribute['org_id'] = $user['org_id'];
        $attributeEntity = $this->newEntity($attribute);

        $this->save($attributeEntity, ['associated' => []]);
    }

    public function typeIsAttachment($type)
    {
        return in_array($type, Attribute::ZIPPED_DEFINITION, true) || in_array($type, Attribute::UPLOAD_DEFINITIONS, true);
    }
}
