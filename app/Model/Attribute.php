<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('FinancialTool', 'Tools');

/**
 * Attribute Model
 *
 * @property Event $Event
 */
class Attribute extends AppModel {

	public $combinedKeys = array('event_id', 'category', 'type');

	public $name = 'Attribute';				// TODO general

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'),
		'Trim',
		'Containable',
		'Regexp' => array('fields' => array('value')),
	);

/**
 * hasMany relation to shadow attributes
 *
 * Display field
 *
 * @var string
 */
	public $displayField = 'value';

/**
 * Virtual field
 *
 * @var array
 */
	public $virtualFields = array(
			'value' => 'IF (Attribute.value2="", Attribute.value1, CONCAT(Attribute.value1, "|", Attribute.value2))',
	); // TODO hardcoded

/**
 * Field Descriptions
 * explanations of certain fields to be used in various views
 *
 * @var array
 */
	public $fieldDescriptions = array(
			'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
			'distribution' => array('desc' => 'Describes who will have access to the event.')
	);

	public $distributionDescriptions = array(
			0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of your organisation on this server to see it."),
			1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on this MISP server and organisations running MISP servers that synchronise with this server. Any other organisations connected to such linked servers will be restricted from seeing the event. Use this option if you are on the central hub of this community."), // former Community
			2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes all organisations on this MISP server, all organisations on MISP servers synchronising with this server and the hosting organisations of servers that connect to those afore mentioned servers (so basically any server that is 2 hops away from this one). Any other organisations connected to linked servers that are 2 hops away from this will be restricted from seeing the event. Use this option if this server isn't the central MISP hub of the community but is connected to it."),
			3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
			4 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting allows you to select a sharing group as the distribution. Keep in mind that the selection here and the event's distribution settings together will form the releasability of this attribute. Both the attribute and the event has to be visible to a user."),
			5 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Inherit the event's distribution settings"),
	);

	public $distributionLevels = array(
			0 => 'Your organisation only', 1 => 'This community only', 2 => 'Connected communities', 3 => 'All communities', 4 => 'Sharing group', 5 => 'Inherit event'
	);

	public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group', 5 => 'Inherit');

	// these are definitions of possible types + their descriptions and maybe later other behaviors
	// e.g. if the attribute should be correlated with others or not

	// if these then a category may have upload to be zipped
	public $zippedDefinitions = array(
			'malware-sample'
	);

	// if these then a category may have upload
	public $uploadDefinitions = array(
			'attachment'
	);

	// skip Correlation for the following types
	public $nonCorrelatingTypes = array(
			'vulnerability',
			'comment',
			'http-method',
			'aba-rtn'
	);

	public $typeDefinitions = array(
			'md5' => array('desc' => 'A checksum in md5 format', 'formdesc' => "You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename"),
			'sha1' => array('desc' => 'A checksum in sha1 format', 'formdesc' => "You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename"),
			'sha256' => array('desc' => 'A checksum in sha256 format', 'formdesc' => "You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename"),
			'filename' => array('desc' => 'Filename'),
			'pdb' => array('desc' => 'Microsoft Program database (PDB) path information'),
			'filename|md5' => array('desc' => 'A filename and an md5 hash separated by a |', 'formdesc' => "A filename and an md5 hash separated by a | (no spaces)"),
			'filename|sha1' => array('desc' => 'A filename and an sha1 hash separated by a |', 'formdesc' => "A filename and an sha1 hash separated by a | (no spaces)"),
			'filename|sha256' => array('desc' => 'A filename and an sha256 hash separated by a |', 'formdesc' => "A filename and an sha256 hash separated by a | (no spaces)"),
			'ip-src' => array('desc' => "A source IP address of the attacker"),
			'ip-dst' => array('desc' => 'A destination IP address of the attacker or C&C server', 'formdesc' => "A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware"),
			'hostname' => array('desc' => 'A full host/dnsname of an attacker', 'formdesc' => "A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware"),
			'domain' => array('desc' => 'A domain name used in the malware', 'formdesc' => "A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events."),
			'domain|ip' => array('desc' => 'A domain name and its IP address (as found in DNS lookup) separated by a |','formdesc' => "A domain name and its IP address (as found in DNS lookup) separated by a | (no spaces)"),
			'email-src' => array('desc' => "The email address (or domainname) used to send the malware."),
			'email-dst' => array('desc' => "A recipient email address", 'formdesc' => "A recipient email address that is not related to your constituency."),
			'email-subject' => array('desc' => "The subject of the email"),
			'email-attachment' => array('desc' => "File name of the email attachment."),
			'url' => array('desc' => 'url'),
			'http-method' => array('desc' => "HTTP method used by the malware (e.g. POST, GET, ...)."),
			'user-agent' => array('desc' => "The user-agent used by the malware in the HTTP request."),
			'regkey' => array('desc' => "Registry key or value"),
			'regkey|value' => array('desc' => "Registry value + data separated by |"),
			'AS' => array('desc' => 'Autonomous system'),
			'snort' => array('desc' => 'An IDS rule in Snort rule-format', 'formdesc' => "An IDS rule in Snort rule-format. This rule will be automatically rewritten in the NIDS exports."),
			'pattern-in-file' => array('desc' => 'Pattern in file that identifies the malware'),
			'pattern-in-traffic' => array('desc' => 'Pattern in network traffic that identifies the malware'),
			'pattern-in-memory' => array('desc' => 'Pattern in memory dump that identifies the malware'),
			'yara' => array('desc' => 'Yara signature'),
			'vulnerability' => array('desc' => 'A reference to the vulnerability used in the exploit'),
			'attachment' => array('desc' => 'Attachment with external information', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button."),
			'malware-sample' => array('desc' => 'Attachment containing encrypted malware sample', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button."),
			'link' => array('desc' => 'Link to an external information'),
			'comment' => array('desc' => 'Comment or description in a human language', 'formdesc' => 'Comment or description in a human language.  This will not be correlated with other attributes'),
			'text' => array('desc' => 'Name, ID or a reference'),
			'other' => array('desc' => 'Other attribute'),
			'named pipe' => array('desc' => 'Named pipe, use the format \\.\pipe\<PipeName>'),
			'mutex' => array('desc' => 'Mutex, use the format \BaseNamedObjects\<Mutex>'),
			'target-user' => array('desc' => 'Attack Targets Username(s)'),
			'target-email' => array('desc' => 'Attack Targets Email(s)'),
			'target-machine' => array('desc' => 'Attack Targets Machine Name(s)'),
			'target-org' => array('desc' => 'Attack Targets Department or Organization(s)'),
			'target-location' => array('desc' => 'Attack Targets Physical Location(s)'),
			'target-external' => array('desc' => 'External Target Organizations Affected by this Attack'),
			'btc' => array('desc' => 'Bitcoin Address'),
			'iban' => array('desc' => 'International Bank Account Number'),
			'bic' => array('desc' => 'Bank Identifier Code Number'),
			'bank-account-nr' => array('desc' => 'Bank account number without any routing number'),
			'aba-rtn' => array('desc' => 'ABA routing transit number'),
			'bin' => array('desc' => 'Bank Identification Number'),
			'cc-number' => array('desc' => 'Credit-Card Number'),
			'prtn' => array('desc' => 'Premium-Rate Telephone Number'),
			'threat-actor' => array('desc' => 'A string identifying the threat actor'),
			'campaign-name' => array('desc' => 'Associated campaign name'),
			'campaign-id' => array('desc' => 'Associated campaign ID'),
			'malware-type' => array('desc' => ''),
			'uri' => array('desc' => 'Uniform Resource Identifier'),
			'authentihash' => array('desc' => 'Authenticode executable signature hash', 'formdesc' => "You are encouraged to use filename|authentihash instead. Authenticode executable signature hash, only use this if you don't know the correct filename"),
			'ssdeep' => array('desc' => 'A checksum in ssdeep format', 'formdesc' => "You are encouraged to use filename|ssdeep instead. A checksum in the SSDeep format, only use this if you don't know the correct filename"),
			'imphash' => array('desc' => 'Import hash - a hash created based on the imports in the sample.', 'formdesc' => "You are encouraged to use filename|imphash instead. A hash created based on the imports in the sample, only use this if you don't know the correct filename"),
			'pehash' => array('desc' => 'PEhash - a hash calculated based of certain pieces of a PE executable file'),
			'sha224' => array('desc' => 'A checksum in sha-224 format', 'formdesc' => "You are encouraged to use filename|sha224 instead. A checksum in sha224 format, only use this if you don't know the correct filename"),
			'sha384' => array('desc' => 'A checksum in sha-384 format', 'formdesc' => "You are encouraged to use filename|sha384 instead. A checksum in sha384 format, only use this if you don't know the correct filename"),
			'sha512' => array('desc' => 'A checksum in sha-512 format', 'formdesc' => "You are encouraged to use filename|sha512 instead. A checksum in sha512 format, only use this if you don't know the correct filename"),
			'sha512/224' => array('desc' => 'A checksum in the sha-512/224 format', 'formdesc' => "You are encouraged to use filename|sha512/224 instead. A checksum in sha512/224 format, only use this if you don't know the correct filename"),
			'sha512/256' => array('desc' => 'A checksum in the sha-512/256 format', 'formdesc' => "You are encouraged to use filename|sha512/256 instead. A checksum in sha512/256 format, only use this if you don't know the correct filename"),
			'tlsh' => array('desc' => 'A checksum in the Trend Micro Locality Sensitive Hash format', 'formdesc' => "You are encouraged to use filename|tlsh instead. A checksum in the Trend Micro Locality Sensitive Hash format, only use this if you don't know the correct filename"),
			'filename|authentihash' => array('desc' => 'A checksum in md5 format'),
			'filename|ssdeep' => array('desc' => 'A checksum in ssdeep format'),
			'filename|imphash' => array('desc' => 'Import hash - a hash created based on the imports in the sample.'),
			'filename|pehash' => array('desc' => 'A filename and a PEhash separated by a |'),
			'filename|sha224' => array('desc' => 'A filename and a sha-224 hash separated by a |'),
			'filename|sha384' => array('desc' => 'A filename and a sha-384 hash separated by a |'),
			'filename|sha512' => array('desc' => 'A filename and a sha-512 hash separated by a |'),
			'filename|sha512/224' => array('desc' => 'A filename and a sha-512/224 hash separated by a |'),
			'filename|sha512/256' => array('desc' => 'A filename and a sha-512/256 hash separated by a |'),
			'filename|tlsh' => array('desc' => 'A filename and a Trend Micro Locality Sensitive Hash separated by a |'),
			'windows-scheduled-task' => array('desc' => 'A scheduled task in windows'),
			'windows-service-name' => array('desc' => 'A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname.'),
			'windows-service-displayname' => array('desc' => 'A windows service\'s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service\'s name in applications.'),
			'whois-registrant-email' => array('desc' => 'The e-mail of a domain\'s registrant, obtained from the WHOIS information.'),
			'whois-registrant-phone' => array('desc' => 'The phone number of a domain\'s registrant, obtained from the WHOIS information.'),
			'whois-registrant-name' => array('desc' => 'The name of a domain\'s registrant, obtained from the WHOIS information.'),
			'whois-registrar' => array('desc' => 'The registrar of the domain, obtained from the WHOIS information.'),
			'whois-creation-date' => array('desc' => 'The date of domain\'s creation, obtained from the WHOIS information.'),
			'targeted-threat-index' => array('desc' => ''),
			'mailslot' => array('desc' => 'MailSlot interprocess communication'),
			'pipe' => array('desc' => 'Pipeline (for named pipes use the attribute type "named pipe")'),
			'ssl-cert-attributes' => array('desc' => 'SSL certificate attributes'),
			'x509-fingerprint-sha1' => array('desc' => 'X509 fingerprint in SHA-1 format')
	);

	// definitions of categories
	public $categoryDefinitions = array(
			'Internal reference' => array(
					'desc' => 'Reference used by the publishing party (e.g. ticket number)',
					'types' => array('link', 'comment', 'text', 'other')
					),
			'Targeting data' => array(
					'desc' => 'Internal Attack Targeting and Compromise Information',
					'formdesc' => 'Targeting information to include recipient email, infected machines, department, and or locations.',
					'types' => array('target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'comment')
					),
			'Antivirus detection' => array(
					'desc' => 'All the info about how the malware is detected by the antivirus products',
					'formdesc' => 'List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%). Attachment with list of detection or link to VirusTotal could be placed here as well.',
					'types' => array('link', 'comment', 'text', 'attachment', 'other')
					),
			'Payload delivery' => array(
					'desc' => 'Information about how the malware is delivered',
					'formdesc' => 'Information about the way the malware payload is initially delivered, for example information about the email or web-site, vulnerability used, originating IP etc. Malware sample itself should be attached here.',
					'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'authentihash', 'pehash', 'tlsh', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'ip-src', 'ip-dst', 'hostname', 'domain', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'yara', 'attachment', 'malware-sample', 'link', 'malware-type', 'comment', 'text', 'vulnerability', 'x509-fingerprint-sha1', 'other')
					),
			'Artifacts dropped' => array(
					'desc' => 'Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system',
					'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'authentihash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory','pdb', 'yara', 'attachment', 'malware-sample', 'named pipe', 'mutex', 'windows-scheduled-task', 'windows-service-name', 'windows-service-displayname', 'comment', 'text', 'x509-fingerprint-sha1', 'other')
					),
			'Payload installation' => array(
					'desc' => 'Info on where the malware gets installed in the system',
					'formdesc' => 'Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.',
					'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'authentihash', 'pehash', 'tlsh', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'yara', 'vulnerability', 'attachment', 'malware-sample', 'malware-type', 'comment', 'text', 'x509-fingerprint-sha1', 'other')
					),
			'Persistence mechanism' => array(
					'desc' => 'Mechanisms used by the malware to start at boot',
					'formdesc' => 'Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup',
					'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other')
					),
			'Network activity' => array(
					'desc' => 'Information about network traffic generated by the malware',
					'types' => array('ip-src', 'ip-dst', 'hostname', 'domain', 'domain|ip', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'x509-fingerprint-sha1', 'other')
					),
			'Payload type' => array(
					'desc' => 'Information about the final payload(s)',
					'formdesc' => 'Information about the final payload(s). Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.',
					'types' => array('comment', 'text', 'other')
					),
			'Attribution' => array(
					'desc' => 'Identification of the group, organisation, or country behind the attack',
					'types' => array('threat-actor', 'campaign-name', 'campaign-id', 'whois-registrant-phone', 'whois-registrant-email', 'whois-registrant-name', 'whois-registrar', 'whois-creation-date','comment', 'text', 'x509-fingerprint-sha1', 'other')
					),
			'External analysis' => array(
					'desc' => 'Any other result from additional analysis of the malware like tools output',
					'formdesc' => 'Any other result from additional analysis of the malware like tools output Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.',
					'types' => array('md5', 'sha1', 'sha256','filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'domain|ip', 'url', 'user-agent', 'regkey', 'regkey|value', 'AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'vulnerability', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'x509-fingerprint-sha1', 'other')
					),
			'Financial fraud' => array(
					'desc' => 'Financial Fraud indicators',
					'formdesc' => 'Financial Fraud indicators, for example: IBAN Numbers, BIC codes, Credit card numbers, etc.',
					'types' => array('btc', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'comment', 'text', 'other'),
					),
			'Other' => array(
					'desc' => 'Attributes that are not part of any other category',
					'types' => array('comment', 'text', 'other')
					)
	);

	public $defaultCategories = array(
			'md5' => 'Payload delivery',
			'sha1' => 'Payload delivery',
			'sha224' =>'Payload delivery',
			'sha256' => 'Payload delivery',
			'sha384' => 'Payload delivery',
			'sha512' => 'Payload delivery',
			'sha512/224' => 'Payload delivery',
			'sha512/256' => 'Payload delivery',
			'authentihash' => 'Payload delivery',
			'imphash' => 'Payload delivery',
			'pehash' => 'Payload delivery',
			'filename|md5' => 'Payload delivery',
			'filename|sha1' => 'Payload delivery',
			'filename|sha256' => 'Payload delivery',
			'regkey' => 'Persistence mechanism',
			'filename' => 'Payload delivery',
			'ip-src' => 'Network activity',
			'ip-dst' => 'Network activity',
			'hostname' => 'Network activity',
			'domain' => 'Network activity',
			'url' => 'Network activity',
			'link' => 'External analysis',
			'email-src' => 'Payload delivery',
			'email-dst' => 'Payload delivery',
			'text' => 'Other',
			'attachment' => 'External analysis',
			'malware-sample' => 'Payload delivery'
	);

	// typeGroupings are a mapping to high level groups for attributes
	// for example, IP addresses, domain names, hostnames and e-mail addresses are network related attribute types
	// whilst filenames and hashes are file related attribute types
	// This helps generate quick filtering for the event view, but we may reuse this and enhance it in the future for other uses (such as the API?)
	public $typeGroupings = array(
		'file' => array('attachment', 'pattern-in-file', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'authentihash', 'pehash', 'tlsh', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'malware-sample', 'x509-fingerprint-sha1'),
		'network' => array('ip-src', 'ip-dst', 'hostname', 'domain', 'domain|ip', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-traffic', 'x509-fingerprint-sha1'),
		'financial' => array('btc', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn')
	);

	public $order = array("Attribute.event_id" => "DESC");

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'event_id' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'type' => array(
			// currently when adding a new attribute type we need to change it in both places
			'rule' => array('validateTypeValue'),
			'message' => 'Options depend on the selected category.',
			//'allowEmpty' => false,
			'required' => true,
			//'last' => false, // Stop validation after this rule
			//'on' => 'create', // Limit validation to 'create' or 'update' operations

		),
		// this could be initialized from categoryDefinitions but dunno how at the moment
		'category' => array(
			'rule' => array('validCategory'),
			'message' => 'Options : Payload delivery, Antivirus detection, Payload installation, Files dropped ...'
		),
		'value' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
			'userdefined' => array(
				'rule' => array('validateAttributeValue'),
				'message' => 'Value not in the right type/format. Please double check the value or select type "other".',
				//'allowEmpty' => false,
				//'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'uniqueValue' => array(
					'rule' => array('valueIsUnique'),
					'message' => 'A similar attribute already exists for this event.',
					//'allowEmpty' => false,
					//'required' => true,
					//'last' => false, // Stop validation after this rule
					//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'to_ids' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'uuid' => array(
			'uuid' => array(
				'rule' => array('uuid'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'The UUID provided is not unique',
				'required' => 'create'
			)
		),
		'distribution' => array(
				'rule' => array('inList', array('0', '1', '2', '3', '4', '5')),
				'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group, Inherit event',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
		),
	);

	// automatic resolution of complex types
	// If the complex type "file" is chosen for example, then the system will try to categorise the values entered into a complex template field based
	// on the regular expression rules
	public $validTypeGroups = array(
			'File' => array(
				'description' => '',
				'types' => array('filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'md5', 'sha1', 'sha256'),
			),
			'CnC' => array(
				'description' => '',
				'types' => array('url', 'domain', 'hostname', 'ip-dst'),
			),
	);

	public $typeGroupCategoryMapping = array(
			'Payload delviery' => array('File', 'CnC'),
			'Payload installation' => array('File'),
			'Artifacts dropped' => array('File'),
			'Network activity' => array('CnC'),
	);

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);
	}

	// The Associations below have been created with all possible keys, those that are not needed can be removed

/**
 * belongsTo associations
 *
 * @var array
 */
	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'event_id',
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'counterCache' => 'attribute_count',
			'counterScope' => array('Attribute.deleted' => false)
		),
		'SharingGroup' => array(
				'className' => 'SharingGroup',
				'foreignKey' => 'sharing_group_id'
		)
	);

	public $hashTypes = array(
		'md5' => array(
			'length' => 32,
			'pattern' => '#^[0-9a-f]{32}$#',
			'lowerCase' => true,
		),
		'sha1' => array(
			'length' => 40,
			'pattern' => '#^[0-9a-f]{40}$#',
			'lowerCase' => true,
		),
		'sha256' => array(
			'length' => 64,
			'pattern' => '#^[0-9a-f]{64}$#',
			'lowerCase' => true,
		)
	);

/**
 * beforeSave
 *
 * @throws InternalErrorException
 * @return bool always true
 */
	public function beforeSave($options = array()) {
		// explode value of composite type in value1 and value2
		// or copy value to value1 if not composite type
		if (!empty($this->data['Attribute']['type'])) {
			$compositeTypes = $this->getCompositeTypes();
			// explode composite types in value1 and value2
			$pieces = explode('|', $this->data['Attribute']['value']);
			if (in_array($this->data['Attribute']['type'], $compositeTypes)) {
				if (2 != count($pieces)) {
					throw new InternalErrorException('Composite type, but value not explodable');
				}
				$this->data['Attribute']['value1'] = $pieces[0];
				$this->data['Attribute']['value2'] = $pieces[1];
			} else {
				$total = implode('|', $pieces);
				$this->data['Attribute']['value1'] = $total;
				$this->data['Attribute']['value2'] = '';
			}
		}

		if ($this->data['Attribute']['distribution'] != 4) $this->data['Attribute']['sharing_group_id'] = 0;

		// update correlation... (only needed here if there's an update)
		if ($this->id || !empty($this->data['Attribute']['id'])) {
			$this->__beforeSaveCorrelation($this->data['Attribute']);
		}
		// always return true after a beforeSave()
		return true;
	}

	public function afterSave($created, $options = array()) {
		// update correlation...
		if (isset($this->data['Attribute']['deleted']) && $this->data['Attribute']['deleted']) {
			$this->__beforeSaveCorrelation($this->data['Attribute']);
		} else {
			$this->__afterSaveCorrelation($this->data['Attribute']);
		}
		$result = true;
		// if the 'data' field is set on the $this->data then save the data to the correct file
		if (isset($this->data['Attribute']['type']) && $this->typeIsAttachment($this->data['Attribute']['type']) && !empty($this->data['Attribute']['data'])) {
			$result = $result && $this->saveBase64EncodedAttachment($this->data['Attribute']); // TODO : is this correct?
		}
		return $result;
	}

	public function beforeDelete($cascade = true) {
		// delete attachments from the disk
		$this->read(); // first read the attribute from the db
		if ($this->typeIsAttachment($this->data['Attribute']['type'])) {
			// only delete the file if it exists
			$filepath = APP . "files" . DS . $this->data['Attribute']['event_id'] . DS . $this->data['Attribute']['id'];
			$file = new File($filepath);
			if ($file->exists()) {
				if (!$file->delete()) {
					throw new InternalErrorException('Delete of file attachment failed. Please report to administrator.');
				}
			}
		}
		// update correlation..
		$this->__beforeDeleteCorrelation($this->data['Attribute']['id']);
	}

	public function beforeValidate($options = array()) {
		parent::beforeValidate();

		if (!isset($this->data['Attribute']['type'])) {
			return false;
		}
		// remove leading and trailing blanks
		$this->data['Attribute']['value'] = trim($this->data['Attribute']['value']);

		// make some last changes to the inserted value
		$this->data['Attribute']['value'] = $this->modifyBeforeValidation($this->data['Attribute']['type'], $this->data['Attribute']['value']);

		// set to_ids if it doesn't exist
		if (empty($this->data['Attribute']['to_ids'])) {
		    $this->data['Attribute']['to_ids'] = 0;
		}
		// generate UUID if it doesn't exist
		if (empty($this->data['Attribute']['uuid'])) {
			$this->data['Attribute']['uuid'] = $this->generateUuid();
		}
		// generate timestamp if it doesn't exist
		if (empty($this->data['Attribute']['timestamp'])) {
			$date = new DateTime();
			$this->data['Attribute']['timestamp'] = $date->getTimestamp();
		}
		// TODO: add explanatory comment
		$result = $this->runRegexp($this->data['Attribute']['type'], $this->data['Attribute']['value']);
		if (!$result) {
			$this->invalidate('value', 'This value is blocked by a regular expression in the import filters.');
		} else {
			$this->data['Attribute']['value'] = $result;
		}

		// TODO: add explanatory comment
		if (!isset($this->data['Attribute']['distribution']) || $this->data['Attribute']['distribution'] != 4) $this->data['Attribute']['sharing_group_id'] = 0;
		if (!isset($this->data['Attribute']['distribution'])) $this->data['Attribute']['distribution'] = 5;

		// return true, otherwise the object cannot be saved
		return true;
	}

	public function validCategory($fields) {
		$validCategories = array_keys($this->categoryDefinitions);
		if (in_array($fields['category'], $validCategories)) return true;
		return false;
	}

	public function valueIsUnique ($fields) {
		if (isset($this->data['Attribute']['deleted']) && $this->data['Attribute']['deleted']) return true;
		$value = $fields['value'];
		$eventId = $this->data['Attribute']['event_id'];
		$type = $this->data['Attribute']['type'];
		$toIds = $this->data['Attribute']['to_ids'];
		$category = $this->data['Attribute']['category'];

		// check if the attribute already exists in the same event
		$conditions = array('Attribute.event_id' => $eventId,
				'Attribute.type' => $type,
				'Attribute.category' => $category,
				'Attribute.value' => $value,
				'Attribute.deleted' => false
		);
		if (isset($this->data['Attribute']['id'])) {
			$conditions['Attribute.id !='] = $this->data['Attribute']['id'];
		}

		$params = array('recursive' => -1,
				'conditions' => $conditions,
		);
		if (0 != $this->find('count', $params)) {
			// value isn't unique
			return false;
		}
		// value is unique
		return true;
	}

	public function validateTypeValue($fields) {
		$category = $this->data['Attribute']['category'];
		if (isset($this->categoryDefinitions[$category]['types'])) {
			return in_array($fields['type'], $this->categoryDefinitions[$category]['types']);
		}
		return false;
	}

	public function validateAttributeValue($fields) {
		$value = $fields['value'];
		return $this->runValidation($value, $this->data['Attribute']['type']);
	}

	private $__hexHashLengths = array(
			'authentihash' => 64,
			'md5' => 32,
			'imphash' => 32,
			'sha1' => 40,
			'x509-fingerprint-sha1' => 40,
			'pehash' => 40,
			'sha224' => 56,
			'sha256' => 64,
			'sha384' => 96,
			'sha512' => 128,
			'sha512/224' => 56,
			'sha512/256' => 64,
	);

	public function runValidation($value, $type) {
		$returnValue = false;
		// check data validation
		switch ($type) {
			case 'md5':
			case 'imphash':
			case 'sha1':
			case 'sha224':
			case 'sha256':
			case 'sha384':
			case 'sha512':
			case 'sha512/224':
			case 'sha512/256':
			case 'authentihash':
			case 'x509-fingerprint-sha1':
				$length = $this->__hexHashLengths[$type];
				if (preg_match("#^[0-9a-f]{" . $length . "}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has an invalid length or format (expected: ' . $length . ' hexadecimal characters). Please double check the value or select type "other".';
				}
				break;
			case 'tlsh':
				if (preg_match("#^[0-9a-f]{35,}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has an invalid length or format (expected: at least 35 hexadecimal characters). Please double check the value or select type "other".';
				}
				break;
			case 'pehash':
				if (preg_match("#^[0-9a-f]{40}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'The input doesn\'t match the expected sha1 format (expected: 40 hexadecimal characters). Keep in mind that MISP currently only supports SHA1 for PEhashes, if you would like to get the support extended to other hash types, make sure to create a github ticket about it at https://github.com/MISP/MISP!';
				}
				break;
			case 'ssdeep':
				if (substr_count($value, ':') == 2) {
					$parts = explode(':', $value);
					if (is_numeric($parts[0])) $returnValue = true;
				}
				if (!$returnValue) $returnValue = 'Invalid SSDeep hash. The format has to be blocksize:hash:hash';
				break;
			case 'http-method':
				if (preg_match("#(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH)#", $value)) {
				    $returnValue = true;
				} else {
					$returnValue = 'Unknown HTTP method.';
				}
				break;
			case 'filename|pehash':
				// no newline
				if (preg_match("#^.+\|[0-9a-f]{40}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'The input doesn\'t match the expected filename|sha1 format (expected: filename|40 hexadecimal characters). Keep in mind that MISP currently only supports SHA1 for PEhashes, if you would like to get the support extended to other hash types, make sure to create a github ticket about it at https://github.com/MISP/MISP!';
				}
				break;
			case 'filename|md5':
			case 'filename|sha1':
			case 'filename|imphash':
			case 'filename|sha224':
			case 'filename|sha256':
			case 'filename|sha384':
			case 'filename|sha512':
			case 'filename|sha512/224':
			case 'filename|sha512/256':
			case 'filename|authentihash':
				$parts = explode('|', $type);
				$length = $this->__hexHashLengths[$parts[1]];
				if (preg_match("#^.+\|[0-9a-f]{" . $length . "}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has an invalid length or format (expected: filename|' . $length . ' hexadecimal characters). Please double check the value or select type "other".';
				}
				break;
			case 'filename|ssdeep':
				if (substr_count($value, '|') != 1 || !preg_match("#^.+\|.+$#", $value)) {
					$returnValue = 'Invalid composite type. The format has to be ' . $type . '.';
				} else {
					$composite = explode('|', $value);
					$value = $composite[1];
					if (substr_count($value, ':') == 2) {
						$parts = explode(':', $value);
						if (is_numeric($parts[0])) $returnValue = true;
					}
					if (!$returnValue) $returnValue = 'Invalid SSDeep hash (expected: blocksize:hash:hash).';
				}
				break;
			case 'filename|tlsh':
				if (preg_match("#^.+\|[0-9a-f]{35,}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has an invalid length or format (expected: filename|at least 35 hexadecimal characters). Please double check the value or select type "other".';
				}
				break;
			case 'ip-src':
			case 'ip-dst':
				$parts = explode("/", $value);
				// [0] = the IP
				// [1] = the network address
				if (count($parts) <= 2 ) {
					// IPv4 and IPv6 matching
					if (filter_var($parts[0], FILTER_VALIDATE_IP)) {
						// IP is validated, now check if we have a valid network mask
						if (empty($parts[1])) {
							$returnValue = true;
						} else {
							if (is_numeric($parts[1]) && $parts[1] < 129) {
								$returnValue = true;
							}
						}
					}
				}
				if (!$returnValue) {
					$returnValue = 'IP address has an invalid format. Please double check the value or select type "other".';
				}
				break;
			case 'hostname':
			case 'domain':
				if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z]{2,}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Domain name has an invalid format. Please double check the value or select type "other".';
				}
				break;
			case 'domain|ip':
				if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z]{2,}\|.*$#i", $value)) {
					$parts = explode('|', $value);
					if (filter_var($parts[1], FILTER_VALIDATE_IP)) {
						$returnValue = true;
					} else {
						$returnValue = 'IP address has an invalid format.';
					}
				} else {
					$returnValue = 'Domain name has an invalid format.';
				}
				break;
			case 'email-src':
			case 'email-dst':
			case 'target-email':
			case 'whois-registrant-email':
				// we don't use the native function to prevent issues with partial email addresses
				if (preg_match("#^[A-Z0-9._&%+-]*@[A-Z0-9.\-_]+\.[A-Z]{2,}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Email address has an invalid format. Please double check the value or select type "other".';
				}
				break;
			case 'vulnerability':
				if (preg_match("#^(CVE-)[0-9]{4}(-)[0-9]{4,6}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Invalid format. Expected: CVE-xxxx-xxxx.';
				}
				break;
			case 'named pipe':
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'windows-service-name':
			case 'windows-service-displayname':
				if (strlen($value) > 256 || preg_match('#[\\\/]#', $value)) {
					$returnValue = 'Invalid format. Only values shorter than 256 characters that don\'t include any forward or backward slashes are allowed.';
				} else {
					$returnValue = true;
				}
				break;
			case 'mutex':
			case 'AS':
			case 'snort':
			case 'pattern-in-file':
			case 'pattern-in-traffic':
			case 'pattern-in-memory':
			case 'yara':
			case 'attachment':
			case 'malware-sample':
				$returnValue = true;
				break;
			case 'link':
				if (preg_match('#^(http|ftp)(s)?\:\/\/((([a-z|0-9|\-]{1,25})(\.)?){2,7})($|/.*$)#i', $value) && !preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'comment':
			case 'text':
			case 'other':
				$returnValue = true;
				break;
			case 'target-user':
			case 'campaign-name':
			case 'campaign-id':
			case 'threat-actor':
			case 'target-machine':
			case 'target-org':
			case 'target-location':
			case 'target-external':
			case 'email-subject':
			case 'email-attachment':
			case 'malware-type':
			case 'url':
			case 'uri':
			case 'user-agent':
			case 'regkey':
			case 'regkey|value':
			case 'filename':
			case 'pdb':
            case 'windows-scheduled-task':
            case 'whois-registrant-name':
			case 'whois-registrar':
			case 'whois-creation-date':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'targeted-threat-index':
				if (!is_numeric($value) || $value < 0 || $value > 10) {
					$returnValue = 'The value has to be a number between 0 and 10.';
				} else {
					$returnValue = true;
				}
				break;
			case 'iban':
			case 'bic':
			case 'btc':
				if (preg_match('/^[a-zA-Z0-9]+$/', $value)) {
					$returnValue = true;
				}
				break;
			case 'bin':
			case 'cc-number':
			case 'bank-account-nr':
			case 'aba-rtn':
			case 'prtn':
			case 'whois-registrant-phone':
				if (is_numeric($value)) {
					$returnValue = true;
				}
				break;

			/*
			case 'btc':
				$fTool = new FinancialTool();
				if ($fTool->validateBTC($value)) {
					$returnValue = true;
				}
				break;
			case 'iban':
				$fTool = new FinancialTool();
				if ($fTool->validateIBAN($value)) {
					$returnValue = true;
				}
				break;
			case 'bic':
				$fTool = new FinancialTool();
				if ($fTool->validateBIC($value)) {
					$returnValue = true;
				}
				break;
			case 'bin':
				$fTool = new FinancialTool();
				if ($fTool->validateBIN($value)) {
					$returnValue = true;
				}
				break;
			case 'cc-number':
				$fTool = new FinancialTool();
				if ($fTool->validateCC($value)) {
					$returnValue = true;
				}
				break;
			case 'prtn':
			case 'whois-registrant-phone':
				if (is_numeric($value)) {
					$returnValue = true;
				}
				break;
			*/
		}
		return $returnValue;
	}

	// do some last second modifications before the validation
	public function modifyBeforeValidation($type, $value) {
		switch ($type) {
			case 'md5':
			case 'sha1':
			case 'sha224':
			case 'sha256':
			case 'sha384':
			case 'sha512':
			case 'sha512/224':
			case 'sha512/256':
			case 'domain':
			case 'hostname':
			case 'pehash':
			case 'authentihash':
			case 'imphash':
			case 'tlsh':
			case 'email-src':
			case 'email-dst':
			case 'domain|ip':
				$parts = explode('|', $value);
				if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					// convert IPv6 address to compressed format
					$parts[1] = inet_ntop(inet_pton($value));
					$value = implode('|', $parts);
				}
			case 'target-email':
			case 'whois-registrant-email':
				$value = strtolower($value);
				break;
			case 'filename|md5':
			case 'filename|sha1':
			case 'filename|imphash':
			case 'filename|sha224':
			case 'filename|sha256':
			case 'filename|sha384':
			case 'filename|sha512':
			case 'filename|sha512/224':
			case 'filename|sha512/256':
			case 'filename|authentihash':
			case 'filename|pehash':
			case 'filename|tlsh':
				$pieces = explode('|', $value);
				$value = $pieces[0] . '|' . strtolower($pieces[1]);
				break;
			case 'http-method':
				$value = strtoupper($value);
				break;
			case 'cc-number':
			case 'bin':
				$value = preg_replace('/[^0-9]+/', '', $value);
				break;
			case 'iban':
			case 'bic':
				$value = strtoupper($value);
				$value = preg_replace('/[^0-9A-Z]+/', '', $value);
				break;
			case 'prtn':
			case 'whois-registrant-phone':
				if (substr($value, 0, 1) == '+') $value = '00' . substr($value, 1);
				$value = preg_replace('/[^0-9]+/', '', $value);
				break;
			case 'url':
				$value = preg_replace('/^hxxp/i', 'http', $value);
				$value = preg_replace('/\[\.\]/', '.' , $value);
				break;
			case 'x509-fingerprint-sha1':
				$value = str_replace(':', '', $value);
				$value = strtolower($value);
				break;
			case 'ip-src':
			case 'ip-dst':
				if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					// convert IPv6 address to compressed format
					$value = inet_ntop(inet_pton($value));
				}
				break;
		}
		return $value;
	}

	public function getCompositeTypes() {
		// build the list of composite Attribute.type dynamically by checking if type contains a |
		// default composite types
		$compositeTypes = array('malware-sample');	// TODO hardcoded composite
		// dynamically generated list
		foreach (array_keys($this->typeDefinitions) as $type) {
			$pieces = explode('|', $type);
			if (2 == count($pieces)) {
				$compositeTypes[] = $type;
			}
		}
		return $compositeTypes;
	}

	public function isOwnedByOrg($attributeId, $org) {
		$this->id = $attributeId;
		$this->read();
		return $this->data['Event']['org_id'] === $org;
	}

	public function getRelatedAttributes($attribute, $fields=array()) {
		// LATER getRelatedAttributes($attribute) this might become a performance bottleneck

		// exclude these specific categories from being linked
		switch ($attribute['category']) {
			case 'Antivirus detection':
				return null;
		}
		// exclude these specific types from being linked
		switch ($attribute['type']) {
			case 'other':
			case 'comment':
				return null;
		}

		// prepare the conditions
		$conditions = array(
				'Attribute.event_id !=' => $attribute['event_id'],
				);

		// prevent issues with empty fields
		if (empty($attribute['value1'])) {
			return null;
		}

		if (empty($attribute['value2'])) {
			// no value2, only search for value 1
			$conditions['OR'] = array(
					'Attribute.value1' => $attribute['value1'],
					'Attribute.value2' => $attribute['value1'],
			);
		} else {
			// value2 also set, so search for both
			$conditions['AND'] = array( // TODO was OR
					'Attribute.value1' => array($attribute['value1'],$attribute['value2']),
					'Attribute.value2' => array($attribute['value1'],$attribute['value2']),
			);
		}

		// do the search
		if (empty($fields)) {
			$fields = array('Attribute.*');
		}
		$similarEvents = $this->find('all',array('conditions' => $conditions,
												'fields' => $fields,
												'recursive' => 0,
												'group' => array('Attribute.event_id'),
												'order' => 'Attribute.event_id DESC', )
		);
		return $similarEvents;
	}

	public function typeIsMalware($type) {
		if (in_array($type, $this->zippedDefinitions)) {
			return true;
		} else {
			return false;
		}
	}

	public function typeIsAttachment($type) {
		if ((in_array($type, $this->zippedDefinitions)) || (in_array($type, $this->uploadDefinitions))) {
			return true;
		} else {
			return false;
		}
	}

	public function base64EncodeAttachment($attribute) {
		$filepath = APP . "files" . DS . $attribute['event_id'] . DS . $attribute['id'];
		$file = new File($filepath);
		if (!$file->readable()) {
			return '';
		}
		$content = $file->read();
		return base64_encode($content);
	}

	public function saveBase64EncodedAttachment($attribute) {
		$rootDir = APP . DS . "files" . DS . $attribute['event_id'];
		$dir = new Folder($rootDir, true);						// create directory structure
		$destpath = $rootDir . DS . $attribute['id'];
		$file = new File($destpath, true);						// create the file
		$decodedData = base64_decode($attribute['data']);		// decode
		if ($file->write($decodedData)) {						// save the data
			return true;
		} else {
			// error
			return false;
		}
	}

/**
 * add_attachment method
 *
 * @return void
 */
	public function uploadAttachment($fileP, $realFileName, $malware, $eventId = null, $category = null, $extraPath = '', $fullFileName = '', $dist, $fromGFI = false) {
		// Check if there were problems with the file upload
		// only keep the last part of the filename, this should prevent directory attacks
		$filename = basename($fileP);
		$tmpfile = new File($fileP);

		// save the file-info in the database
		$this->create();
		$this->data['Attribute']['event_id'] = $eventId;
		$this->data['Attribute']['distribution'] = $dist;
		if ($malware) {
			$md5 = !$tmpfile->size() ? md5_file($fileP) : $tmpfile->md5();
			$this->data['Attribute']['category'] = $category ? $category : "Payload delivery";
			$this->data['Attribute']['type'] = "malware-sample";
			$this->data['Attribute']['value'] = $fullFileName ? $fullFileName . '|' . $md5 : $filename . '|' . $md5; // TODO gives problems with bigger files
			$this->data['Attribute']['to_ids'] = 1; // LATER let user choose whether to send this to an IDS
			if ($fromGFI) $this->data['Attribute']['comment'] = 'GFI import';
		} else {
			$this->data['Attribute']['category'] = $category ? $category : "Artifacts dropped";
			$this->data['Attribute']['type'] = "attachment";
			$this->data['Attribute']['value'] = $fullFileName ? $fullFileName : $realFileName;
			$this->data['Attribute']['to_ids'] = 0;
			if ($fromGFI) $this->data['Attribute']['comment'] = 'GFI import';
		}

		if (!$this->save($this->data)) {
			// TODO: error handling
		}

		// no errors in file upload, entry already in db, now move the file where needed and zip it if required.
		// no sanitization is required on the filename, path or type as we save
		// create directory structure
		$rootDir = APP . "files" . DS . $eventId;
		$dir = new Folder($rootDir, true);
		// move the file to the correct location
		$destpath = $rootDir . DS . $this->getID(); // id of the new attribute in the database
		$file = new File($destpath);
		$zipfile = new File($destpath . '.zip');
		$fileInZip = new File($rootDir . DS . $extraPath . $filename);

		// zip and password protect the malware files
		if ($malware) {
			$execRetval = '';
			$execOutput = array();
			exec('zip -j -P infected ' . escapeshellarg($zipfile->path) . ' ' . escapeshellarg($fileInZip->path), $execOutput, $execRetval);
			if ($execRetval != 0) { // not EXIT_SUCCESS
				throw new Exception('An error has occured while attempting to zip the malware file.');
			}
			$fileInZip->delete(); // delete the original non-zipped-file
			rename($zipfile->path, $file->path); // rename the .zip to .nothing
		} else {
			$fileAttach = new File($fileP);
			rename($fileAttach->path, $file->path);
		}
	}

	public function __beforeSaveCorrelation($a) {
		// (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
		// ==> DELETE FROM correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
		// first check if it's an update
		if (isset($a['id'])) {
			$this->Correlation = ClassRegistry::init('Correlation');
			// FIXME : check that $a['id'] is checked correctly so that the user can't remove attributes he shouldn't
			$dummy = $this->Correlation->deleteAll(array('OR' => array(
					'Correlation.1_attribute_id' => $a['id'],
					'Correlation.attribute_id' => $a['id']))
			);
		}
	}

	public function __afterSaveCorrelation($a, $full = false, $event = false) {
		// Don't do any correlation if the type is a non correlating type
		if (!in_array($a['type'], $this->nonCorrelatingTypes)) {
			if (!$event) {
				$event = $this->Event->find('first', array(
						'recursive' => -1,
						'fields' => array('Event.distribution', 'Event.id', 'Event.info', 'Event.org_id', 'Event.date', 'Event.sharing_group_id'),
						'conditions' => array('id' => $a['event_id']),
						'order' => array(),
				));
			}
			$this->Correlation = ClassRegistry::init('Correlation');
			$correlations = array();
			$fields = array('value1', 'value2');
			$correlatingValues = array($a['value1']);
			if (!empty($a['value2'])) $correlatingValues[] = $a['value2'];
			foreach ($correlatingValues as $k => $cV) {
				$correlatingAttributes[$k] = $this->find('all', array(
						'conditions' => array(
							'AND' => array(
								'OR' => array(
										'Attribute.value1' => $cV,
										'Attribute.value2' => $cV
								),
								'Attribute.type !=' => $this->nonCorrelatingTypes,
							),
						),
						'recursive => -1',
						'fields' => array('Attribute.event_id', 'Attribute.id', 'Attribute.distribution', 'Attribute.sharing_group_id'),
						'contain' => array('Event' => array('fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id'))),
						'order' => array(),
				));
				foreach ($correlatingAttributes[$k] as $key => &$correlatingAttribute) {
					if ($correlatingAttribute['Attribute']['id'] == $a['id']) unset($correlatingAttributes[$k][$key]);
					else if ($correlatingAttribute['Attribute']['event_id'] == $a['event_id']) unset($correlatingAttributes[$k][$key]);
					else if ($full && $correlatingAttribute['Attribute']['id'] <= $a['id']) unset($correlatingAttributes[$k][$key]);
				}
			}
			$correlations = array();
			foreach ($correlatingAttributes as $k => $cA) {
				foreach ($cA as $corr) {
					$correlations[] = array(
							'value' => $correlatingValues[$k],
							'1_event_id' => $event['Event']['id'],
							'1_attribute_id' => $a['id'],
							'event_id' => $corr['Attribute']['event_id'],
							'attribute_id' => $corr['Attribute']['id'],
							'org_id' => $corr['Event']['org_id'],
							'distribution' => $corr['Event']['distribution'],
							'a_distribution' => $corr['Attribute']['distribution'],
							'sharing_group_id' => $corr['Event']['sharing_group_id'],
							'a_sharing_group_id' => $corr['Attribute']['sharing_group_id'],
							'date' => $corr['Event']['date'],
							'info' => $corr['Event']['info'],
					);
					$correlations[] = array(
							'value' => $correlatingValues[$k],
							'1_event_id' => $corr['Event']['id'],
							'1_attribute_id' => $corr['Attribute']['id'],
							'event_id' => $a['event_id'],
							'attribute_id' => $a['id'],
							'org_id' => $event['Event']['org_id'],
							'distribution' => $event['Event']['distribution'],
							'a_distribution' => $a['distribution'],
							'sharing_group_id' => $event['Event']['sharing_group_id'],
							'a_sharing_group_id' => $a['sharing_group_id'],
							'date' => $event['Event']['date'],
							'info' => $event['Event']['info'],
					);
				}
			}
			$this->Correlation->saveMany($correlations);
		}
	}

	private function __beforeDeleteCorrelation($attribute_id) {
		$this->Correlation = ClassRegistry::init('Correlation');
		// When we remove an attribute we need to
		// - remove the existing relations related to that attribute, we DO have an id reference
		// ==> DELETE FROM correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id;
		$dummy = $this->Correlation->deleteAll(array('OR' => array(
						'Correlation.1_attribute_id' => $attribute_id,
						'Correlation.attribute_id' => $attribute_id))
		);
	}

	public function checkComposites() {
		$compositeTypes = $this->getCompositeTypes();
		$fails = array();
		$attributes = $this->find('all', array('recursive' => 0));

		foreach ($attributes as $attribute) {
			if ((in_array($attribute['Attribute']['type'], $compositeTypes)) && (!strlen($attribute['Attribute']['value1']) || !strlen($attribute['Attribute']['value2']))) {
				$fails[] = $attribute['Attribute']['event_id'] . ':' . $attribute['Attribute']['id'];
			}
		}
		return $fails;
	}


	public function hids($user, $type, $tags = '', $from = false, $to = false, $last = false) {
		if (empty($user)) throw new MethodNotAllowedException('Could not read user.');
		// check if it's a valid type
		if ($type != 'md5' && $type != 'sha1' && $type != 'sha256') {
			throw new UnauthorizedException('Invalid hash type.');
		}
		$conditions = array();
		$typeArray = array($type, 'filename|' . $type);
		if ($type == 'md5') $typeArray[] = 'malware-sample';
		$rules = array();
		$eventIds = $this->Event->fetchEventIds($user, $from, $to, $last);
		if ($tags !== '') {
			$tag = ClassRegistry::init('Tag');
			$args = $this->dissectArgs($tags);
			$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
			if (!empty($tagArray[0])) {
				foreach ($eventIds as $k => $v) {
					if (!in_array($v['Event']['id'], $tagArray[0])) unset($eventIds[$k]);
				}
			}
			if (!empty($tagArray[1])) {
				foreach ($eventIds as $k => $v) {
					if (in_array($v['Event']['id'], $tagArray[1])) unset($eventIds[$k]);
				}
			}
		}
		App::uses('HidsExport', 'Export');
		$continue = false;
		foreach ($eventIds as $event) {
			$conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1, 'Attribute.type' => $typeArray, 'Attribute.event_id' => $event['Event']['id']);
			$options = array(
					'conditions' => $conditions,
					'group' => array('Attribute.type', 'Attribute.value1'),
			);
			$items = $this->fetchAttributes($user, $options);
			if (empty($items)) continue;
			$export = new HidsExport();
			$rules = array_merge($rules, $export->export($items, strtoupper($type), $continue));
			$continue = true;
		}
		return $rules;
	}


	public function nids($user, $format, $id = false, $continue = false, $tags = false, $from = false, $to = false, $last = false) {
		if (empty($user)) throw new MethodNotAllowedException('Could not read user.');
		$eventIds = $this->Event->fetchEventIds($user, $from, $to, $last);

		// If we sent any tags along, load the associated tag names for each attribute
		if ($tags) {
			$tag = ClassRegistry::init('Tag');
			$args = $this->dissectArgs($tags);
			$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
			if (!empty($tagArray[0])) {
				foreach ($eventIds as $k => $v) {
					if (!in_array($v['Event']['id'], $tagArray[0])) unset($eventIds[$k]);
				}
			}
			if (!empty($tagArray[1])) {
				foreach ($eventIds as $k => $v) {
					if (in_array($v['Event']['id'], $tagArray[1])) unset($eventIds[$k]);
				}
			}
		}

		if ($id) {
			foreach ($eventIds as $k => $v) {
				if ($v['Event']['id'] !== $id) unset($eventIds[$k]);
			}
		}

		if ($format == 'suricata') App::uses('NidsSuricataExport', 'Export');
		else App::uses('NidsSnortExport', 'Export');

		$rules = array();
		foreach ($eventIds as $event) {
			$conditions['AND'] = array('Attribute.to_ids' => 1, "Event.published" => 1, 'Attribute.event_id' => $event['Event']['id']);
			$valid_types = array('ip-dst', 'ip-src', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'domain', 'hostname', 'url', 'user-agent', 'snort');
			$conditions['AND']['Attribute.type'] = $valid_types;

			$params = array(
					'conditions' => $conditions, // array of conditions
					'recursive' => -1, // int
					'fields' => array('Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.value'),
					'contain' => array('Event'=> array('fields' => array('Event.id', 'Event.threat_level_id'))),
					'group' => array('Attribute.type', 'Attribute.value1'), // fields to GROUP BY
			);
			$items = $this->fetchAttributes($user, $params);
			if (empty($items)) continue;
			// export depending on the requested type
			switch ($format) {
				case 'suricata':
					$export = new NidsSuricataExport();
					break;
				case 'snort':
					$export = new NidsSnortExport();
					break;
			}
			$rules = array_merge($rules, $export->export($items, $user['nids_sid'], $format, $continue));
			// Only prepend the comments once
			$continue = true;
		}
		return $rules;
	}

	public function text($user, $type, $tags = false, $eventId = false, $allowNonIDS = false, $from = false, $to = false, $last = false) {
		//restricting to non-private or same org if the user is not a site-admin.
		$conditions['AND'] = array();
		if ($allowNonIDS === false) $conditions['AND'] = array('Attribute.to_ids =' => 1, 'Event.published =' => 1);
		if ($type !== 'all') $conditions['AND']['Attribute.type'] = $type;
		if ($from) $conditions['AND']['Event.date >='] = $from;
		if ($to) $conditions['AND']['Event.date <='] = $to;
		if ($last) $conditions['AND']['Event.publish_timestamp >='] = $last;

		if ($eventId !== false) {
			$conditions['AND'][] = array('Event.id' => $eventId);
		} else if ($tags !== false) {
			// If we sent any tags along, load the associated tag names for each attribute
			$tag = ClassRegistry::init('Tag');
			$args = $this->dissectArgs($tags);
			$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
			$temp = array();
			foreach ($tagArray[0] as $accepted) {
				$temp['OR'][] = array('Event.id' => $accepted);
			}
			$conditions['AND'][] = $temp;
			$temp = array();
			foreach ($tagArray[1] as $rejected) {
				$temp['AND'][] = array('Event.id !=' => $rejected);
			}
			$conditions['AND'][] = $temp;
		}
		$attributes = $this->fetchAttributes($user, array(
				'conditions' => $conditions,
				'order' => 'Attribute.value1 ASC',
				'fields' => array('value'),
				'contain' => array('Event' => array(
					'fields' => array('Event.id', 'Event.published', 'Event.date', 'Event.publish_timestamp'),
		))));
		return $attributes;
	}

	public function rpz($user, $tags = false, $eventId = false, $from = false, $to = false) {
		// we can group hostname and domain as well as ip-src and ip-dst in this case
		$conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1);
		$typesToFetch = array('ip' => array('ip-src', 'ip-dst'), 'domain' => array('domain'), 'hostname' => array('hostname'));
		if ($from) $conditions['AND']['Event.date >='] = $from;
		if ($to) $conditions['AND']['Event.date <='] = $to;
		if ($eventId !== false) {
			$conditions['AND'][] = array('Event.id' => $eventId);
		}
		if ($tags !== false) {
			// If we sent any tags along, load the associated tag names for each attribute
			$tag = ClassRegistry::init('Tag');
			$args = $this->dissectArgs($tags);
			$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
			$temp = array();
			foreach ($tagArray[0] as $accepted) {
				$temp['OR'][] = array('Event.id' => $accepted);
			}
			$conditions['AND'][] = $temp;
			$temp = array();
			foreach ($tagArray[1] as $rejected) {
				$temp['AND'][] = array('Event.id !=' => $rejected);
			}
			$conditions['AND'][] = $temp;
		}
		$values = array();
		foreach ($typesToFetch as $k => $v) {
			$temp = $this->fetchAttributes(
					$user,
					array(
						'conditions' => array(
							$conditions,
							array('type' => $v),
						),
						'fields' => array('Attribute.value'), // array of field names
					)
			);
			if (empty($temp)) continue;
			if ($k == 'hostname') {
				foreach ($temp as $value) {
					$found = false;
					if (isset($values['domain'])) {
						foreach ($values['domain'] as $domain) {
							if (strpos($value['Attribute']['value'], $domain) != 0) {
								$found = true;
							}
						}
					}
					if (!$found) $values[$k][] = $value['Attribute']['value'];
				}
			} else {
				foreach ($temp as $value) {
					$values[$k][] = $value['Attribute']['value'];
				}
			}
			unset($temp);
		}
		return $values;
	}

	public function generateCorrelation($jobId = false, $startPercentage = 0) {
		$this->Correlation = ClassRegistry::init('Correlation');
		$this->Correlation->deleteAll(array('id !=' => 0), false);
		// get all attributes..
		$eventIds = $this->Event->find('list', array('recursive' => -1, 'fields' => array('Event.id')));
		$attributeCount = 0;
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job = ClassRegistry::init('Job');
			$this->Job->id = $jobId;
			$eventCount = count($eventIds);
		}
		foreach (array_values($eventIds) as $j => $id) {
			if ($jobId && Configure::read('MISP.background_jobs')) {
				$this->Job->saveField('message', 'Correlating Event ' . $id);
				$this->Job->saveField('progress', ($startPercentage + ($j / $eventCount * (100 - $startPercentage))));
			}
			$event = $this->Event->find('first', array(
					'recursive' => -1,
					'fields' => array('Event.distribution', 'Event.id', 'Event.info', 'Event.org_id', 'Event.date', 'Event.sharing_group_id'),
					'conditions' => array('id' => $id),
					'order' => array()
			));
			$attributes = $this->find('all', array('recursive' => -1, 'conditions' => array('Attribute.event_id' => $id, 'Attribute.deleted' => false), 'order' => array()));
			foreach ($attributes as $k => $attribute) {
				$this->__afterSaveCorrelation($attribute['Attribute'], true, $event);
				$attributeCount++;
			}
		}
		if ($jobId && Configure::read('MISP.background_jobs')) $this->Job->saveField('message', 'Job done.');
		return $attributeCount;
	}

	public function reportValidationIssuesAttributes($eventId) {
		$conditions = array();
		if ($eventId && is_numeric($eventId)) $conditions = array('event_id' => $eventId);

		// get all attributes..
		$attributes = $this->find('all', array('recursive' => -1, 'fields' => array('id'), 'conditions' => $conditions));
		// for all attributes..
		$result = array();
		$i = 0;
		foreach ($attributes as $a) {
			$attribute = $this->find('first', array('recursive' => -1, 'conditions' => array('id' => $a['Attribute']['id'])));
			$this->set($attribute);
			if (!$this->validates()) {
				$errors = $this->validationErrors;
				$result[$i]['id'] = $attribute['Attribute']['id'];
				$result[$i]['error'] = array();
				foreach ($errors as $field => $error) {
					$result[$i]['error'][$field] = array('value' => $attribute['Attribute'][$field], 'error' => $error[0]);
				}
				$result[$i]['details'] = 'Event ID: [' . $attribute['Attribute']['event_id'] . "] - Category: [" . $attribute['Attribute']['category'] . "] - Type: [" . $attribute['Attribute']['type'] . "] - Value: [" . $attribute['Attribute']['value'] . ']';
				$i++;
			}
		}
		return $result;
	}

	// This method takes a string from an argument with several elements (separated by '&&' and negated by '!') and returns 2 arrays
	// array 1 will have all of the non negated terms and array 2 all the negated terms
	public function dissectArgs($args) {
		if (!$args) return array(null, null);
		if (is_array($args)) {
			$argArray = $args;
		} else {
			$argArray = explode('&&', $args);
		}
		$accept = $reject = $result = array();
		$reject = array();
		foreach ($argArray as $arg) {
			if (substr($arg, 0, 1) == '!') {
				$reject[] = substr($arg, 1);
			} else {
				$accept[] = $arg;
			}
		}
		$result[0] = $accept;
		$result[1] = $reject;
		return $result;
	}

	public function checkForValidationIssues($attribute) {
		$this->set($attribute);
		if ($this->validates()) {
			return false;
		} else {
			return $this->validationErrors;
		}
	}


	public function checkTemplateAttributes($template, &$data, $event_id) {
		$result = array();
		$errors = array();
		$attributes = array();
		if (isset($data['Template']['fileArray'])) $fileArray = json_decode($data['Template']['fileArray'], true);
		foreach ($template['TemplateElement'] as $element) {
			if ($element['element_definition'] == 'attribute') {
				$result = $this->__resolveElementAttribute($element['TemplateElementAttribute'][0], $data['Template']['value_' . $element['id']]);
			} else if ($element['element_definition'] == 'file') {
				$temp = array();
				if (isset($fileArray)) {
					foreach ($fileArray as $fileArrayElement) {
						if ($fileArrayElement['element_id'] == $element['id']) {
							$temp[] = $fileArrayElement;
						}
					}
				}
				$result = $this->__resolveElementFile($element['TemplateElementFile'][0], $temp);
				if ($element['TemplateElementFile'][0]['mandatory'] && empty($temp) && empty($errors[$element['id']])) $errors[$element['id']] = 'This field is mandatory.';
			}
			if ($element['element_definition'] == 'file' || $element['element_definition'] == 'attribute') {
				if ($result['errors']) {
					$errors[$element['id']] = $result['errors'];
				} else {
					foreach ($result['attributes'] as &$a) {
						$a['event_id'] = $event_id;
						$a['distribution'] = 5;
						$test = $this->checkForValidationIssues(array('Attribute' => $a));
						if ($test) {
							foreach ($test['value'] as $e) {
								$errors[$element['id']] = $e;
							}
						} else {
							$attributes[] = $a;
						}
					}
				}
			}
		}
		return array('attributes' => $attributes, 'errors' => $errors);
	}


	private function __resolveElementAttribute($element, $value) {
		$attributes = array();
		$results = array();
		$errors = null;
		if (!empty($value)) {
				if ($element['batch']) {
				$values = explode("\n", $value);
				foreach ($values as $v) {
					$v = trim($v);
					$attributes[] = $this->__createAttribute($element, $v);
				}
			} else {
				$attributes[] = $this->__createAttribute($element, trim($value));
			}
			foreach ($attributes as $att) {
				if (isset($att['multi'])) {
					foreach ($att['multi'] as $a) {
						$results[] = $a;
					}
				} else {
					$results[] = $att;
				}
			}
		} else {
			if ($element['mandatory']) $errors = 'This field is mandatory.';
		}
		return array('attributes' => $results, 'errors' => $errors);
	}

	private function __resolveElementFile($element, $files) {
		$attributes = array();
		$errors = null;
		$element['complex'] = false;
		if ($element['malware']) {
			$element['type'] = 'malware-sample';
			$element['to_ids'] = true;
		} else {
			$element['type'] = 'attachment';
			$element['to_ids'] = false;
		}
		foreach ($files as $file) {
			if (!preg_match('@^[\w\-. ]+$@', $file['filename'])) {
				$errors = 'Filename not allowed.';
				continue;
			}
			if ($element['malware']) {
				$malwareName = $file['filename'] . '|' . hash_file('md5', APP . 'tmp/files/' . $file['tmp_name']);
				$tmp_file = new File(APP . 'tmp/files/' . $file['tmp_name']);
				if (!$tmp_file->readable()) {
					$errors = 'File cannot be read.';
				} else {
					$element['type'] = 'malware-sample';
					$attributes[] = $this->__createAttribute($element, $malwareName);
					$attributes[count($attributes) - 1]['data'] = $file['tmp_name'];
					$element['type'] = 'filename|sha256';
					$sha256 = $file['filename'] . '|' . (hash_file('sha256', APP . 'tmp/files/' . $file['tmp_name']));
					$attributes[] = $this->__createAttribute($element, $sha256);
					$element['type'] = 'filename|sha1';
					$sha1 = $file['filename'] . '|' . (hash_file('sha1', APP . 'tmp/files/' . $file['tmp_name']));
					$attributes[] = $this->__createAttribute($element, $sha1);
				}
			} else {
				$attributes[] = $this->__createAttribute($element, $file['filename']);
				$tmp_file = new File(APP . 'tmp/files/' . $file['tmp_name']);
				if (!$tmp_file->readable()) {
					$errors = 'File cannot be read.';
				} else {
					$attributes[count($attributes) - 1]['data'] = $file['tmp_name'];
				}
			}
		}
		return array('attributes' => $attributes, 'errors' => $errors, 'files' => $files);
	}

	private function __createAttribute($element, $value) {
		$attribute = array(
				'comment' => $element['name'],
				'to_ids' => $element['to_ids'],
				'category' => $element['category'],
				'value' => $value,
		);
		if ($element['complex']) {
			App::uses('ComplexTypeTool', 'Tools');
			$complexTypeTool = new ComplexTypeTool();
			$result = $complexTypeTool->checkComplexRouter($value, ucfirst($element['type']));
			if (isset($result['multi'])) {
				$temp = $attribute;
				$attribute = array();
				foreach ($result['multi'] as $k => $r) {
					$attribute['multi'][] = $temp;
					$attribute['multi'][$k]['type'] = $r['type'];
					$attribute['multi'][$k]['value'] = $r['value'];
				}
			} else if ($result != false) {
				$attribute['type'] = $result['type'];
				$attribute['value'] = $result['value'];
			} else {
				return false;
			}
		} else {
			$attribute['type'] = $element['type'];
		}
		return $attribute;
	}

	public function buildConditions($user) {
		$conditions = array();
		if (!$user['Role']['perm_site_admin']) {
			$eventIds = $this->Event->fetchEventIds($user, false, false, false, true);
			$sgsids = $this->SharingGroup->fetchAllAuthorised($user);
			$conditions = array(
				'AND' => array(
					'OR' => array(
						array(
							'AND' => array(
								'Event.org_id' => $user['org_id'],
							)
						),
						array(
							'AND' => array(
								'Event.id' => $eventIds,
								'OR' => array(
									'Attribute.distribution' => array('1', '2', '3', '5'),
									'AND '=> array(
										'Attribute.distribution' => 4,
										'Attribute.sharing_group_id' => $sgsids,
									)
								)
							)
						)
					)
				)
			);
		}
		return $conditions;
	}

	// Method that fetches all attributes for the various exports
	// very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
	// options:
	//     fields
	//     contain
	//     conditions
	//     order
	//     group
	public function fetchAttributes($user, $options = array()) {
		$params = array(
			'conditions' => $this->buildConditions($user),
			'recursive' => -1,
			'contain' => array(
				'Event' => array(
					'fields' => array('id', 'info', 'org_id'),
				),
			),
		);
		if (isset($options['contain'])) $params['contain'] = array_merge_recursive($params['contain'], $options['contain']);
		else $option['contain']['Event']['fields'] = array('id', 'info', 'org_id');
		if (isset($options['fields'])) $params['fields'] = $options['fields'];
		if (isset($options['conditions'])) $params['conditions']['AND'][] = $options['conditions'];
		if (isset($options['order'])) $params['order'] = $options['order'];
		else ($params['order'] = array());
		if (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted']) $params['conditions']['AND']['Attribute.deleted'] = false;
		if (isset($options['group'])) $params['group'] = $options['group'];
		if (Configure::read('MISP.unpublishedprivate')) $params['conditions']['AND'][] = array('OR' => array('Event.published' => 1, 'Event.orgc_id' => $user['org_id']));
		$results = $this->find('all', $params);
		if (isset($options['withAttachments']) && $options['withAttachments']) {
			foreach ($results as &$attribute) {
				if ($this->typeIsAttachment($attribute['Attribute']['type'])) {
					$encodedFile = $this->base64EncodeAttachment($attribute['Attribute']);
					$attribute['Attribute']['data'] = $encodedFile;
				}
			}
		}
		return $results;
	}

	// Method gets and converts the contents of a file passed along as a base64 encoded string with the original filename into a zip archive
	// The zip archive is then passed back as a base64 encoded string along with the md5 hash and a flag whether the transaction was successful
	// The archive is password protected using the "infected" password
	// The contents of the archive will be the actual sample, named <md5> and the original filename in a text file named <md5>.filename.txt
	public function handleMaliciousBase64($event_id, $original_filename, $base64, $hash_types, $proposal = false) {
		if (!is_numeric($event_id)) throw new Exception('Something went wrong. Received a non-numeric event ID while trying to create a zip archive of an uploaded malware sample.');
		if ($proposal) {
			$dir = new Folder(APP . "files" . DS . $event_id . DS . 'shadow', true);
		} else {
			$dir = new Folder(APP . "files" . DS . $event_id, true);
		}
		$tmpFile = new File($dir->path . DS . $this->generateRandomFileName(), true, 0600);
		$tmpFile->write(base64_decode($base64));
		$hashes = array();
		foreach ($hash_types as $hash) {
			$hashes[$hash] = $this->__hashRouter($hash, $tmpFile->path);
		}
		$contentsFile = new File($dir->path . DS . $hashes['md5']);
		rename($tmpFile->path, $contentsFile->path);
		$fileNameFile = new File($dir->path . DS . $hashes['md5'] . '.filename.txt');
		$fileNameFile->write($original_filename);
		$fileNameFile->close();
		$zipFile = new File($dir->path . DS . $hashes['md5'] . '.zip');
		exec('zip -j -P infected ' . escapeshellarg($zipFile->path) . ' ' . escapeshellarg($contentsFile->path) . ' ' . escapeshellarg($fileNameFile->path), $execOutput, $execRetval);
		if ($execRetval != 0) $result = array('success' => false);
		else $result = array_merge(array('data' => base64_encode($zipFile->read()), 'success' => true), $hashes);
		$fileNameFile->delete();
		$zipFile->delete();
		$contentsFile->delete();
		return $result;
	}

	private function __hashRouter($hashType, $file) {
		$validHashes = array('md5', 'sha1', 'sha256');
		if (!in_array($hashType, $validHashes)) return false;
		switch ($hashType) {
			case 'md5':
			case 'sha1':
			case 'sha256':
				return hash_file($hashType, $file);
				break;
		}
		return false;
	}

	public function generateRandomFileName() {
		$length = 12;
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charLen = strlen($characters) - 1;
		$fn = '';
		for ($p = 0; $p < $length; $p++) {
			$fn .= $characters[rand(0, $charLen)];
		}
		return $fn;
	}

	public function resolveHashType($hash) {
		$hashTypes = $this->hashTypes;
		$validTypes = array();
		$length = strlen($hash);
		foreach ($hashTypes as $k => $hashType) {
			$temp = $hashType['lowerCase'] ? strtolower($hash) : $hash;
			if ($hashType['length'] == $length && preg_match($hashType['pattern'], $temp)) $validTypes[] = $k;
		}
		return $validTypes;
	}

	public function validateAttribute($attribute, $context = true) {
		$this->set($attribute);
		if (!$context) {
			unset($this->validate['event_id']);
			unset($this->validate['value']['uniqueValue']);
		}
		if ($this->validates()) return true;
		else {
			return $this->validationErrors;
		}
	}

	public function restore($id, $user) {
		$this->id = $id;
		if (!$this->exists()) return 'Attribute doesn\'t exist, or you lack the permission to edit it.';
		$attribute = $this->find('first', array('conditions' => array('Attribute.id' => $id), 'recursive' => -1, 'contain' => array('Event')));
		if (!$user['Role']['perm_site_admin']) {
			if (!($attribute['Event']['orgc_id'] == $user['org_id'] && (($user['Role']['perm_modify'] && $attribute['Event']['user_id'] != $user['id']) || $user['Role']['perm_modify_org']))) {
				return 'Attribute doesn\'t exist, or you lack the permission to edit it.';
			}
		}
		unset($attribute['Attribute']['timestamp']);
		$attribute['Attribute']['deleted'] = false;
		$date = new DateTime();
		$attribute['Attribute']['timestamp'] = $date->getTimestamp();
		if ($this->save($attribute['Attribute'])) {
			$attribute['Event']['published'] = false;
			$attribute['Event']['timestamp'] = $date->getTimestamp();
			$this->Event->save($attribute['Event']);
			return true;
		}
		else return 'Could not save changes.';
	}
}
