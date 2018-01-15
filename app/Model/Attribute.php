<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('FinancialTool', 'Tools');
App::uses('RandomTool', 'Tools');

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

	public $displayField = 'value';

	public $virtualFields = array(
			'value' => "CASE WHEN Attribute.value2 = '' THEN Attribute.value1 ELSE CONCAT(Attribute.value1, '|', Attribute.value2) END",
	); // TODO hardcoded

	 // explanations of certain fields to be used in various views
	public $fieldDescriptions = array(
			'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
			'distribution' => array('desc' => 'Describes who will have access to the event.')
	);

	public $distributionDescriptions = array(
		0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of your organisation on this server to see it."),
		1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Organisations that are part of this MISP community will be able to see the event."),
		2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Organisations that are either part of this MISP community or part of a directly connected MISP community will be able to see the event."),
		3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
		4 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This distribution of this event will be handled by the selected sharing group."),
		5 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Inherit the event's distribution settings"),
	);

	public $distributionLevels = array(
			0 => 'Your organisation only', 1 => 'This community only', 2 => 'Connected communities', 3 => 'All communities', 4 => 'Sharing group', 5 => 'Inherit event'
	);

	public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' Sharing Group', 5 => 'Inherit');

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
			'comment',
			'http-method',
			'aba-rtn',
			'gender',
			'counter',
			'port',
			'nationality',
			'cortex'
	);

	public $primaryOnlyCorrelatingTypes = array(
		'ip-src|port',
		'ip-dst|port'
	);

	public $searchResponseTypes = array(
		'xml' => array(
			'type' => 'xml',
			'layout' => 'xml/default',
			'header' => 'Content-Disposition: download; filename="misp.search.attribute.results.xml"'
		),
		'json' => array(
			'type' => 'json',
			'layout' => 'json/default',
			'header' => 'Content-Disposition: download; filename="misp.search.attribute.results.json"'
		),
		'openioc' => array(
			'type' => 'xml',
			'layout' => 'xml/default',
			'header' => 'Content-Disposition: download; filename="misp.search.attribute.results.openioc.xml"'
		),
	);

	public $typeDefinitions = array(
			'md5' => array('desc' => 'A checksum in md5 format', 'formdesc' => "You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha1' => array('desc' => 'A checksum in sha1 format', 'formdesc' => "You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha256' => array('desc' => 'A checksum in sha256 format', 'formdesc' => "You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename' => array('desc' => 'Filename', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'pdb' => array('desc' => 'Microsoft Program database (PDB) path information', 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
			'filename|md5' => array('desc' => 'A filename and an md5 hash separated by a |', 'formdesc' => "A filename and an md5 hash separated by a | (no spaces)", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha1' => array('desc' => 'A filename and an sha1 hash separated by a |', 'formdesc' => "A filename and an sha1 hash separated by a | (no spaces)", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha256' => array('desc' => 'A filename and an sha256 hash separated by a |', 'formdesc' => "A filename and an sha256 hash separated by a | (no spaces)", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'ip-src' => array('desc' => "A source IP address of the attacker", 'default_category' => 'Network activity', 'to_ids' => 1),
			'ip-dst' => array('desc' => 'A destination IP address of the attacker or C&C server', 'formdesc' => "A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware", 'default_category' => 'Network activity', 'to_ids' => 1),
			'hostname' => array('desc' => 'A full host/dnsname of an attacker', 'formdesc' => "A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware", 'default_category' => 'Network activity', 'to_ids' => 1),
			'domain' => array('desc' => 'A domain name used in the malware', 'formdesc' => "A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events.", 'default_category' => 'Network activity', 'to_ids' => 1),
			'domain|ip' => array('desc' => 'A domain name and its IP address (as found in DNS lookup) separated by a |','formdesc' => "A domain name and its IP address (as found in DNS lookup) separated by a | (no spaces)", 'default_category' => 'Network activity', 'to_ids' => 1),
			'email-src' => array('desc' => "The email address used to send the malware.", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'email-dst' => array('desc' => "A recipient email address", 'formdesc' => "A recipient email address that is not related to your constituency.", 'default_category' => 'Network activity', 'to_ids' => 1),
			'email-subject' => array('desc' => "The subject of the email", 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-attachment' => array('desc' => "File name of the email attachment.", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'email-body' => array('desc' => 'Email body', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'float' => array('desc' => "A floating point value.", 'default_category' => 'Other', 'to_ids' => 0),
			'url' => array('desc' => 'url', 'default_category' => 'External analysis', 'to_ids' => 1),
			'http-method' => array('desc' => "HTTP method used by the malware (e.g. POST, GET, ...).", 'default_category' => 'Network activity', 'to_ids' => 0),
			'user-agent' => array('desc' => "The user-agent used by the malware in the HTTP request.", 'default_category' => 'Network activity', 'to_ids' => 0),
			'regkey' => array('desc' => "Registry key or value", 'default_category' => 'Persistence mechanism', 'to_ids' => 1),
			'regkey|value' => array('desc' => "Registry value + data separated by |", 'default_category' => 'Persistence mechanism', 'to_ids' => 1),
			'AS' => array('desc' => 'Autonomous system', 'default_category' => 'Network activity', 'to_ids' => 0),
			'snort' => array('desc' => 'An IDS rule in Snort rule-format', 'formdesc' => "An IDS rule in Snort rule-format. This rule will be automatically rewritten in the NIDS exports.", 'default_category' => 'Network activity', 'to_ids' => 1),
			'pattern-in-file' => array('desc' => 'Pattern in file that identifies the malware', 'default_category' => 'Payload installation', 'to_ids' => 1),
			'pattern-in-traffic' => array('desc' => 'Pattern in network traffic that identifies the malware', 'default_category' => 'Network activity', 'to_ids' => 1),
			'pattern-in-memory' => array('desc' => 'Pattern in memory dump that identifies the malware', 'default_category' => 'Payload installation', 'to_ids' => 1),
      'yara' => array('desc' => 'Yara signature', 'default_category' => 'Payload installation', 'to_ids' => 1),
      'stix2-pattern' => array('desc' => 'STIX 2 pattern', 'default_category' => 'Payload installation', 'to_ids' => 1),
			'sigma' => array('desc' => 'Sigma - Generic Signature Format for SIEM Systems', 'default_category' => 'Payload installation', 'to_ids' => 1),
			'cookie' => array('desc' => 'HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie.', 'default_category' => 'Network activity', 'to_ids' => 0),
			'vulnerability' => array('desc' => 'A reference to the vulnerability used in the exploit', 'default_category' => 'External analysis', 'to_ids' => 0),
			'attachment' => array('desc' => 'Attachment with external information', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button.", 'default_category' => 'External analysis', 'to_ids' => 0),
			'malware-sample' => array('desc' => 'Attachment containing encrypted malware sample', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button.", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'link' => array('desc' => 'Link to an external information', 'default_category' => 'External analysis', 'to_ids' => 0),
			'comment' => array('desc' => 'Comment or description in a human language', 'formdesc' => 'Comment or description in a human language.  This will not be correlated with other attributes', 'default_category' => 'Other', 'to_ids' => 0),
			'text' => array('desc' => 'Name, ID or a reference', 'default_category' => 'Other', 'to_ids' => 0),
			'hex' => array('desc' => 'A value in hexadecimal format', 'default_category' => 'Other', 'to_ids' => 0),
			'other' => array('desc' => 'Other attribute', 'default_category' => 'Other', 'to_ids' => 0),
			'named pipe' => array('desc' => 'Named pipe, use the format \\.\pipe\<PipeName>', 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
			'mutex' => array('desc' => 'Mutex, use the format \BaseNamedObjects\<Mutex>', 'default_category' => 'Artifacts dropped', 'to_ids' => 1),
			'target-user' => array('desc' => 'Attack Targets Username(s)', 'default_category' => 'Targeting data', 'to_ids' => 0),
			'target-email' => array('desc' => 'Attack Targets Email(s)', 'default_category' => 'Targeting data', 'to_ids' => 0),
			'target-machine' => array('desc' => 'Attack Targets Machine Name(s)', 'default_category' => 'Targeting data', 'to_ids' => 0),
			'target-org' => array('desc' => 'Attack Targets Department or Organization(s)', 'default_category' => 'Targeting data', 'to_ids' => 0),
			'target-location' => array('desc' => 'Attack Targets Physical Location(s)', 'default_category' => 'Targeting data', 'to_ids' => 0),
			'target-external' => array('desc' => 'External Target Organizations Affected by this Attack', 'default_category' => 'Targeting data', 'to_ids' => 0),
			'btc' => array('desc' => 'Bitcoin Address', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'iban' => array('desc' => 'International Bank Account Number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'bic' => array('desc' => 'Bank Identifier Code Number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'bank-account-nr' => array('desc' => 'Bank account number without any routing number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'aba-rtn' => array('desc' => 'ABA routing transit number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'bin' => array('desc' => 'Bank Identification Number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'cc-number' => array('desc' => 'Credit-Card Number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'prtn' => array('desc' => 'Premium-Rate Telephone Number', 'default_category' => 'Financial fraud', 'to_ids' => 1),
			'phone-number' => array('desc' => 'Telephone Number', 'default_category' => 'Person', 'to_ids' => 0),
			'threat-actor' => array('desc' => 'A string identifying the threat actor', 'default_category' => 'Attribution', 'to_ids' => 0),
			'campaign-name' => array('desc' => 'Associated campaign name', 'default_category' => 'Attribution', 'to_ids' => 0),
			'campaign-id' => array('desc' => 'Associated campaign ID', 'default_category' => 'Attribution', 'to_ids' => 0),
			'malware-type' => array('desc' => '', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'uri' => array('desc' => 'Uniform Resource Identifier', 'default_category' => 'Network activity', 'to_ids' => 1),
			'authentihash' => array('desc' => 'Authenticode executable signature hash', 'formdesc' => "You are encouraged to use filename|authentihash instead. Authenticode executable signature hash, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'ssdeep' => array('desc' => 'A checksum in ssdeep format', 'formdesc' => "You are encouraged to use filename|ssdeep instead. A checksum in the SSDeep format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'imphash' => array('desc' => 'Import hash - a hash created based on the imports in the sample.', 'formdesc' => "You are encouraged to use filename|imphash instead. A hash created based on the imports in the sample, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'pehash' => array('desc' => 'PEhash - a hash calculated based of certain pieces of a PE executable file', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'impfuzzy' => array('desc' => 'A fuzzy hash of import table of Portable Executable format', 'formdesc' => "You are encouraged to use filename|impfuzzy instead. A fuzzy hash created based on the imports in the sample, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha224' => array('desc' => 'A checksum in sha-224 format', 'formdesc' => "You are encouraged to use filename|sha224 instead. A checksum in sha224 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha384' => array('desc' => 'A checksum in sha-384 format', 'formdesc' => "You are encouraged to use filename|sha384 instead. A checksum in sha384 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha512' => array('desc' => 'A checksum in sha-512 format', 'formdesc' => "You are encouraged to use filename|sha512 instead. A checksum in sha512 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha512/224' => array('desc' => 'A checksum in the sha-512/224 format', 'formdesc' => "You are encouraged to use filename|sha512/224 instead. A checksum in sha512/224 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'sha512/256' => array('desc' => 'A checksum in the sha-512/256 format', 'formdesc' => "You are encouraged to use filename|sha512/256 instead. A checksum in sha512/256 format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'tlsh' => array('desc' => 'A checksum in the Trend Micro Locality Sensitive Hash format', 'formdesc' => "You are encouraged to use filename|tlsh instead. A checksum in the Trend Micro Locality Sensitive Hash format, only use this if you don't know the correct filename", 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|authentihash' => array('desc' => 'A checksum in md5 format', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|ssdeep' => array('desc' => 'A checksum in ssdeep format', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|imphash' => array('desc' => 'Import hash - a hash created based on the imports in the sample.', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|impfuzzy' => array('desc' => 'Import fuzzy hash - a fuzzy hash created based on the imports in the sample.', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|pehash' => array('desc' => 'A filename and a PEhash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha224' => array('desc' => 'A filename and a sha-224 hash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha384' => array('desc' => 'A filename and a sha-384 hash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha512' => array('desc' => 'A filename and a sha-512 hash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha512/224' => array('desc' => 'A filename and a sha-512/224 hash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|sha512/256' => array('desc' => 'A filename and a sha-512/256 hash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'filename|tlsh' => array('desc' => 'A filename and a Trend Micro Locality Sensitive Hash separated by a |', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'windows-scheduled-task' => array('desc' => 'A scheduled task in windows', 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
			'windows-service-name' => array('desc' => 'A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname.', 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
			'windows-service-displayname' => array('desc' => 'A windows service\'s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service\'s name in applications.', 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
			'whois-registrant-email' => array('desc' => 'The e-mail of a domain\'s registrant, obtained from the WHOIS information.', 'default_category' => 'Attribution', 'to_ids' => 0),
			'whois-registrant-phone' => array('desc' => 'The phone number of a domain\'s registrant, obtained from the WHOIS information.', 'default_category' => 'Attribution', 'to_ids' => 0),
			'whois-registrant-name' => array('desc' => 'The name of a domain\'s registrant, obtained from the WHOIS information.', 'default_category' => 'Attribution', 'to_ids' => 0),
			'whois-registrant-org' => array('desc' => 'The org of a domain\'s registrant, obtained from the WHOIS information.', 'default_category' => 'Attribution', 'to_ids' => 0),
			'whois-registrar' => array('desc' => 'The registrar of the domain, obtained from the WHOIS information.', 'default_category' => 'Attribution', 'to_ids' => 0),
			'whois-creation-date' => array('desc' => 'The date of domain\'s creation, obtained from the WHOIS information.', 'default_category' => 'Attribution', 'to_ids' => 0),
			// 'targeted-threat-index' => array('desc' => ''), // currently not mapped!
			// 'mailslot' => array('desc' => 'MailSlot interprocess communication'), // currently not mapped!
			// 'pipe' => array('desc' => 'Pipeline (for named pipes use the attribute type "named pipe")'), // currently not mapped!
			// 'ssl-cert-attributes' => array('desc' => 'SSL certificate attributes'), // currently not mapped!
			'x509-fingerprint-sha1' => array('desc' => 'X509 fingerprint in SHA-1 format', 'default_category' => 'Network activity', 'to_ids' => 1),
			'x509-fingerprint-md5' => array('desc' => 'X509 fingerprint in MD5 format', 'default_category' => 'Network activity', 'to_ids' => 1),
			'x509-fingerprint-sha256' => array('desc' => 'X509 fingerprint in SHA-256 format', 'default_category' => 'Network activity', 'to_ids' => 1),
			'dns-soa-email' => array('desc' => 'RFC1035 mandates that DNS zones should have a SOA (Statement Of Authority) record that contains an email address where a PoC for the domain could be contacted. This can sometimes be used for attribution/linkage between different domains even if protected by whois privacy', 'default_category' => 'Attribution', 'to_ids' => 0),
			'size-in-bytes' => array('desc' => 'Size expressed in bytes', 'default_category' => 'Other', 'to_ids' => 0),
			'counter' => array('desc' => 'An integer counter, generally to be used in objects', 'default_category' => 'Other', 'to_ids' => 0),
			'datetime' => array('desc' => 'Datetime in the ISO 8601 format', 'default_category' => 'Other', 'to_ids' => 0),
			'cpe' => array('desc' => 'Common platform enumeration', 'default_category' => 'Other', 'to_ids' => 0),
			'port' => array('desc' => 'Port number', 'default_category' => 'Network activity', 'to_ids' => 0),
			'ip-dst|port' => array('desc' => 'IP destination and port number seperated by a |', 'default_category' => 'Network activity', 'to_ids' => 1),
			'ip-src|port' => array('desc' => 'IP source and port number seperated by a |', 'default_category' => 'Network activity', 'to_ids' => 1),
			'hostname|port' => array('desc' => 'Hostname and port number seperated by a |', 'default_category' => 'Network activity', 'to_ids' => 1),
			'mac-address' => array('desc' => 'Mac address', 'default_category' => 'Network activity', 'to_ids' => 0),
			'mac-eui-64' => array('desc' => 'Mac EUI-64 address', 'default_category' => 'Network activity', 'to_ids' => 0),
			// verify IDS flag defaults for these
			'email-dst-display-name' => array('desc' => 'Email destination display name', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-src-display-name' => array('desc' => 'Email source display name', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-header' => array('desc' => 'Email header', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-reply-to' => array('desc' => 'Email reply to header', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-x-mailer' => array('desc' => 'Email x-mailer header', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-mime-boundary' => array('desc' => 'The email mime boundary separating parts in a multipart email', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-thread-index' => array('desc' => 'The email thread index header', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'email-message-id' => array('desc' => 'The email message ID', 'default_category' => 'Payload delivery', 'to_ids' => 0),
			'github-username' => array('desc' => 'A github user name', 'default_category' => 'Social network', 'to_ids' => 0),
			'github-repository' => array('desc' => 'A github repository', 'default_category' => 'Social network', 'to_ids' => 0),
			'github-organisation' => array('desc' => 'A github organisation', 'default_category' => 'Social network', 'to_ids' => 0),
			'jabber-id' => array('desc' => 'Jabber ID', 'default_category' => 'Social network', 'to_ids' => 0),
			'twitter-id' => array('desc' => 'Twitter ID', 'default_category' => 'Social network', 'to_ids' => 0),
			'first-name' => array('desc' => 'First name of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'middle-name' => array('desc' => 'Middle name of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'last-name' => array('desc' => 'Last name of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'date-of-birth' => array('desc' => 'Date of birth of a natural person (in YYYY-MM-DD format)', 'default_category' => 'Person', 'to_ids' => 0),
			'place-of-birth' => array('desc' => 'Place of birth of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'gender' => array('desc' => 'The gender of a natural person (Male, Female, Other, Prefer not to say)', 'default_category' => 'Person', 'to_ids' => 0),
			'passport-number' => array('desc' => 'The passport number of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'passport-country' => array('desc' => 'The country in which the passport was issued', 'default_category' => 'Person', 'to_ids' => 0),
			'passport-expiration' => array('desc' => 'The expiration date of a passport', 'default_category' => 'Person', 'to_ids' => 0),
			'redress-number' => array('desc' => 'The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems', 'default_category' => 'Person', 'to_ids' => 0),
			'nationality' => array('desc' => 'The nationality of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'visa-number' => array('desc' => 'Visa number', 'default_category' => 'Person', 'to_ids' => 0),
			'issue-date-of-the-visa' => array('desc' => 'The date on which the visa was issued', 'default_category' => 'Person', 'to_ids' => 0),
			'primary-residence' => array('desc' => 'The primary residence of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'country-of-residence' => array('desc' => 'The country of residence of a natural person', 'default_category' => 'Person', 'to_ids' => 0),
			'special-service-request' => array('desc' => 'A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers. ', 'default_category' => 'Person', 'to_ids' => 0),
			'frequent-flyer-number' => array('desc' => 'The frequent flyer number of a passenger', 'default_category' => 'Person', 'to_ids' => 0),
			// Do we really need remarks? Or just use comment/text for this?
			//'remarks' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
			'travel-details' => array('desc' => 'Travel details', 'default_category' => 'Person', 'to_ids' => 0),
			'payment-details' => array('desc' => 'Payment details', 'default_category' => 'Person', 'to_ids' => 0),
			'place-port-of-original-embarkation' => array('desc' => 'The orignal port of embarkation', 'default_category' => 'Person', 'to_ids' => 0),
			'place-port-of-clearance' => array('desc' => 'The port of clearance', 'default_category' => 'Person', 'to_ids' => 0),
			'place-port-of-onward-foreign-destination' => array('desc' => 'A Port where the passenger is transiting to', 'default_category' => 'Person', 'to_ids' => 0),
			'passenger-name-record-locator-number' => array('desc' => 'The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers.', 'default_category' => 'Person', 'to_ids' => 0),
			'mobile-application-id' => array('desc' => 'The application id of a mobile application', 'default_category' => 'Payload delivery', 'to_ids' => 1),
			'cortex' => array('desc' => 'Cortex analysis result', 'default_category' => 'External analysis', 'to_ids' => 0)
			// Not convinced about this.
			//'url-regex' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
	);

	// definitions of categories
	public $categoryDefinitions = array(
			'Internal reference' => array(
					'desc' => 'Reference used by the publishing party (e.g. ticket number)',
					'types' => array('text', 'link', 'comment', 'other', 'hex')
					),
			'Targeting data' => array(
					'desc' => 'Internal Attack Targeting and Compromise Information',
					'formdesc' => 'Targeting information to include recipient email, infected machines, department, and or locations.',
					'types' => array('target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'comment')
					),
			'Antivirus detection' => array(
					'desc' => 'All the info about how the malware is detected by the antivirus products',
					'formdesc' => 'List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%). Attachment with list of detection or link to VirusTotal could be placed here as well.',
					'types' => array('link', 'comment', 'text', 'hex', 'attachment', 'other')
					),
			'Payload delivery' => array(
					'desc' => 'Information about how the malware is delivered',
					'formdesc' => 'Information about the way the malware payload is initially delivered, for example information about the email or web-site, vulnerability used, originating IP etc. Malware sample itself should be attached here.',
					'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'impfuzzy','authentihash', 'pehash', 'tlsh', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash','filename|impfuzzy', 'filename|pehash', 'mac-address', 'mac-eui-64', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'hostname', 'domain', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'email-body', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'stix2-pattern', 'yara', 'sigma', 'attachment', 'malware-sample', 'link', 'malware-type', 'comment', 'text', 'hex', 'vulnerability', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'hostname|port', 'email-dst-display-name', 'email-src-display-name', 'email-header', 'email-reply-to', 'email-x-mailer', 'email-mime-boundary', 'email-thread-index', 'email-message-id', 'mobile-application-id', 'whois-registrant-email')
					),
			'Artifacts dropped' => array(
					'desc' => 'Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system',
					'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'impfuzzy','authentihash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy','filename|pehash', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory','pdb', 'stix2-pattern', 'yara', 'sigma', 'attachment', 'malware-sample', 'named pipe', 'mutex', 'windows-scheduled-task', 'windows-service-name', 'windows-service-displayname', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'cookie')
					),
			'Payload installation' => array(
					'desc' => 'Info on where the malware gets installed in the system',
					'formdesc' => 'Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.',
					'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash','impfuzzy','authentihash', 'pehash', 'tlsh', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy','filename|pehash', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'stix2-pattern', 'yara', 'sigma', 'vulnerability', 'attachment', 'malware-sample', 'malware-type', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'mobile-application-id', 'other')
					),
			'Persistence mechanism' => array(
					'desc' => 'Mechanisms used by the malware to start at boot',
					'formdesc' => 'Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup',
					'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other', 'hex')
					),
			'Network activity' => array(
					'desc' => 'Information about network traffic generated by the malware',
					'types' => array('ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'port', 'hostname', 'domain', 'domain|ip', 'mac-address', 'mac-eui-64', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'stix2-pattern', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'x509-fingerprint-sha1', 'other', 'hex', 'cookie')
					),
			'Payload type' => array(
					'desc' => 'Information about the final payload(s)',
					'formdesc' => 'Information about the final payload(s). Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.',
					'types' => array('comment', 'text', 'other')
					),
			'Attribution' => array(
					'desc' => 'Identification of the group, organisation, or country behind the attack',
					'types' => array('threat-actor', 'campaign-name', 'campaign-id', 'whois-registrant-phone', 'whois-registrant-email', 'whois-registrant-name', 'whois-registrant-org', 'whois-registrar', 'whois-creation-date','comment', 'text', 'x509-fingerprint-sha1','x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'dns-soa-email')
					),
			'External analysis' => array(
					'desc' => 'Any other result from additional analysis of the malware like tools output',
					'formdesc' => 'Any other result from additional analysis of the malware like tools output Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.',
					'types' => array('md5', 'sha1', 'sha256','filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'mac-address', 'mac-eui-64', 'hostname', 'domain', 'domain|ip', 'url', 'user-agent', 'regkey', 'regkey|value', 'AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'vulnerability', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'github-repository', 'other', 'cortex')
					),
			'Financial fraud' => array(
					'desc' => 'Financial Fraud indicators',
					'formdesc' => 'Financial Fraud indicators, for example: IBAN Numbers, BIC codes, Credit card numbers, etc.',
					'types' => array('btc', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number', 'comment', 'text', 'other', 'hex'),
					),
			'Support Tool' => array(
					'desc' => 'Tools supporting analysis or detection of the event',
					'types' => array('link', 'text', 'attachment', 'comment', 'other', 'hex')
			),
			'Social network' => array(
					'desc' => 'Social networks and platforms',
					// email-src and email-dst or should we go with a new email type that is neither / both?
					'types' => array('github-username', 'github-repository', 'github-organisation', 'jabber-id', 'twitter-id', 'email-src', 'email-dst', 'comment', 'text', 'other', 'whois-registrant-email')
			),
			'Person' => array(
					'desc' => 'A human being - natural person',
					'types' => array('first-name', 'middle-name', 'last-name', 'date-of-birth', 'place-of-birth', 'gender', 'passport-number', 'passport-country', 'passport-expiration', 'redress-number', 'nationality', 'visa-number', 'issue-date-of-the-visa', 'primary-residence', 'country-of-residence', 'special-service-request', 'frequent-flyer-number', 'travel-details', 'payment-details', 'place-port-of-original-embarkation', 'place-port-of-clearance', 'place-port-of-onward-foreign-destination', 'passenger-name-record-locator-number', 'comment', 'text', 'other', 'phone-number')
			),
			'Other' => array(
					'desc' => 'Attributes that are not part of any other category or are meant to be used as a component in MISP objects in the future',
					'types' => array('comment', 'text', 'other', 'size-in-bytes', 'counter', 'datetime', 'cpe', 'port', 'float', 'hex', 'phone-number')
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
			'impfuzzy'=> 'Payload delivery',
			'pehash' => 'Payload delivery',
			'filename|md5' => 'Payload delivery',
			'filename|sha1' => 'Payload delivery',
			'filename|sha256' => 'Payload delivery',
			'regkey' => 'Persistence mechanism',
			'filename' => 'Payload delivery',
			'ip-src' => 'Network activity',
			'ip-dst' => 'Network activity',
			'mac-address' => 'Network activity',
			'mac-eui-64' => 'Network activity',
			'hostname' => 'Network activity',
			'domain' => 'Network activity',
			'url' => 'Network activity',
			'link' => 'External analysis',
			'email-src' => 'Payload delivery',
			'email-dst' => 'Payload delivery',
			'text' => 'Other',
			'hex' => 'Other',
			'attachment' => 'External analysis',
			'malware-sample' => 'Payload delivery',
			'cortex' => 'External analysis',
			'dns-soa-email' => 'Attribution'
	);

	// typeGroupings are a mapping to high level groups for attributes
	// for example, IP addresses, domain names, hostnames and e-mail addresses are network related attribute types
	// whilst filenames and hashes are file related attribute types
	// This helps generate quick filtering for the event view, but we may reuse this and enhance it in the future for other uses (such as the API?)
	public $typeGroupings = array(
		'file' => array('attachment', 'pattern-in-file', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'impfuzzy','authentihash', 'pehash', 'tlsh', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|authentihash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'malware-sample', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'x509-fingerprint-md5'),
        'network' => array('ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'mac-address', 'mac-eui-64', 'hostname', 'hostname|port', 'domain', 'domain|ip', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-traffic', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256'),
        'financial' => array('btc', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number')
	);

	public $order = array("Attribute.event_id" => "DESC");

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
				'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
				'message' => 'Please provide a valid UUID'
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

	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'event_id',
			'conditions' => '',
			'fields' => '',
			//'counterCache' => 'attribute_count',
			//'counterScope' => array('Attribute.deleted' => 0),
			'order' => ''
		),
		'SharingGroup' => array(
				'className' => 'SharingGroup',
				'foreignKey' => 'sharing_group_id'
		),
		'Object' => array(
			'className' => 'MispObject',
			'foreignKey' => 'object_id'
		)
	);

	public $hasMany = array(
		'AttributeTag' => array(
			'dependent' => true
		),
		'Sighting' => array(
				'className' => 'Sighting',
				'dependent' => true,
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

	public function afterFind($results, $primary = false) {
		foreach ($results as $k => $v) {
			if (isset($v['Attribute']['object_relation']) && $v['Attribute']['object_relation'] === null) {
				$results[$k]['Attribute']['object_relation'] = '';
			}
		}
		return $results;
	}

	public function beforeSave($options = array()) {
		// explode value of composite type in value1 and value2
		// or copy value to value1 if not composite type
		if (!empty($this->data['Attribute']['type'])) {
			$compositeTypes = $this->getCompositeTypes();
			// explode composite types in value1 and value2
			if (in_array($this->data['Attribute']['type'], $compositeTypes)) {
				$pieces = explode('|', $this->data['Attribute']['value']);
				if (2 != count($pieces)) {
					throw new InternalErrorException('Composite type, but value not explodable');
				}
				$this->data['Attribute']['value1'] = $pieces[0];
				$this->data['Attribute']['value2'] = $pieces[1];
			} else {
				$this->data['Attribute']['value1'] = $this->data['Attribute']['value'];
				$this->data['Attribute']['value2'] = '';
			}
		}

		// update correlation... (only needed here if there's an update)
		if ($this->id || !empty($this->data['Attribute']['id'])) {
			$this->__beforeSaveCorrelation($this->data['Attribute']);
		}
		// always return true after a beforeSave()
		return true;
	}

	private function __alterAttributeCount($event_id, $increment = true) {
		$event = $this->Event->find('first', array(
			'recursive' => -1,
			'conditions' => array('Event.id' => $event_id)
		));
		if (!empty($event)) {
			if ($increment) $event['Event']['attribute_count'] = $event['Event']['attribute_count'] + 1;
			else  $event['Event']['attribute_count'] = $event['Event']['attribute_count'] - 1;
			$this->Event->save($event, array('callbacks' => false));
		}
	}

	public function afterSave($created, $options = array()) {
		parent::afterSave($created, $options);
		// update correlation...
		if (isset($this->data['Attribute']['deleted']) && $this->data['Attribute']['deleted']) {
			$this->__beforeSaveCorrelation($this->data['Attribute']);
			if (isset($this->data['Attribute']['event_id'])) $this->__alterAttributeCount($this->data['Attribute']['event_id'], false);
		} else {
			$this->__afterSaveCorrelation($this->data['Attribute']);
		}
		if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_attribute_notifications_enable')) {
			$pubSubTool = $this->getPubSubTool();
			$attribute = $this->fetchAttribute($this->id);
			if (!empty($attribute)) {
				$user = array(
					'org_id' => -1,
					'Role' => array(
						'perm_site_admin' => 1
					)
				);
				$attribute['Attribute']['Sighting'] = $this->Sighting->attachToEvent($attribute, $user, $this->id);
				if (empty($attribute['Object']['id'])) unset($attribute['Object']);
				$action = $created ? 'add' : 'edit';
				if (!empty($this->data['Attribute']['deleted'])) $action = 'soft-delete';
				$pubSubTool->attribute_save($attribute, $action);
			}
		}
		if (Configure::read('MISP.enable_advanced_correlations') && in_array($this->data['Attribute']['type'], array('ip-src', 'ip-dst', 'domain-ip')) && strpos($this->data['Attribute']['value'], '/')) {
			$this->setCIDRList();
		}
		$result = true;
		// if the 'data' field is set on the $this->data then save the data to the correct file
		if (isset($this->data['Attribute']['type']) && $this->typeIsAttachment($this->data['Attribute']['type']) && !empty($this->data['Attribute']['data'])) {
			$result = $result && $this->saveBase64EncodedAttachment($this->data['Attribute']); // TODO : is this correct?
		}
		if ($created && isset($this->data['Attribute']['event_id']) && empty($this->data['Attribute']['skip_auto_increment'])) {
			$this->__alterAttributeCount($this->data['Attribute']['event_id']);
		}
		return $result;
	}

	public function beforeDelete($cascade = true) {
		// delete attachments from the disk
		$this->read(); // first read the attribute from the db
		if ($this->typeIsAttachment($this->data['Attribute']['type'])) {
			// only delete the file if it exists
			$attachments_dir = Configure::read('MISP.attachments_dir');
			if (empty($attachments_dir)) {
				$my_server = ClassRegistry::init('Server');
				$attachments_dir = $my_server->getDefaultAttachments_dir();
			}
			$filepath = $attachments_dir . DS . $this->data['Attribute']['event_id'] . DS . $this->data['Attribute']['id'];
			$file = new File($filepath);
			if ($file->exists()) {
				if (!$file->delete()) {
					throw new InternalErrorException('Delete of file attachment failed. Please report to administrator.');
				}
			}
		}
		// update correlation..
		$this->__beforeDeleteCorrelation($this->data['Attribute']['id']);
		if (!empty($this->data['Attribute']['id'])) {
			if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_attribute_notifications_enable')) {
				$pubSubTool = $this->getPubSubTool();
				$pubSubTool->attribute_save($this->data, 'delete');
			}
		}
	}

	public function afterDelete() {
		if (Configure::read('MISP.enable_advanced_correlations') && in_array($this->data['Attribute']['type'], array('ip-src', 'ip-dst', 'domain-ip')) && strpos($this->data['Attribute']['value'], '/')) {
			$this->setCIDRList();
		}
		if (isset($this->data['Attribute']['event_id'])) {
			if (empty($this->data['Attribute']['deleted'])) $this->__alterAttributeCount($this->data['Attribute']['event_id'], false);
		}
		if (!empty($this->data['Attribute']['id'])) {
			$this->Object->ObjectReference->deleteAll(
				array(
					'ObjectReference.referenced_type' => 0,
					'ObjectReference.referenced_id' => $this->data['Attribute']['id'],
				),
				false
			);
		}
	}

	public function beforeValidate($options = array()) {
		parent::beforeValidate();

		if (!isset($this->data['Attribute']['type'])) {
			return false;
		}
		if (is_array($this->data['Attribute']['value'])) {
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

		if (empty($this->data['Attribute']['comment'])) {
			$this->data['Attribute']['comment'] = "";
		}
		// generate UUID if it doesn't exist
		if (empty($this->data['Attribute']['uuid'])) {
			$this->data['Attribute']['uuid'] = CakeText::uuid();
		}
		// generate timestamp if it doesn't exist
		if (empty($this->data['Attribute']['timestamp'])) {
			$date = new DateTime();
			$this->data['Attribute']['timestamp'] = $date->getTimestamp();
		}
		// TODO: add explanatory comment
		$result = $this->runRegexp($this->data['Attribute']['type'], $this->data['Attribute']['value']);
		if ($result === false) {
			$this->invalidate('value', 'This value is blocked by a regular expression in the import filters.');
		} else {
			$this->data['Attribute']['value'] = $result;
		}

		// Set defaults for when some of the mandatory fields don't have defaults
		// These fields all have sane defaults either based on another field, or due to server settings
		if (!isset($this->data['Attribute']['distribution'])) {
			$this->data['Attribute']['distribution'] = Configure::read('MISP.default_attribute_distribution');
			if ($this->data['Attribute']['distribution'] == 'event') {
				$this->data['Attribute']['distribution'] = 5;
			}
		}

		if (!empty($this->data['Attribute']['type']) && empty($this->data['Attribute']['category'])) {
			$this->data['Attribute']['category'] = $this->typeDefinitions[$this->data['Attribute']['type']]['default_category'];
		}

		if (!isset($this->data['Attribute']['to_ids'])) {
			$this->data['Attribute']['to_ids'] = $this->typeDefinitions[$this->data['Attribute']['type']]['to_ids'];
		}

		if ($this->data['Attribute']['distribution'] != 4) $this->data['Attribute']['sharing_group_id'] = 0;
		// return true, otherwise the object cannot be saved

		if ($this->data['Attribute']['type'] == 'float' && $this->data['Attribute']['value'] == 0) $this->data['Attribute']['value'] = '0.0';
		return true;
	}

	public function validCategory($fields) {
		$validCategories = array_keys($this->categoryDefinitions);
		if (in_array($fields['category'], $validCategories)) return true;
		return false;
	}

		public function valueIsUnique ($fields) {
		if (isset($this->data['Attribute']['deleted']) && $this->data['Attribute']['deleted']) return true;
		// We escape this rule for objects as we can have the same category/type/value combination in different objects
		if (!empty($this->data['Attribute']['object_relation'])) {
			return true;
		}
		$value = $fields['value'];
		if (strpos($value, '|')) {
			$value = explode('|', $value);
			$value = array(
				'Attribute.value1' => $value[0],
				'Attribute.value2' => $value[1]
			);
		} else {
			$value = array(
				'Attribute.value1' => $value,
			);
		}
		$eventId = $this->data['Attribute']['event_id'];
		$type = $this->data['Attribute']['type'];
		$category = $this->data['Attribute']['category'];

		// check if the attribute already exists in the same event
		$conditions = array(
			'Attribute.event_id' => $eventId,
			'Attribute.type' => $type,
			'Attribute.category' => $category,
			'Attribute.deleted' => 0
		);
		$conditions = array_merge ($conditions, $value);
		if (isset($this->data['Attribute']['id'])) {
			$conditions['Attribute.id !='] = $this->data['Attribute']['id'];
		}

		$params = array(
			'recursive' => -1,
			'fields' => array('id'),
			'conditions' => $conditions,
		);
		if (!empty($this->find('first', $params))) {
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
            'x509-fingerprint-md5' => 32,
			'x509-fingerprint-sha1' => 40,
            'x509-fingerprint-sha256' => 64,
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
            case 'x509-fingerprint-md5':
            case 'x509-fingerprint-sha256':
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
				$returnValue = true;
				if (strpos($value, '/') !== false) {
					$parts = explode("/", $value);
					// [0] = the IP
					// [1] = the network address
					if (count($parts) != 2 || (!is_numeric($parts[1]) || !($parts[1] < 129 && $parts[1] > 0))) {
							$returnValue = 'Invalid CIDR notation value found.';
					}
					$ip = $parts[0];
				} else {
					$ip = $value;
				}
				if (!filter_var($ip, FILTER_VALIDATE_IP)) {
					$returnValue = 'IP address has an invalid format.';
				}
				break;
			case 'port':
				if (!is_numeric($value) || $value < 1 || $value > 65535) {
					$returnValue = 'Port numbers have to be positive integers between 1 and 65535.';
				} else {
					$returnValue = true;
				}
				break;
			case 'ip-dst|port':
			case 'ip-src|port':
				$parts = explode('|', $value);
				if (filter_var($parts[0], FILTER_VALIDATE_IP)) {
					if (!is_numeric($parts[1]) || $parts[1] > 1 || $parts[1] < 65536) {
						$returnValue = true;
					}
				}
				break;
			case 'mac-address':
				if (preg_match('/^([a-fA-F0-9]{2}[:|\-| |\.]?){6}$/', $value) == 1) {
					$returnValue = true;
				}
				break;
			case 'mac-eui-64':
				if (preg_match('/^([a-fA-F0-9]{2}[:|\-| |\.]?){8}$/', $value) == 1) {
					$returnValue = true;
				}
				break;
			case 'hostname':
			case 'domain':
				if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Domain name has an invalid format. Please double check the value or select type "other".';
				}
				break;
			case 'hostname|port':
				$parts = explode('|', $value);
				if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}$#i", $parts[0])) {
					if (!is_numeric($parts[1]) || $parts[1] > 1 || $parts[1] < 65536) {
						$returnValue = true;
					}
				}
				break;
			case 'domain|ip':
				if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}\|.*$#i", $value)) {
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
			case 'dns-soa-email':
			case 'jabber-id':
				// we don't use the native function to prevent issues with partial email addresses
				if (preg_match("#^.*\@.*\..*$#i", $value)) {
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
            case 'stix2-pattern':
			case 'sigma':
			case 'cookie':
			case 'attachment':
			case 'malware-sample':
				$returnValue = true;
				break;
			case 'link':
				// Moved to a native function whilst still enforcing the scheme as a requirement
				if (filter_var($value, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED) && !preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'comment':
			case 'text':
			case 'other':
			case 'email-attachment':
			case 'email-body':
				$returnValue = true;
				break;
			case 'hex':
				if (preg_match("/^[0-9a-f]*$/i", $value)) {
					$returnValue = true;
				}
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
			case 'malware-type':
			// TODO: review url/uri validation
			case 'url':
			case 'uri':
			case 'user-agent':
			case 'regkey':
			case 'regkey|value':
			case 'filename':
			case 'pdb':
			case 'windows-scheduled-task':
            case 'whois-registrant-name':
            case 'whois-registrant-org':
			case 'whois-registrar':
			case 'whois-creation-date':
			case 'first-name':
			case 'middle-name':
			case 'last-name':
			case 'date-of-birth':
			case 'place-of-birth':
			case 'gender':
			case 'passport-number':
			case 'passport-country':
			case 'passport-expiration':
			case 'redress-number':
			case 'nationality':
			case 'visa-number':
			case 'issue-date-of-the-visa':
			case 'primary-residence':
			case 'country-of-residence':
			case 'special-service-request':
			case 'frequent-flyer-number':
			case 'travel-details':
			case 'payment-details':
			case 'place-port-of-original-embarkation':
			case 'place-port-of-clearance':
			case 'place-port-of-onward-foreign-destination':
			case 'passenger-name-record-locator-number':
			case 'email-dst-display-name':
			case 'email-src-display-name':
			case 'email-header':
			case 'email-reply-to':
			case 'email-x-mailer':
			case 'email-mime-boundary':
			case 'email-thread-index':
			case 'email-message-id':
			case 'github-username':
			case 'github-repository':
			case 'github-organisation':
			case 'cpe':
			case 'twitter-id':
			case 'mobile-application-id':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'datetime':
				try {
					new DateTime($value);
					$returnValue = true;
				} catch (Exception $e) {
					$returnValue = 'Datetime has to be in the ISO 8601 format.';
				}
				break;
			case 'size-in-bytes':
			case 'counter':
				if (!is_numeric($value) || $value < 0) {
					$returnValue = 'The value has to be a number greater or equal 0.';
				} else {
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
			case 'phone-number':
			case 'whois-registrant-phone':
				if (is_numeric($value)) {
					$returnValue = true;
				}
				break;
			case 'cortex':
				json_decode($value);
				$returnValue = (json_last_error() == JSON_ERROR_NONE);
				break;
			case 'float':
				$value = floatval($value);
				if (is_float($value)) {
					$returnValue = true;
				}
				break;
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
			case 'target-email':
			case 'whois-registrant-email':
				$value = strtolower($value);
				break;
			case 'domain|ip':
				$parts = explode('|', $value);
				if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					// convert IPv6 address to compressed format
					$parts[1] = inet_ntop(inet_pton($value));
					$value = implode('|', $parts);
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
			case 'phone-number':
				if (substr($value, 0, 2) == '00') $value = '+' . substr($value, 2);
				$value = preg_replace('/\(0\)/', '', $value);
				$value = preg_replace('/[^\+0-9]+/', '', $value);
				break;
			case 'url':
				$value = preg_replace('/^hxxp/i', 'http', $value);
				$value = preg_replace('/\[\.\]/', '.' , $value);
				break;
            case 'x509-fingerprint-md5':
            case 'x509-fingerprint-sha256':
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
			case 'ip-dst|port':
			case 'ip-src|port':
					if (strpos($value, ':')) {
						$parts = explode(':', $value);
					} else if (strpos($value, '|')) {
						$parts = explode('|', $value);
					} else {
						return $value;
					}
					if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
						// convert IPv6 address to compressed format
						$parts[0] = inet_ntop(inet_pton($parts[0]));
					}
					return $parts[0] . '|' . $parts[1];
				break;
			case 'mac-address':
			case 'mac-eui-64':
				$value = str_replace(array('.', ':', '-', ' '), '', $value);
				$value = wordwrap($value, 2, ':', true);
				break;
			case 'hostname|port':
				$value = strtolower($value);
				str_replace(':', '|', $value);
				break;
			case 'float':
				$value = floatval($value);
				break;
			case 'hex':
				$value = strtoupper($value);
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
		$attachments_dir = Configure::read('MISP.attachments_dir');
		if (empty($attachments_dir)) {
			$my_server = ClassRegistry::init('Server');
			$attachments_dir = $my_server->getDefaultAttachments_dir();
		}
		$filepath = $attachments_dir . DS . $attribute['event_id'] . DS . $attribute['id'];
		$file = new File($filepath);
		if (!$file->readable()) {
			return '';
		}
		$content = $file->read();
		return base64_encode($content);
	}

	public function saveBase64EncodedAttachment($attribute) {
		$attachments_dir = Configure::read('MISP.attachments_dir');
		if (empty($attachments_dir)) {
			$my_server = ClassRegistry::init('Server');
			$attachments_dir = $my_server->getDefaultAttachments_dir();
		}
		$rootDir = $attachments_dir . DS . $attribute['event_id'];
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
		$attachments_dir = Configure::read('MISP.attachments_dir');
		if (empty($attachments_dir)) {
			$my_server = ClassRegistry::init('Server');
			$attachments_dir = $my_server->getDefaultAttachments_dir();
		}
		$rootDir = $attachments_dir . DS . $eventId;
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

	// using Alnitak's solution from http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
	private function __ipv4InCidr($ip, $cidr) {
		list ($subnet, $bits) = explode('/', $cidr);
		$ip = ip2long($ip);
		$subnet = ip2long($subnet);
		$mask = -1 << (32 - $bits);
		$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
		return ($ip & $mask) == $subnet;
	}

	// using Snifff's solution from http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
	private function __ipv6InCidr($ip, $cidr) {
		$ip = $this->__expandIPv6Notation($ip);
		$binaryip = $this->__inet_to_bits($ip);
		list($net,$maskbits) = explode('/', $cidr);
		$net = $this->__expandIPv6Notation($net);
		if (substr($net, -1) == ':') {
			$net .= '0';
		}
		$binarynet = $this->__inet_to_bits($net);
		$ip_net_bits = substr($binaryip, 0, $maskbits);
		$net_bits = substr($binarynet, 0, $maskbits);
		return ($ip_net_bits === $net_bits);
	}

	private function __expandIPv6Notation($ip) {
    if (strpos($ip, '::') !== false)
        $ip = str_replace('::', str_repeat(':0', 8 - substr_count($ip, ':')).':', $ip);
    if (strpos($ip, ':') === 0) $ip = '0'.$ip;
    return $ip;
	}

	private function __inet_to_bits($inet) {
		$unpacked = unpack('A16', $inet);
		$unpacked = str_split($unpacked[1]);
		$binaryip = '';
		foreach ($unpacked as $char) {
			$binaryip .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
		}
		return $binaryip;
	}

	private function __cidrCorrelation($a) {
		$ipValues = array();
		$ip = $a['type'] == 'domain-ip' ? $a['value2'] : $a['value1'];
		if (strpos($ip, '/') !== false) {
			$ip_array = explode('/', $ip);
			$ip_version = filter_var($ip_array[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 : 6;
			$ipList = $this->find('list', array(
				'conditions' => array(
					'type' => array('ip-src', 'ip-dst', 'domain_ip'),
				),
				'fields' => array('value1', 'value2'),
				'order' => false
			));
			$ipList = array_merge(array_keys($ipList), array_values($ipList));
			foreach ($ipList as $key => $value) {
				if ($value == '') {
					unset($ipList[$key]);
				}
			}
			foreach ($ipList as $ipToCheck) {
				if (filter_var($ipToCheck, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $ip_version == 4) {
					if ($ip_version == 4) {
						if ($this->__ipv4InCidr($ipToCheck, $ip)) {
							$ipValues[] = $ipToCheck;
						}
					} else {
						if ($this->__ipv6InCidr($ipToCheck, $ip)) {
							$ipValues[] = $ipToCheck;
						}
					}
				}
			}
		} else {
			$ip = $a['value1'];
			$ip_version = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 : 6;
			$cidrList = $this->getSetCIDRList();
			foreach ($cidrList as $cidr) {
				$cidr_ip = explode('/', $cidr)[0];
				if (filter_var($cidr_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					if ($ip_version == 4) {
						if ($this->__ipv4InCidr($ip, $cidr)) {
							$ipValues[] = $cidr;
						}
					}
				} else {
					if ($ip_version == 6) {
						if ($this->__ipv6InCidr($ip, $cidr)) {
							$ipValues[] = $cidr;
						}
					}
				}
			}
		}
		$extraConditions = array();
		if (!empty($ipValues)) {
			$extraConditions = array('OR' => array(
				'Attribute.value1' => $ipValues,
				'Attribute.value2' => $ipValues
			));
		}
		return $extraConditions;
	}

	public function __afterSaveCorrelation($a, $full = false, $event = false) {
		// Don't do any correlation if the type is a non correlating type
		if (!in_array($a['type'], $this->nonCorrelatingTypes)) {
			if (!$event) {
				$event = $this->Event->find('first', array(
						'recursive' => -1,
						'fields' => array('Event.distribution', 'Event.id', 'Event.info', 'Event.org_id', 'Event.date', 'Event.sharing_group_id', 'Event.disable_correlation'),
						'conditions' => array('id' => $a['event_id']),
						'order' => array(),
				));
			}
			if ($event['Event']['disable_correlation']) {
				return true;
			}
			if (Configure::read('MISP.enable_advanced_correlations') && in_array($a['type'], array('ip-src', 'ip-dst', 'domain-ip'))) {
				$extraConditions = $this->__cidrCorrelation($a);
			}
			$this->Correlation = ClassRegistry::init('Correlation');
			$correlatingValues = array($a['value1']);
			if (!empty($a['value2']) && !isset($this->primaryOnlyCorrelatingTypes[$a['type']])) $correlatingValues[] = $a['value2'];
			foreach ($correlatingValues as $k => $cV) {
				$conditions = array(
					'OR' => array(
							'Attribute.value1' => $cV,
							'AND' => array(
									'Attribute.value2' => $cV,
									'NOT' => array('Attribute.type' => $this->primaryOnlyCorrelatingTypes)
							)
					),
					'Attribute.disable_correlation' => 0,
					'Event.disable_correlation' => 0,
					'Attribute.deleted' => 0
				);
				if (!empty($extraConditions)) {
					$conditions['OR'][] = $extraConditions;
				}
				$correlatingAttributes[$k] = $this->find('all', array(
						'conditions' => $conditions,
						'recursive => -1',
						'fields' => array('Attribute.event_id', 'Attribute.id', 'Attribute.distribution', 'Attribute.sharing_group_id', 'Attribute.deleted', 'Attribute.type'),
						'contain' => array('Event' => array('fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id'))),
						'order' => array(),
				));
				foreach ($correlatingAttributes[$k] as $key => &$correlatingAttribute) {
					if ($correlatingAttribute['Attribute']['id'] == $a['id']) unset($correlatingAttributes[$k][$key]);
					else if ($correlatingAttribute['Attribute']['event_id'] == $a['event_id']) unset($correlatingAttributes[$k][$key]);
					else if ($full && $correlatingAttribute['Attribute']['id'] <= $a['id']) unset($correlatingAttributes[$k][$key]);
					else if (in_array($correlatingAttribute['Attribute']['type'], $this->nonCorrelatingTypes)) unset($correlatingAttributes[$k][$key]);
					else if (isset($this->primaryOnlyCorrelatingTypes[$a['type']]) && $correlatingAttribute['value1'] !== $a['value1']) unset($correlatingAttribute[$k][$key]);
				}
			}
			$correlations = array();
			foreach ($correlatingAttributes as $k => $cA) {
				foreach ($cA as $corr) {
					$correlations[] = array(
							$correlatingValues[$k],
							$event['Event']['id'],
							$a['id'],
							$corr['Attribute']['event_id'],
							$corr['Attribute']['id'],
							$corr['Event']['org_id'],
							$corr['Event']['distribution'],
							$corr['Attribute']['distribution'],
							$corr['Event']['sharing_group_id'],
							$corr['Attribute']['sharing_group_id'],
							$corr['Event']['date'],
							$corr['Event']['info']
					);
					$correlations[] = array(
							$correlatingValues[$k],
							$corr['Event']['id'],
							$corr['Attribute']['id'],
							$a['event_id'],
							$a['id'],
							$event['Event']['org_id'],
							$event['Event']['distribution'],
							$a['distribution'],
							$event['Event']['sharing_group_id'],
							$a['sharing_group_id'],
							$event['Event']['date'],
							$event['Event']['info']
					);
				}
			}
			$fields = array(
					'value',
					'1_event_id',
					'1_attribute_id',
					'event_id',
					'attribute_id',
					'org_id',
					'distribution',
					'a_distribution',
					'sharing_group_id',
					'a_sharing_group_id',
					'date',
					'info'
			);
			if (!empty($correlations)) {
				$db = $this->getDataSource();
				$db->insertMulti('correlations', $fields, $correlations);
			}
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


	public function hids($user, $type, $tags = '', $from = false, $to = false, $last = false, $jobId = false, $enforceWarninglist = false) {
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
		if (!empty($tags)) {
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
		$eventCount = count($eventIds);
		if ($jobId) {
			$this->Job = ClassRegistry::init('Job');
			$this->Job->id = $jobId;
			if (!$this->Job->exists()) $jobId = false;
		}
		foreach ($eventIds as $k => $event) {
			$conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1, 'Attribute.type' => $typeArray, 'Attribute.event_id' => $event['Event']['id']);
			$options = array(
					'conditions' => $conditions,
					'group' => array('Attribute.type', 'Attribute.value1'),
					'enforceWarninglist' => $enforceWarninglist,
					'flatten' => true
			);
			$items = $this->fetchAttributes($user, $options);
			if (empty($items)) continue;
			$export = new HidsExport();
			$rules = array_merge($rules, $export->export($items, strtoupper($type), $continue));
			$continue = true;
			if ($jobId && ($k % 10 == 0)) {
				$this->Job->saveField('progress', $k * 80 / $eventCount);
			}
		}
		return $rules;
	}


	public function nids($user, $format, $id = false, $continue = false, $tags = false, $from = false, $to = false, $last = false, $type = false, $enforceWarninglist = false, $includeAllTags = false) {
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
			$valid_types = array('ip-dst', 'ip-src', 'ip-dst|port', 'ip-src|port', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'domain', 'domain|ip', 'hostname', 'url', 'user-agent', 'snort');
			$conditions['AND']['Attribute.type'] = $valid_types;
			if (!empty($type)) {
				$conditions['AND'][] = array('Attribute.type' => $type);
			}

			$params = array(
					'conditions' => $conditions, // array of conditions
					'recursive' => -1, // int
					'fields' => array('Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.value'),
					'contain' => array('Event'=> array('fields' => array('Event.id', 'Event.threat_level_id'))),
					'group' => array('Attribute.type', 'Attribute.value1'), // fields to GROUP BY
					'enforceWarninglist' => $enforceWarninglist,
					'includeAllTags' => $includeAllTags,
					'flatten' => true
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

	public function text($user, $type, $tags = false, $eventId = false, $allowNonIDS = false, $from = false, $to = false, $last = false, $enforceWarninglist = false, $allowNotPublished = false) {
		//permissions are taken care of in fetchAttributes()
		$conditions['AND'] = array();
		if ($allowNonIDS === false) {
			$conditions['AND']['Attribute.to_ids'] = 1;
			if ($allowNotPublished === false) $conditions['AND']['Event.published'] = 1;
		}
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
				)),
				'enforceWarninglist' => $enforceWarninglist,
				'flatten' => 1
		));
		return $attributes;
	}

	public function rpz($user, $tags = false, $eventId = false, $from = false, $to = false, $enforceWarninglist = false) {
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
			$tempConditions = $conditions;
			$tempConditions['type'] = $v;
			$temp = $this->fetchAttributes(
					$user,
					array(
						'conditions' => $tempConditions,
						'fields' => array('Attribute.value'), // array of field names
						'enforceWarninglist' => $enforceWarninglist
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

	public function bro($user, $type, $tags = false, $eventId = false, $from = false, $to = false, $last = false, $enforceWarninglist = false) {
		App::uses('BroExport', 'Export');
		$export = new BroExport();
		if ($type == 'all') {
		  $types = array_keys($export->mispTypes);
		} else {
		  $types = array($type);
		}
		$intel = array();
		foreach ($types as $type) {
			//restricting to non-private or same org if the user is not a site-admin.
			$conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1);
			if ($from) $conditions['AND']['Event.date >='] = $from;
			if ($to) $conditions['AND']['Event.date <='] = $to;
			if ($last) $conditions['AND']['Event.publish_timestamp >='] = $last;
			if ($eventId !== false) {
				$temp = array();
				$args = $this->dissectArgs($eventId);
				foreach ($args[0] as $accepted) {
					$temp['OR'][] = array('Event.id' => $accepted);
				}
				$conditions['AND'][] = $temp;
				$temp = array();
				foreach ($args[1] as $rejected) {
					$temp['AND'][] = array('Event.id !=' => $rejected);
				}
				$conditions['AND'][] = $temp;
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
			$this->Whitelist = ClassRegistry::init('Whitelist');
			$this->whitelist = $this->Whitelist->getBlockedValues();
			$instanceString = 'MISP';
			if (Configure::read('MISP.host_org_id') && Configure::read('MISP.host_org_id') > 0) {
				$this->Event->Orgc->id = Configure::read('MISP.host_org_id');
				if ($this->Event->Orgc->exists()) {
					$instanceString = $this->Event->Orgc->field('name') . ' MISP';
				}
			}
			$mispTypes = $export->getMispTypes($type);
			foreach($mispTypes as $mispType) {
				$conditions['AND']['Attribute.type'] = $mispType[0];
				$intel = array_merge($intel, $this->__bro($user, $conditions, $mispType[1], $export, $this->whitelist, $instanceString, $enforceWarninglist));
			}
		}
		natsort($intel);
		$intel = array_unique($intel);
		array_unshift($intel, $export->header);
		return $intel;
	}

	private function __bro($user, $conditions, $valueField, $export, $whitelist, $instanceString, $enforceWarninglist) {
		$attributes = $this->fetchAttributes($user, array(
				'conditions' => $conditions, // array of conditions
				'order' => 'Attribute.value' . $valueField . ' ASC',
				'recursive' => -1, // int
				'fields' => array('Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.comment', 'Attribute.value' . $valueField . " as value"),
				'contain' => array('Event' => array('fields' => array('Event.id', 'Event.threat_level_id', 'Event.orgc_id', 'Event.uuid'))),
				'group' => array('Attribute.type', 'Attribute.value' . $valueField), // fields to GROUP BY
				'enforceWarninglist' => $enforceWarninglist
			)
		);
		$orgs = $this->Event->Orgc->find('list', array(
				'fields' => array('Orgc.id', 'Orgc.name')
		));
		return $export->export($attributes, $orgs, $valueField, $whitelist, $instanceString);
	}

	public function generateCorrelation($jobId = false, $startPercentage = 0, $eventId = false, $attributeId = false) {
		$this->Correlation = ClassRegistry::init('Correlation');
		$this->purgeCorrelations($eventId);
		// get all attributes..
		if (!$eventId) {
			$eventIds = $this->Event->find('list', array('recursive' => -1, 'fields' => array('Event.id')));
		} else {
			$eventIds = array($eventId);
		}
		$attributeCount = 0;
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job = ClassRegistry::init('Job');
			$this->Job->id = $jobId;
			$eventCount = count($eventIds);
		}
		foreach (array_values($eventIds) as $j => $id) {
			if ($jobId && Configure::read('MISP.background_jobs')) {
				if ($attributeId) {
					$this->Job->saveField('message', 'Correlating Attribute ' . $attributeId);
				} else {
					$this->Job->saveField('message', 'Correlating Event ' . $id);
				}
				$this->Job->saveField('progress', ($startPercentage + ($j / $eventCount * (100 - $startPercentage))));
			}
			$event = $this->Event->find('first', array(
					'recursive' => -1,
					'fields' => array('Event.distribution', 'Event.id', 'Event.info', 'Event.org_id', 'Event.date', 'Event.sharing_group_id', 'Event.disable_correlation'),
					'conditions' => array('id' => $id),
					'order' => array()
			));
			$attributeConditions = array('Attribute.event_id' => $id, 'Attribute.deleted' => 0);
			if ($attributeId) {
				$attributeConditions['Attribute.id'] = $attributeId;
			}
			$attributes = $this->find('all', array('recursive' => -1, 'conditions' => $attributeConditions, 'order' => array()));
			foreach ($attributes as $k => $attribute) {
				$this->__afterSaveCorrelation($attribute['Attribute'], true, $event);
				$attributeCount++;
			}
		}
		if ($jobId && Configure::read('MISP.background_jobs')) $this->Job->saveField('message', 'Job done.');
		return $attributeCount;
	}

	public function purgeCorrelations($eventId = false, $attributeId = false) {
		if (!$eventId) {
			$this->query('TRUNCATE TABLE correlations;');
		} else if (!$attributeId) {
			$this->Correlation = ClassRegistry::init('Correlation');
			$this->Correlation->deleteAll(array('OR' => array(
				'Correlation.1_event_id' => $eventId,
				'Correlation.event_id' => $eventId))
			);
		} else {
			$this->Correlation->deleteAll(array('OR' => array(
				'Correlation.1_attribute_id' => $attributeId,
				'Correlation.attribute_id' => $attributeId))
			);
		}
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


	public function checkTemplateAttributes($template, $data, $event_id) {
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
		$element['complex'] = 0;
		if ($element['malware']) {
			$element['type'] = 'malware-sample';
			$element['to_ids'] = 1;
		} else {
			$element['type'] = 'attachment';
			$element['to_ids'] = 0;
		}
		foreach ($files as $file) {
			if (!$this->checkFilename($file['filename'])) {
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
			$sgids = $this->SharingGroup->fetchAllAuthorised($user);
			$conditions = array(
				'AND' => array(
					array(
						'OR' => array(
							'Event.org_id' => $user['org_id'],
							array(
								'AND' => array(
									'Event.distribution >' => 0,
									'Event.distribution <' => 4,
									Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
								),
							),
							array(
								'AND' => array(
									'Event.sharing_group_id' => $sgids,
									'Event.distribution' => 4,
									Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
								)
							)
						)
					),
					array(
						'OR' => array(
							'Event.org_id' => $user['org_id'],
							'Attribute.distribution' => array('1', '2', '3', '5'),
							'AND '=> array(
								'Attribute.distribution' => 4,
								'Attribute.sharing_group_id' => $sgids,
							)
						)
					),
					array(
						'OR' => array(
							'Attribute.object_id' => 0,
							'Event.org_id' => $user['org_id'],
							'Object.distribution' => array('1', '2', '3', '5'),
							'AND' => array(
								'Object.distribution' => 4,
								'Object.sharing_group_id' => $sgids,
							)
						)
					)
				)
			);
		}
		return $conditions;
	}

	public function listVisibleAttributes($user, $options = array()) {
		$params = array(
			'conditions' => $this->buildConditions($user),
			'recursive' => -1,
			'fields' => array('Attribute.id', 'Attribute.id'),
		);
		if (isset($options['conditions'])) {
			$params['conditions']['AND'][] = $options['conditions'];
		}
		return $this->find('list', $params);
	}

	/*
	 * Unlike the other fetchers, this one foregoes any ACL checks.
	 * the objective is simple: Fetch the given attribute with all related objects needed for the ZMQ output,
	 * standardising on this function for fetching the attribute to be passed to Attribute->save()
	 */
	public function fetchAttribute($id) {
		$attribute = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array('Attribute.id' => $id),
			'contain' => array(
				'Event' => array(
					'Orgc' => array(
						'fields' => array('Orgc.id', 'Orgc.uuid', 'Orgc.name')
					),
					'fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.uuid', 'Event.published', 'Event.analysis', 'Event.threat_level_id', 'Event.org_id', 'Event.orgc_id', 'Event.distribution', 'Event.sharing_group_id')
				),
				'AttributeTag' => array(
					'Tag' => array('fields' => array('Tag.id', 'Tag.name', 'Tag.colour', 'Tag.exportable'))
				),
				'Object'
			)
		));
		if (!empty($attribute)) {
			if (!empty($attribute['AttributeTag'])) {
				foreach ($attribute['AttributeTag'] as $at) {
					if ($at['Tag']['exportable']) $attribute['Attribute']['Tag'][] = $at['Tag'];
				}
			}
			unset($attribute['AttributeTag']);
		}
		return $attribute;
	}

	public function fetchAttributesSimple($user, $options = array()) {
		$params = array(
			'conditions' => $this->buildConditions($user),
			'fields' => array(),
			'recursive' => -1
		);
		if (isset($options['conditions'])) {
			$params['conditions']['AND'][] = $options['conditions'];
		}
		if (isset($options['fields'])) {
			$params['fields'] = $options['fields'];
		}
		$results = $this->find('all', array(
			'conditions' => $params['conditions'],
			'recursive' => -1,
			'fields' => $params['fields'],
			'sort' => false
		));
		return $results;

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
					'fields' => array('id', 'info', 'org_id', 'orgc_id', 'uuid'),
				),
				'Object' => array(
					'fields' => array('id', 'distribution', 'sharing_group_id')
				)
			)
		);
		$params['contain']['AttributeTag'] = array('Tag' => array('conditions' => array()));
		if (empty($options['includeAllTags'])) $params['contain']['AttributeTag']['Tag']['conditions']['exportable'] = 1;
		if (isset($options['contain'])) $params['contain'] = array_merge_recursive($params['contain'], $options['contain']);
		else $option['contain']['Event']['fields'] = array('id', 'info', 'org_id', 'orgc_id');
		if (Configure::read('MISP.proposals_block_attributes') && isset($options['conditions']['AND']['Attribute.to_ids']) && $options['conditions']['AND']['Attribute.to_ids'] == 1) {
			$this->bindModel(array('hasMany' => array('ShadowAttribute' => array('foreignKey' => 'old_id'))));
			$proposalRestriction =  array(
					'ShadowAttribute' => array(
							'conditions' => array(
									'AND' => array(
											'ShadowAttribute.deleted' => 0,
											'OR' => array(
													'ShadowAttribute.proposal_to_delete' => 1,
													'ShadowAttribute.to_ids' => 0
											)
									)
							),
							'fields' => array('ShadowAttribute.id')
					)
			);
			$params['contain'] = array_merge($params['contain'], $proposalRestriction);
		}
		if (isset($options['fields'])) $params['fields'] = $options['fields'];
		if (isset($options['conditions'])) $params['conditions']['AND'][] = $options['conditions'];
		if (empty($options['flatten'])) $params['conditions']['AND'][] = array('Attribute.object_id' => 0);
		if (isset($options['order'])) $params['order'] = $options['order'];
		if (!isset($options['withAttachments'])) $options['withAttachments'] = false;
		else ($params['order'] = array());
		if (!isset($options['enforceWarninglist'])) $options['enforceWarninglist'] = false;
		if (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted']) $params['conditions']['AND']['Attribute.deleted'] = 0;
		if (isset($options['group'])) $params['group'] = empty($options['group']) ? $options['group'] : false;
		if (Configure::read('MISP.unpublishedprivate')) $params['conditions']['AND'][] = array('OR' => array('Event.published' => 1, 'Event.orgc_id' => $user['org_id']));
		if (!empty($options['list'])) {
			if (!empty($options['event_ids'])) {
				$fields = array('Attribute.event_id', 'Attribute.event_id');
				$group = array('Attribute.event_id');
			} else {
				$fields = array('Attribute.event_id');
				$group = false;
			}
			$results = $this->find('list', array(
				'conditions' => $params['conditions'],
				'recursive' => -1,
				'contain' => array('Event', 'Object'),
				'fields' => $fields,
				'group' => $group,
				'sort' => false
			));
			return $results;
		}
		$results = $this->find('all', $params);
		if ($options['enforceWarninglist']) {
			$this->Warninglist = ClassRegistry::init('Warninglist');
			$warninglists = $this->Warninglist->fetchForEventView();
		}
		$results = array_values($results);
		$proposals_block_attributes = Configure::read('MISP.proposals_block_attributes');
		foreach ($results as $key => $attribute) {
			if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttributes($warninglists, $attribute['Attribute'])) {
				unset($results[$key]);
				continue;
			}
			if (!empty($options['includeAttributeUuid'])) {
				$results[$key]['Attribute']['event_uuid'] = $results[$key]['Event']['uuid'];
			}
			if ($proposals_block_attributes) {
				if (!empty($attribute['ShadowAttribute'])) {
					unset($results[$key]);
				} else {
					unset($results[$key]['ShadowAttribute']);
				}
			}
			if ($options['withAttachments']) {
				if ($this->typeIsAttachment($attribute['Attribute']['type'])) {
					$encodedFile = $this->base64EncodeAttachment($attribute['Attribute']);
					$results[$key]['Attribute']['data'] = $encodedFile;
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
		$attachments_dir = Configure::read('MISP.attachments_dir');
		if (empty($attachments_dir)) {
			$my_server = ClassRegistry::init('Server');
			$attachments_dir = $my_server->getDefaultAttachments_dir();
		}
		if ($proposal) {
			$dir = new Folder($attachments_dir . DS . $event_id . DS . 'shadow', true);
		} else {
			$dir = new Folder($attachments_dir . DS . $event_id, true);
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
		return (new RandomTool())->random_str(FALSE, 12);
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
		$attribute['Attribute']['deleted'] = 0;
		$date = new DateTime();
		$attribute['Attribute']['timestamp'] = $date->getTimestamp();
		if ($this->save($attribute['Attribute'])) {
			$attribute['Event']['published'] = 0;
			$attribute['Event']['timestamp'] = $date->getTimestamp();
			$this->Event->save($attribute['Event']);
			return true;
		}
		else return 'Could not save changes.';
	}

	public function saveAttributes($attributes) {
		foreach ($attributes as $k => $attribute) {
			if (!empty($attribute['encrypt']) && $attribute['encrypt']) {
				if (strpos($attribute['value'], '|') !== false) {
					$temp = explode('|', $attribute['value']);
					$attribute['value'] = $temp[0];
				}
				$result = $this->handleMaliciousBase64($attribute['event_id'], $attribute['value'], $attribute['data'], array('md5'));
				$attribute['data'] = $result['data'];
				$attribute['value'] = $attribute['value'] . '|' . $result['md5'];
			}
			unset($attribute['Attachment']);
			$this->create();
			$this->save($attribute);
		}
		return true;
	}

	public function saveAndEncryptAttribute($attribute, $user = false) {
		$hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
		if ($attribute['encrypt']) {
			$result = $this->handleMaliciousBase64($attribute['event_id'], $attribute['value'], $attribute['data'], array_keys($hashes));
			if (!$result['success']) {
				return 'Could not handle the sample';
			}
			foreach ($hashes as $hash => $typeName) {
				if (!$result[$hash]) continue;
				$attributeToSave = array(
					'Attribute' => array(
						'value' => $attribute['value'] . '|' . $result[$hash],
						'category' => $attribute['category'],
						'type' => $typeName,
						'event_id' => $attribute['event_id'],
						'comment' => $attribute['comment'],
						'to_ids' => 1,
						'distribution' => $attribute['distribution'],
						'sharing_group_id' => isset($attribute['sharing_group_id']) ? $attribute['sharing_group_id'] : 0,
					)
				);
				if ($hash == 'md5') $attributeToSave['Attribute']['data'] = $result['data'];
				$this->create();
				if (!$this->save($attributeToSave)) {
					return $this->validationErrors;
				}
			}
		}
		return true;
	}

	public function convertToOpenIOC($user, $attributes) {
		return $this->IOCExport->buildAll($this->Auth->user(), $event);
	}

	private function __createTagSubQuery($tag_id, $blocked = false, $scope = 'Event', $limitAttributeHitsTo = 'event') {
		$conditionKey = $blocked ? array('NOT' => array('EventTag.tag_id' => $tag_id)) : array('EventTag.tag_id' => $tag_id);
		$db = $this->getDataSource();
		$subQuery = $db->buildStatement(
			array(
				'fields' => array($scope . 'Tag.' . $limitAttributeHitsTo . '_id'),
				'table' => strtolower($scope) . '_tags',
				'alias' => $scope . 'Tag',
				'limit' => null,
				'offset' => null,
				'joins' => array(),
				'conditions' => array(
					$scope . 'Tag.tag_id' => $tag_id
				),
				'group' => array($scope . 'Tag.' . $limitAttributeHitsTo . '_id')
			),
			$this
		);
		$subQuery = ucfirst($limitAttributeHitsTo) . '.id IN (' . $subQuery . ') ';
		$conditions = array(
			$db->expression($subQuery)->value
		);
		return $conditions;
	}

	public function setTagConditions($tags, $conditions, $limitAttributeHitsTo = 'event') {
		$args = $this->dissectArgs($tags);
		$tagArray = $this->AttributeTag->Tag->fetchTagIdsFromFilter($args[0], $args[1]);
		$temp = array();
		if (!empty($tagArray[0])) {
			$temp['OR'][] = $this->__createTagSubQuery($tagArray[0]);
			$temp['OR'][] = $this->__createTagSubQuery($tagArray[0], false, 'Attribute', $limitAttributeHitsTo);
		}
		if (!empty($tagArray[1])) {
			$temp['AND']['NOT'] = $this->__createTagSubQuery($tagArray[1], true);
		}
		$conditions['AND'][] = $temp;
		return $conditions;
	}

	public function setPublishTimestampConditions($publish_timestamp, $conditions) {
		if (is_array($publish_timestamp)) {
			$conditions['AND'][] = array('Event.publish_timestamp >=' => $publish_timestamp[0]);
			$conditions['AND'][] = array('Event.publish_timestamp <=' => $publish_timestamp[1]);
		} else {
			$conditions['AND'][] = array('Event.publish_timestamp >=' => $publish_timestamp);
		}
		return $conditions;
	}

	public function setTimestampConditions($timestamp, $conditions, $scope = 'Event') {
		if (is_array($timestamp)) {
			$conditions['AND'][] = array($scope . '.timestamp >=' => $timestamp[0]);
			$conditions['AND'][] = array($scope . '.timestamp <=' => $timestamp[1]);
		} else {
			$conditions['AND'][] = array($scope . '.timestamp >=' => $timestamp);
		}
		return $conditions;
	}

	public function setToIDSConditions($to_ids, $conditions) {
		if ($to_ids === 'exclude') {
			$conditions['AND'][] = array('Attribute.to_ids' => 0);
		} else {
			$conditions['AND'][] = array('Attribute.to_ids' => 1);
		}
		return $conditions;
	}

	public function setSimpleConditions($parameterKey, $parameterValue, $conditions) {
		$subcondition = array();
		App::uses('CIDRTool', 'Tools');
		$cidr = new CIDRTool();
		if (is_array($parameterValue)) $elements = $parameterValue;
		else $elements = explode('&&', $parameterValue);
		foreach ($elements as $v) {
			if (empty($v)) continue;
			if (substr($v, 0, 1) == '!') {
				// check for an IPv4 address and subnet in CIDR notation (e.g. 127.0.0.1/8)
				if ($parameterKey === 'value' && $cidr->checkCIDR(substr($v, 1), 4)) {
					$cidrresults = $cidr->CIDR(substr($v, 1));
					foreach ($cidrresults as $result) {
						$subcondition['AND'][] = array('Attribute.value NOT LIKE' => $result);
					}
				} else if ($parameterKey === 'org') {
						// from here
						$found_orgs = $this->Event->Org->find('all', array(
								'recursive' => -1,
								'conditions' => array('LOWER(name) LIKE' => '%' . strtolower(substr($v, 1)) . '%'),
						));
						foreach ($found_orgs as $o) $subcondition['AND'][] = array('Event.orgc_id !=' => $o['Org']['id']);
				} else if ($parameterKey === 'eventid') {
					$subcondition['AND'][] = array('Attribute.event_id !=' => substr($v, 1));
				} else if ($parameterKey === 'uuid') {
					$subcondition['AND'][] = array('Event.uuid !=' => substr($v, 1));
					$subcondition['AND'][] = array('Attribute.uuid !=' => substr($v, 1));
				} else {
					$subcondition['AND'][] = array('Attribute.' . $parameterKey . ' NOT LIKE' => '%'.substr($v, 1).'%');
				}
			} else {
				// check for an IPv4 address and subnet in CIDR notation (e.g. 127.0.0.1/8)
				if ($parameterKey === 'value' && $cidr->checkCIDR($v, 4)) {
					$cidrresults = $cidr->CIDR($v);
					foreach ($cidrresults as $result) {
						$subcondition['OR'][] = array('Attribute.value LIKE' => $result);
					}
				} else if ($parameterKey === 'org') {
					// from here
					$found_orgs = $this->Event->Org->find('all', array(
							'recursive' => -1,
							'conditions' => array('LOWER(name) LIKE' => '%' . strtolower($v) . '%'),
					));
					foreach ($found_orgs as $o) $subcondition['OR'][] = array('Event.orgc_id' => $o['Org']['id']);
				} else if ($parameterKey === 'eventid') {
					if (!empty($v)) $subcondition['OR'][] = array('Attribute.event_id' => $v);
				} else if ($parameterKey === 'uuid') {
					$subcondition['OR'][] = array('Attribute.uuid' => $v);
					$subcondition['OR'][] = array('Event.uuid' => $v);
				} else {
					if (!empty($v)) $subcondition['OR'][] = array('Attribute.' . $parameterKey . ' LIKE' => '%'.$v.'%');
				}
			}
		}
		array_push ($conditions['AND'], $subcondition);
		return $conditions;
	}

	private function __getCIDRList() {
		return $this->find('list', array(
			'conditions' => array(
				'type' => array('ip-src', 'ip-dst'),
				'value1 LIKE' => '%/%'
			),
			'fields' => array('value1'),
			'order' => false
		));
	}

	public function setCIDRList() {
		$redis = $this->setupRedis();
		$cidrList = array();
		if ($redis) {
			$redis->del('misp:cidr_cache_list');
			$cidrList = $this->__getCIDRList();
			$pipeline = $redis->multi(Redis::PIPELINE);
			foreach ($cidrList as $cidr) {
				$pipeline->sadd('misp:cidr_cache_list', $cidr);
			}
			$pipeline->exec();
			$redis->smembers('misp:cidr_cache_list');
		}
		return $cidrList;
	}

	public function getSetCIDRList() {
		$redis = $this->setupRedis();
		if ($redis) {
			if (!$redis->exists('misp:cidr_cache_list') || $redis->sCard('misp:cidr_cache_list') == 0) {
				$cidrList = $this->setCIDRList($redis);
			} else {
				$cidrList = $redis->smembers('misp:cidr_cache_list');
			}
		} else {
			$cidrList = $this->__getCIDRList();
		}
		return $cidrList;
	}

	public function fetchDistributionData($user) {
		$initialDistribution = 5;
		if (Configure::read('MISP.default_attribute_distribution') != null) {
			if (Configure::read('MISP.default_attribute_distribution') === 'event') {
				$initialDistribution = 5;
			} else {
				$initialDistribution = Configure::read('MISP.default_attribute_distribution');
			}
		}
		$sgs = $this->SharingGroup->fetchAllAuthorised($user, 'name', 1);
		$this->set('sharingGroups', $sgs);
		$distributionLevels = $this->distributionLevels;
		if (empty($sgs)) {
			unset($distributionLevels[4]);
		}
		return array('sgs' => $sgs, 'levels' => $distributionLevels, 'initial' => $initialDistribution);
	}

	public function simpleAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile) {
		$attributes = array(
			'malware-sample' => array('type' => 'malware-sample', 'data' => 1, 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'malware-sample'),
			'filename' => array('type' => 'filename', 'category' => '', 'to_ids' => 0, 'disable_correlation' => 0, 'object_relation' => 'filename'),
			'md5' => array('type' => 'md5', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'md5'),
			'sha1' => array('type' => 'sha1', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'sha1'),
			'sha256' => array('type' => 'sha256', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'sha256'),
			'size-in-bytes' => array('type' => 'size-in-bytes', 'category' => 'Other', 'to_ids' => 0, 'disable_correlation' => 1, 'object_relation' => 'size-in-bytes')
		);
		$hashes = array('md5', 'sha1', 'sha256');
		$this->Object = ClassRegistry::init('Object');
		$this->ObjectTemplate = ClassRegistry::init('ObjectTemplate');
		$current = $this->ObjectTemplate->find('first', array(
			'fields' => array('MAX(version) AS version', 'uuid'),
			'conditions' => array('uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215'),
			'recursive' => -1,
			'group' => array('uuid')
		));
		if (!empty($current)) {
			$object_template = $this->ObjectTemplate->find('first', array(
				'conditions' => array(
					'ObjectTemplate.uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215',
					'ObjectTemplate.version' => $current[0]['version']
				),
				'recursive' => -1
			));
		}
		if (empty($object_template)) {
			$object_template = array(
				'ObjectTemplate' => array(
					'meta-category' => 'file',
					'name' => 'file',
					'uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215',
					'version' => 1,
					'description' => 'File object describing a file with meta-information'
				)
			);
		}
		$object = array(
			'distribution' => $attribute_settings['distribution'],
			'sharing_group_id' => isset($attribute_settings['sharing_group_id']) ? $attribute_settings['sharing_group_id'] : 0,
			'meta-category' => $object_template['ObjectTemplate']['meta-category'],
			'name' => $object_template['ObjectTemplate']['name'],
			'template_version' => $object_template['ObjectTemplate']['version'],
			'description' => $object_template['ObjectTemplate']['description'],
			'template_uuid' => $object_template['ObjectTemplate']['uuid'],
			'event_id' => $event_id,
			'comment' => !empty($attribute_settings['comment']) ? $attribute_settings['comment'] : ''
		);
		$result = $this->Event->Attribute->handleMaliciousBase64($event_id, $filename, base64_encode($tmpfile->read()), $hashes);
		foreach ($attributes as $k => $v) {
			$attribute = array(
				'distribution' => 5,
				'category' => empty($v['category']) ? $attribute_settings['category'] : $v['category'],
				'type' => $v['type'],
				'to_ids' => $v['to_ids'],
				'disable_correlation' => $v['disable_correlation'],
				'object_id' => $this->Object->id,
				'event_id' => $event_id,
				'object_relation' => $v['object_relation']
			);
			if (isset($v['data'])) {
				$attribute['data'] = $result['data'];
			}
			if ($k == 'malware-sample') {
				$attribute['value'] = $filename . '|' . $result['md5'];
			} else if ($k == 'size-in-bytes') {
				$attribute['value'] = $tmpfile->size();
			} else if ($k == 'filename') {
				$attribute['value'] = $filename;
			} else {
				$attribute['value'] = $result[$v['type']];
			}
			$object['Attribute'][] = $attribute;
		}
		return array('Object' => array($object));
	}

	public function advancedAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile) {
		$execRetval = '';
		$execOutput = array();
		$result = shell_exec('python ' . APP . 'files/scripts/generate_file_objects.py -p ' . $tmpfile->path);
		if (!empty($result)) {
			$result = json_decode($result, true);
			if (isset($result['objects'])) {
				$result['Object'] = $result['objects'];
				unset($result['objects']);
			}
			if (isset($result['references'])) {
				$result['ObjectReference'] = $result['references'];
				unset($result['references']);
			}
			foreach ($result['Object'] as $k => $object) {
				$result['Object'][$k]['distribution'] = $attribute_settings['distribution'];
				$result['Object'][$k]['sharing_group_id'] = isset($attribute_settings['distribution']) ? $attribute_settings['distribution'] : 0;
				if (!empty($result['Object'][$k]['Attribute'])) {
					foreach ($result['Object'][$k]['Attribute'] as $k2 => $attribute) {
						if ($attribute['value'] == $tmpfile->name) {
							$result['Object'][$k]['Attribute'][$k2]['value'] = $filename;
						}
						if (!empty($attribute['encrypt'])) {
							if (!empty($attribute['encrypt']) && $attribute['encrypt']) {
								$encrypted = $this->handleMaliciousBase64($event_id, $filename, $attribute['data'], array('md5'));
								$result['Object'][$k]['Attribute'][$k2]['data'] = $encrypted['data'];
								$result['Object'][$k]['Attribute'][$k2]['value'] = $filename . '|' . $encrypted['md5'];
							}
						}
					}
				}
			}
		} else {
			$result = $this->simpleAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile);
		}
		return $result;
	}

	// gets an attribute, saves it
	// handles encryption, attaching to event/object, logging of issues, tag capturing
	public function captureAttribute($attribute, $eventId, $user, $objectId = false, $log = false) {
		if ($log == false) {
			$log = ClassRegistry::init('Log');
		}
		$attribute['event_id'] = $eventId;
		$attribute['object_id'] = $objectId ? $objectId : 0;
		unset($attribute['id']);
		if (isset($attribute['encrypt'])) {
			$result = $this->handleMaliciousBase64($eventId, $attribute['value'], $attribute['data'], array('md5'));
		}
		$fieldList = array(
			'event_id',
			'category',
			'type',
			'value',
			'value1',
			'value2',
			'to_ids',
			'uuid',
			'timestamp',
			'distribution',
			'comment',
			'sharing_group_id',
			'deleted',
			'disable_correlation',
			'object_id',
			'object_relation'
		);
		$this->create();
		if (!$this->save($attribute, array('fieldList' => $fieldList))) {
			$attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
			$log->create();
			$log->save(array(
					'org' => $user['Organisation']['name'],
					'model' => 'Attribute',
					'model_id' => 0,
					'email' => $user['email'],
					'action' => 'add',
					'user_id' => $user['id'],
					'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed: ' . $attribute_short,
					'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
			));
			} else {
				if (isset($attribute['AttributeTag'])) {
					foreach ($attribute['AttributeTag'] as $at) {
						unset($at['id']);
						$this->AttributeTag->create();
						$at['attribute_id'] = $this->id;
						$at['event_id'] = $eventId;
						$this->AttributeTag->save($at);
					}
				}
				if (!empty($attribute['Sighting'])) {
					foreach ($attribute['Sighting'] as $k => $sighting) {
						$this->Sighting->captureSighting($sighting, $this->id, $eventId, $user);
					}
				}
			}
		return $attribute;
	}

	public function editAttribute($attribute, $eventId, $user, $objectId, $log = false) {
		$attribute['event_id'] = $eventId;
		$attribute['object_id'] = $objectId;
		if (isset($attribute['encrypt'])) {
			$result = $this->handleMaliciousBase64($eventId, $attribute['value'], $attribute['data'], array('md5'));
			$attribute['data'] = $result['data'];
			$attribute['value'] = $attribute['value'] . '|' . $result['md5'];
		}
		if (isset($attribute['uuid'])) {
			$existingAttribute = $this->find('first', array(
				'conditions' => array('Attribute.uuid' => $attribute['uuid']),
				'recursive' => -1
			));
			if (count($existingAttribute)) {
				if ($existingAttribute['Attribute']['event_id'] != $eventId || $existingAttribute['Attribute']['object_id'] != $objectId) {
					$result = $this->Log->save(array(
							'org' => $user['Organisation']['name'],
							'model' => 'Attribute',
							'model_id' => 0,
							'email' => $user['email'],
							'action' => 'edit',
							'user_id' => $user['id'],
							'title' => 'Duplicate UUID found in attribute',
							'change' => 'An attribute was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $attribute['uuid'] . '. This can also be due to the same attribute (or an attribute with the same UUID) existing in a different event / object)',
					));
					return true;
				}
				// If a field is not set in the request, just reuse the old value
				$recoverFields = array('value', 'to_ids', 'distribution', 'category', 'type', 'comment', 'sharing_group_id', 'object_id', 'object_relation');
				foreach ($recoverFields as $rF) if (!isset($attribute[$rF])) $attribute[$rF] = $existingAttribute['Attribute'][$rF];
				$attribute['id'] = $existingAttribute['Attribute']['id'];
				// Check if the attribute's timestamp is bigger than the one that already exists.
				// If yes, it means that it's newer, so insert it. If no, it means that it's the same attribute or older - don't insert it, insert the old attribute.
				// Alternatively, we could unset this attribute from the request, but that could lead with issues if we decide that we want to start deleting attributes that don't exist in a pushed event.
				if (isset($attribute['timestamp'])) {
					if ($attribute['timestamp'] <= $existingAttribute['Attribute']['timestamp']) {
						return true;
					}
				} else {
					$date = new DateTime();
					$attribute['timestamp'] = $date->getTimestamp();;
				}
			} else {
				$this->create();
			}
		} else {
			$this->create();
		}
	$attribute['event_id'] = $eventId;
		if (isset($attribute['distribution']) && $attribute['distribution'] == 4) {
			if (!empty($attribute['SharingGroup'])) {
				$attribute['sharing_group_id'] = $this->SharingGroup->captureSG($attribute['SharingGroup'], $user);
			} elseif (!empty($attribute['sharing_group_id'])) {
				if (!$this->SharingGroup->checkIfAuthorised($user, $attribute['sharing_group_id'])) {
					unset($attribute['sharing_group_id']);
				}
			}
			if (empty($attribute['sharing_group_id'])) {
				$attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
				$this->Log = ClassRegistry::init('Log');
				$this->Log->create();
				$this->Log->save(array(
					'org' => $user['Organisation']['name'],
					'model' => 'Attribute',
					'model_id' => 0,
					'email' => $user['email'],
					'action' => 'edit',
					'user_id' => $user['id'],
					'title' => 'Attribute dropped due to invalid sharing group for Event ' . $eventId . ' failed: ' . $attribute_short,
					'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
				));
				return 'Invalid sharing group choice.';
			}
		}
		$fieldList = array(
			'event_id',
			'category',
			'type',
			'value',
			'value1',
			'value2',
			'to_ids',
			'uuid',
			'revision',
			'distribution',
			'timestamp',
			'comment',
			'sharing_group_id',
			'deleted',
			'disable_correlation'
		);
		if ($objectId) {
			$fieldList[] = 'object_id';
			$fieldList[] = 'object_relation';
		}
		if (!$this->save(array('Attribute' => $attribute), array('fieldList' => $fieldList))) {
			$attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
				'org' => $user['Organisation']['name'],
				'model' => 'Attribute',
				'model_id' => 0,
				'email' => $user['email'],
				'action' => 'edit',
				'user_id' => $user['id'],
				'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed: ' . $attribute_short,
				'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
			));
			return $this->validationErrors;
		} else {
			if (isset($attribute['Tag']) && $user['Role']['perm_tagger']) {
				foreach ($attribute['Tag'] as $tag) {
					$tag_id = $this->AttributeTag->Tag->captureTag($tag, $user);
					if ($tag_id) {
						// fix the IDs here
						$this->AttributeTag->attachTagToAttribute($this->id, $this->id, $tag_id);
					} else {
						// If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
						// However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
						// In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
						if ($user['Role']['perm_tag_editor']) {
							$this->Log->create();
							$this->Log->save(array(
								'org' => $user['Organisation']['name'],
								'model' => 'Attrubute',
								'model_id' => $this->id,
								'email' => $user['email'],
								'action' => 'edit',
								'user_id' => $user['id'],
								'title' => 'Failed create or attach Tag ' . $tag['name'] . ' to the attribute.',
								'change' => ''
							));
						}
					}
				}
			}
		}
		return true;
	}
}
