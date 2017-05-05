<?php

class BroExport {

	public $rules = array();

	public $header = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\tmeta.if_in";

	// mapping from misp attribute type to the bro intel type
	// alternative mechanisms are:
	// - alternate: array containing a detection regex and a replacement bro type
	// - composite: for composite misp attributes (domain|ip), use the provided bro type if the second value is queried
	// - replace: run a replacement regex on the value before generating the bro rule
	private $mapping = array(
		'ip-dst' => array('brotype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET')),
		'ip-src' => array('brotype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET')),
		'ip-dst|port' => array('brotype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET'), 'composite' => 'NONE'),
		'ip-src|port' => array('brotype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET'), 'composite' => 'NONE'),
		'email-src' => array('brotype' => 'EMAIL'),
		'email-dst' => array('brotype' => 'EMAIL'),
		'target-email' => array('brotype' => 'EMAIL'),
		'email-attachment' => array('brotype' => 'FILE_NAME'),
		'filename' => array('brotype' => 'FILE_NAME'),
		'hostname' => array('brotype' => 'DOMAIN'),
		'domain' => array('brotype' => 'DOMAIN'),
		'domain|ip' => array('brotype' => 'DOMAIN', 'composite' => 'ADDR'),
		'url' => array('brotype' => 'URL', 'replace' => array('#^https?://#', '')),
		'user-agent' => array('brotype' => 'SOFTWARE'),
		'md5' => array('brotype' => 'FILE_HASH'),
		'malware-sample' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|md5' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'sha1' => array('brotype' => 'FILE_HASH'),
		'filename|sha1' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'sha256' => array('brotype' => 'FILE_HASH'),
		'filename|sha256' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'x509-fingerprint-sha1' => array('brotype' => 'CERT_HASH'),
		'pdb' => array('brotype' => 'FILE_NAME'),
		'authentihash' => array('brotype' => 'FILE_HASH'),
		'ssdeep' => array('brotype' => 'FILE_HASH'),
		'imphash' => array('brotype' => 'FILE_HASH'),
		'pehash' => array('brotype' => 'FILE_HASH'),
		'impfuzzy' => array('brotype' => 'FILE_HASH'),
		'sha224' => array('brotype' => 'FILE_HASH'),
		'sha384' => array('brotype' => 'FILE_HASH'),
		'sha512' => array('brotype' => 'FILE_HASH'),
		'sha512/224' => array('brotype' => 'FILE_HASH'),
		'sha512/256' => array('brotype' => 'FILE_HASH'),
		'tlsh' => array('brotype' => 'FILE_HASH'),
		'filename|authentihash' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|ssdeep' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|imphash' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|pehash' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|impfuzzy' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|sha224' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|sha384' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|sha512' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|sha512/224' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|sha512/256' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
		'filename|tlsh' => array('brotype' => 'FILE_NAME', 'composite' => 'FILE_HASH')
	);

	// export group to misp type mapping
	// the mapped type is in an array format, first value being the misp type, second being the value field used
	public $mispTypes = array(
		'ip' => array(
			array('ip-src', 1),
			array('ip-dst', 1),
			array('ip-src|port', 1),
			array('ip-dst|port', 1),
			array('domain|ip', 2)
		),
		'url' => array(
			array('url', 1)
		),
		'domain' => array(
			array('hostname', 1),
			array('domain', 1),
			array('domain|ip', 1)
		),
		'email' => array(
			array('email-src', 1),
			array('email-dst', 1),
			array('target-email', 1)
		),
		'filename' => array(
			array('filename', 1),
			array('email-attachment', 1),
			array('attachment', 1),
			array('filename|md5', 1),
			array('filename|sha1', 1),
			array('filename|sha256', 1),
			array('malware-sample', 1),
			array('pdb', 1)
		),
		'filehash' => array(
			array('md5', 1),
			array('sha1', 1),
			array('sha256', 1),
			array('authentihash', 1),
			array('ssdeep', 1),
			array('imphash', 1),
			array('pehash', 1),
			array('impfuzzy', 1),
			array('sha224', 1),
			array('sha384', 1),
			array('sha512', 1),
			array('sha512/224', 1),
			array('sha512/256', 1),
			array('tlsh', 1),
			array('filename|md5', 2),
			array('filename|sha1', 2),
			array('filename|sha256', 2),
			array('filename|authentihash', 2),
			array('filename|ssdeep', 2),
			array('filename|imphash', 2),
			array('filename|pehash', 2),
			array('filename|impfuzzy', 2),
			array('filename|sha224', 2),
			array('filename|sha384', 2),
			array('filename|sha512', 2),
			array('filename|sha512/224', 2),
			array('filename|sha512/256', 2),
			array('filename|tlsh', 2),
			array('malware-sample', 2)
		),
		'certhash' => array(
			array('x509-fingerprint-sha1', 1)
		),
		'software' => array(
			array('user-agent', 1)
		)
	);

	private $whitelist = null;

	public function export($items, $orgs, $valueField, $whitelist, $instanceString) {
		$intel = array();
		//For bro format organisation
		$orgsName = array();
		// generate the rules
		foreach ($items as $item) {
			if (!isset($orgs[$item['Event']['orgc_id']])) {
				continue;
			} else {
				$orgName = $instanceString . ' (' . $item['Event']['uuid'] . ')' . ' - ' . $orgs[$item['Event']['orgc_id']];
			}
			$ruleFormatReference = Configure::read('MISP.baseurl') . '/events/view/' . $item['Event']['id'];
			$ruleFormat = "%s\t%s\t" . $orgName . "\t" . $this->replaceIllegalChars($item['Event']['info']) . ". %s" . "\t" . $ruleFormatReference . "\t%s\t%s";
			$rule = $this->__generateRule($item['Attribute'], $ruleFormat, $valueField, $whitelist);
			if (!empty($rule)) {
				$intel[] = $rule;
			}
		}
		return $intel;
	}

	private function __generateRule($attribute, $ruleFormat, $valueField, $whitelist) {
		if (isset($this->mapping[$attribute['type']])) {
			if (! $this->checkWhitelist($attribute['value'], $whitelist)) {
				$brotype = $this->mapping[$attribute['type']]['brotype'];
				if (isset($this->mapping[$attribute['type']]['alternate'])) {
					if (preg_match($this->mapping[$attribute['type']]['alternate'][0], $attribute['value'])) {
						$brotype = $this->mapping[$attribute['type']]['alternate'][1];
					}
				}
				if ($valueField == 2 && isset($this->mapping[$attribute['type']]['composite'])) {
					$brotype = $this->mapping[$attribute['type']]['composite'];
				}
				$attribute['value'] = $this->replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
				if (isset($this->mapping[$attribute['type']]['replace'])) {
					$attribute['value'] = preg_replace(
						$this->mapping[$attribute['type']]['replace'][0],
						$this->mapping[$attribute['type']]['replace'][1],
						$attribute['value']
					);
				}
				return sprintf($ruleFormat,
		                        $this->replaceIllegalChars($attribute['value']),    // value - for composite values only the relevant element is taken
		                        'Intel::' . $brotype,   // type
		                        $this->replaceIllegalChars($attribute['comment']),
		                        'T',    // meta.do_notice
		                        '-'  // meta.if_in
		                        );
			}
		}
		return false;
	}

	/**
	 * Replaces characters that are not allowed in a signature.
	 * @param unknown_type $value
	 */
	public static function replaceIllegalChars($value) {
		$replace_pairs = array(
				"\t" => ' ',
				"\x0B" => ' ',
				"\r" => ' ',
				"\r\n" => ' ',
				"\n" => ' '
		);
		return html_entity_decode(filter_var(strtr($value, $replace_pairs), FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH));
	}

	public function checkWhitelist($value, $whitelist) {
		foreach ($whitelist as $wlitem) {
			if (preg_match($wlitem, $value)) {
				return true;
			}
		}
		return false;
	}

	public function getMispTypes($type) {
		$mispTypes = array();
		if (isset($this->mispTypes[$type])) {
			$mispTypes = $this->mispTypes[$type];
		}
		return $mispTypes;
	}
}
