<?php

class ComplexTypeTool {

	private $__refangRegexTable = array(
		'/^hxxp/i' => 'http',
		'/^meow/i' => 'http',
		'/^h\[tt\]p/i' => 'http',
		'/\[\.\]/' => '.',
		'/\[dot\]/' => '.',
		'/\(dot\)/' => '.',
		'/\\\\\./' => '.',
		'/\.+/' => '.',
		'/\[hxxp:\/\/\]/' => 'http://',
		'/\\\/' => ''
	);

	private $__tlds = array();

	public function setTLDs($tlds = array()) {
		if (!empty($tlds)) {
			$this->__tlds = $tlds;
		}
	}

	public function checkComplexRouter($input, $type, $settings = array()) {
		switch ($type) {
			case 'File':
				return $this->checkComplexFile($input);
				break;
			case 'CnC':
				return $this->checkComplexCnC($input);
				break;
			case 'freetext':
			case 'FreeText':
				return $this->checkFreeText($input, $settings);
				break;
			case 'csv':
				return $this->checkCSV($input, $settings);
				break;
			default:
				return false;
		}
	}

	// checks if the passed input matches a valid file description attribute's pattern (filename, md5, sha1, sha256, filename|md5, filename|sha1, filename|sha256)
	public function checkComplexFile($input) {
		$original = $input;
		$type = '';
		$composite = false;
		if (strpos($input, '|')) {
			$composite = true;
			$result = explode('|', $input);
			if (count($result) != 2 || !preg_match("#^.+#", $result[0])) {
				$type = 'other';
			} else {
				$type = 'filename|';
			}
			$input = $result[1];
		}
		if (strlen($input) == 32 && preg_match("#[0-9a-f]{32}$#", $input)) $type .= 'md5';
		if (strlen($input) == 40 && preg_match("#[0-9a-f]{40}$#", $input)) $type .= 'sha1';
		if (strlen($input) == 64 && preg_match("#[0-9a-f]{64}$#", $input)) $type .= 'sha256';
		if ($type == '' && !$composite && preg_match("#^.+#", $input)) $type = 'filename';
		if ($type == '') $type = 'other';
		return array('type' => $type, 'value' => $original);
	}

	public function checkComplexCnC($input) {
		$toReturn = array();
		// check if it's an IP address
		if (filter_var($input, FILTER_VALIDATE_IP)) return array('type' => 'ip-dst', 'value' => $input);
		if (preg_match("#^[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $input)) {
			$result = explode('.', $input);
			if (count($result) > 2) {
				$toReturn['multi'][] = array('type' => 'hostname', 'value' => $input);
				$pos = strpos($input, '.');
				$toReturn['multi'][] = array('type' => 'domain', 'value' => substr($input, (1 + $pos)));
				return $toReturn;
			}
			return array('type' => 'domain', 'value' => $input);
		}

		if (!preg_match("#\n#", $input)) return array('type' => 'url', 'value' => $input);
		return array('type' => 'other', 'value' => $input);
	}

	private function __returnOddElements($array) {
		foreach ($array as $k => $v) if ($k % 2 != 1) unset($array[$k]);
		return array_values($array);
	}

	private function __parse_row($row, $delimiter) {
		$columns = str_getcsv($row, $delimiter);
		return $columns;
	}

	/*
	 * parse a CSV file with the given settings
	 * All lines starting with # are stripped
	 * The settings can contain the following:
	 *     delimiter: Expects a delimiter string (default is a simple comma).
	 *                For example, to split the following line: "value1##comma##value2" simply pass $settings['delimiter'] = "##comma##";
	 *     values:    Expects an array (or a comma separated string) with numeric values denoting the columns containing indicators. If this is not set then every value will be checked. (column numbers start at 1)
	 */
	public function checkCSV($input, $settings = array()) {
		$delimiter = !empty($settings['delimiter']) ? $settings['delimiter'] : ",";
		$rows = str_getcsv($input, "\n");
		$data = array();
		foreach ($rows as $k => $row) {
			if (empty($row[0]) || $row[0] === '#') continue;
			if ($delimiter == '\t') {
				$data[$k] = explode("\t", $row);	
			} else {
				$data[$k] = str_getcsv($row, $delimiter);
			}
		}
		unset($rows);
		unset($input);
		$values = !empty($settings['value']) ? $settings['value'] : array();
		if (!is_array($values)) {
			$values = explode(',', $values);
		}
		foreach ($values as $key => $value) {
			$values[$key] = intval($value);
		}
		$iocArray = array();
		foreach ($data as $rowPos => $row) {
			foreach ($row as $elementPos => $element) {
				if ((!empty($values) && in_array(($elementPos + 1), $values)) || empty($values)) {
					$element = trim($element, " \t\n\r\0\x0B\"\'");
					if (isset($settings['excluderegex']) && !empty($settings['excluderegex'])) {
						if (preg_match($settings['excluderegex'], $element)) {
							continue;
						}
					}
					$resolvedResult = $this->__resolveType($element);
					if (!empty($resolvedResult)) {
						$iocArray[] = $resolvedResult;
					}
				}
			}
		}
		return $iocArray;
	}

	public function checkFreeText($input, $settings = array()) {
		$charactersToTrim = array('\'', '"', ',', '(', ')');
		$iocArray = preg_split("/\r\n|\n|\r|\s|\s+|,|;/", $input);
		$quotedText = explode('"', $input);
		foreach ($quotedText as $k => $temp) {
			$temp = trim($temp);
			if (empty($temp)) {
				unset($quotedText[$k]);
			} else {
				$quotedText[$k] = $temp;
			}
		}
		$iocArray = array_merge($iocArray, $this->__returnOddElements($quotedText));
		$resultArray = array();
		if (!empty($iocArray)) {
			foreach ($iocArray as $ioc) {
				$ioc = trim($ioc);
				foreach ($charactersToTrim as $c) {
					$ioc = trim($ioc, $c);
				}
				$ioc = preg_replace('/\p{C}+/u', '', $ioc);
				if (empty($ioc)) continue;
				if (isset($settings['excluderegex']) && !empty($settings['excluderegex'])) {
					if (preg_match($settings['excluderegex'], $ioc)) {
						continue;
					}
				}
				$typeArray = $this->__resolveType($ioc);
				if ($typeArray === false) continue;
				$temp = $typeArray;
				if (!isset($temp['value'])) $temp['value'] = $ioc;
				$resultArray[] = $temp;
			}
		}
		return $resultArray;
	}

	private $__hexHashTypes = array(
		32 => array('single' => array('md5', 'imphash'), 'composite' => array('filename|md5', 'filename|imphash')),
		40 => array('single' => array('sha1', 'pehash', 'x509-fingerprint-sha1'), 'composite' => array('filename|sha1', 'filename|pehash')),
		56 => array('single' => array('sha224', 'sha512/224'), 'composite' => array('filename|sha224', 'filename|sha512/224')),
		64 => array('single' => array('sha256', 'authentihash', 'sha512/256'), 'composite' => array('filename|sha256', 'filename|authentihash', 'filename|sha512/256')),
		96 => array('single' => array('sha384'), 'composite' => array('filename|sha384')),
		128 => array('single' => array('sha512'), 'composite' => array('filename|sha512'))
	);

	private function __resolveType($input) {
		$input = trim($input);
		if (strpos($input, '|')) {
			$compositeParts = explode('|', $input);
			if (count($compositeParts) == 2) {
				if ($this->__resolveFilename($compositeParts[0])) {
					foreach ($this->__hexHashTypes as $k => $v) {
						if (strlen($compositeParts[1]) == $k && preg_match("#[0-9a-f]{" . $k . "}$#i", $compositeParts[1])) return array('types' => $v['composite'], 'to_ids' => true, 'default_type' => $v['composite'][0], 'value' => $input);
					}
					if (preg_match('#^[0-9]+:[0-9a-zA-Z\/\+]+:[0-9a-zA-Z\/\+]+$#', $compositeParts[1]) && !preg_match('#^[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}$#', $compositeParts[1])) {
						return array('types' => array('ssdeep'), 'to_ids' => true, 'default_type' => 'filename|ssdeep', 'value' => $input);
					}
				}
			}
		}

		// check for hashes
		foreach ($this->__hexHashTypes as $k => $v) {
			if (strlen($input) == $k && preg_match("#[0-9a-f]{" . $k . "}$#i", $input)) return array('types' => $v['single'], 'to_ids' => true, 'default_type' => $v['single'][0], 'value' => $input);
		}
		if (preg_match('#^[0-9]+:[0-9a-zA-Z\/\+]+:[0-9a-zA-Z\/\+]+$#', $input) && !preg_match('#^[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}$#', $input)) return array('types' => array('ssdeep'), 'to_ids' => true, 'default_type' => 'ssdeep', 'value' => $input);
		$inputRefanged = $input;
		foreach ($this->__refangRegexTable as $regex => $replacement) {
			$inputRefanged = preg_replace($regex, $replacement , $inputRefanged);
		}
		$inputRefanged = rtrim($inputRefanged, ".");
		if (strpos($input, '@') !== false) {
			if (filter_var($input, FILTER_VALIDATE_EMAIL)) return array('types' => array('email-src', 'email-dst', 'target-email', 'whois-registrant-email'), 'to_ids' => true, 'default_type' => 'email-src', 'value' => $input);
		}
		// note down and remove the port if it's a url / domain name / hostname / ip
		// input2 from here on is the variable containing the original input with the port removed. It is only used by url / domain name / hostname / ip
		$comment = false;
		if (preg_match('/(:[0-9]{2,5})$/', $inputRefanged, $port)) {
			$comment = 'On port ' . substr($port[0], 1);
			$inputRefangedNoPort = str_replace($port[0], '', $inputRefanged);
			$port = substr($port[0], 1);
		} else {
			unset($port);
			$inputRefangedNoPort = $inputRefanged;
		}
		// check for IP
		if (filter_var($inputRefangedNoPort, FILTER_VALIDATE_IP)) {
			if (isset($port)) {
				return array('types' => array('ip-dst|port', 'ip-src|port', 'ip-src|port/ip-dst|port'), 'to_ids' => true, 'default_type' => 'ip-dst|port', 'comment' => $comment, 'value' => $inputRefangedNoPort . '|' . $port);
			} else {
				return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'to_ids' => true, 'default_type' => 'ip-dst', 'comment' => $comment, 'value' => $inputRefangedNoPort);
			}
		}
		if (strpos($inputRefangedNoPort, '/')) {
			$temp = explode('/', $inputRefangedNoPort);
			if (count($temp) == 2) {
				if (filter_var($temp[0], FILTER_VALIDATE_IP) && is_numeric($temp[1])) return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'to_ids' => true, 'default_type' => 'ip-dst', 'comment' => $comment, 'value' => $inputRefangedNoPort);
			}
		}
		// check for domain name, hostname, filename
		if (strpos($inputRefanged, '.') !== false) {
			$temp = explode('.', $inputRefanged);
			// TODO: use a more flexible matching approach, like the one below (that still doesn't support non-ASCII domains)
			//if (filter_var($input, FILTER_VALIDATE_URL)) {
			$domainDetection = true;
			if (preg_match('/^([-\pL\pN]+\.)+[a-z]+(:[0-9]{2,5})?$/iu', $inputRefanged)) {
				if (empty($this->__tlds) || count($this->__tlds) == 1) {
					$this->__generateTLDList();
				}
				$tldExploded = explode(':', $temp[count($temp)-1]);
				if (!in_array(strtolower($tldExploded[0]), $this->__tlds)) {
					$domainDetection = false;
				}
			} else {
				$domainDetection = false;
			}
			if ($domainDetection) {
				if (count($temp) > 2) {
					return array('types' => array('hostname', 'domain', 'url'), 'to_ids' => true, 'default_type' => 'hostname', 'comment' => $comment, 'value' => $inputRefangedNoPort);
				} else {
					return array('types' => array('domain'), 'to_ids' => true, 'default_type' => 'domain', 'comment' => $comment, 'value' => $inputRefangedNoPort);
				}
			} else {
				// check if it is a URL
				// Adding http:// infront of the input in case it was left off. github.com/MISP/MISP should still be counted as a valid link
				if (count($temp) > 1 && (filter_var($inputRefangedNoPort, FILTER_VALIDATE_URL) || filter_var('http://' . $inputRefangedNoPort, FILTER_VALIDATE_URL))) {
					// TODO: add comment explaining why there is a check for a specific domain
					if (preg_match('/^https:\/\/(www.)?virustotal.com\//i', $inputRefangedNoPort)) return array('types' => array('link'), 'to_ids' => false, 'default_type' => 'link', 'comment' => $comment, 'value' => $inputRefangedNoPort);
					if (preg_match('/^https:\/\/www\.hybrid-analysis\.com\//i', $inputRefangedNoPort)) return array('types' => array('link'), 'categories' => array('External analysis'), 'to_ids' => false, 'default_type' => 'link', 'comment' => $comment, 'value' => $inputRefangedNoPort);
					if (strpos($inputRefangedNoPort, '/')) return array('types' => array('url'), 'to_ids' => true, 'default_type' => 'url', 'comment' => $comment, 'value' => $inputRefangedNoPort);
				}
				if ($this->__resolveFilename($input)) return array('types' => array('filename'), 'to_ids' => true, 'default_type' => 'filename', 'value' => $inputRefanged);
			}
		}

		if (strpos($input, '\\') !== false) {
			$temp = explode('\\', $input);
			if (strpos($temp[count($temp)-1], '.') || preg_match('/^.:/i', $temp[0])) {
				if ($this->__resolveFilename($temp[count($temp)-1])) return array('types' => array('filename'), 'categories' => array('Payload installation'), 'to_ids' => true, 'default_type' => 'filename', 'value' => $input);
			} else {
				return array('types' => array('regkey'), 'to_ids' => false, 'default_type' => 'regkey', 'value' => $input);
			}
		}

		// check for CVE
		if (preg_match("#^cve-[0-9]{4}-[0-9]{4,9}$#i", $input)) return array('types' => array('vulnerability'), 'categories' => array('External analysis'), 'to_ids' => false, 'default_type' => 'vulnerability', 'value' => $input);
		if (preg_match("#^(\+)?([0-9]{1,3}(\(0\))?)?[0-9\/\-]{5,}[0-9]$#i", $input)) return array('types' => array('phone-number', 'prtn', 'whois-registrant-phone'), 'categories' => array('Other'), 'to_ids' => false, 'default_type' => 'phone-number', 'value' => $input);

		return false;
	}

	private function __resolveFilename($input) {
		if ((preg_match('/^.:/', $input) || strpos($input, '.') !=0)) {
			$parts = explode('.', $input);
			if (!is_numeric($parts[count($parts)-1]) && ctype_alnum($parts[count($parts)-1])) return true;
		}
		return false;
	}

	private function __generateTLDList() {
		$this->__tlds = array('biz', 'cat', 'com', 'edu', 'gov', 'int', 'mil', 'net', 'org', 'pro', 'tel', 'aero', 'arpa', 'asia', 'coop', 'info', 'jobs', 'mobi', 'name', 'museum', 'travel', 'onion');
		$char1 = $char2 = 'a';
		for ($i = 0; $i < 26; $i++) {
			for ($j = 0; $j < 26; $j++) {
				$this->__tlds[] = $char1 . $char2;
				$char2++;
			}
			$char1++;
			$char2 = 'a';
		}
	}
}
