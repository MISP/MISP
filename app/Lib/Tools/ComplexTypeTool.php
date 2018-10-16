<?php

class ComplexTypeTool
{
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
        '/\\\/' => '',
        '/[\@]/' => '@',
        '/\[:\]/' => ':'
    );

    private $__tlds = array();

    public function setTLDs($tlds = array())
    {
        if (!empty($tlds)) {
            $this->__tlds = $tlds;
        }
        return true;
    }

    public function checkComplexRouter($input, $type, $settings = array())
    {
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
    public function checkComplexFile($input)
    {
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
        if (strlen($input) == 32 && preg_match("#[0-9a-f]{32}$#", $input)) {
            $type .= 'md5';
        }
        if (strlen($input) == 40 && preg_match("#[0-9a-f]{40}$#", $input)) {
            $type .= 'sha1';
        }
        if (strlen($input) == 64 && preg_match("#[0-9a-f]{64}$#", $input)) {
            $type .= 'sha256';
        }
        if ($type == '' && !$composite && preg_match("#^.+#", $input)) {
            $type = 'filename';
        }
        if ($type == '') {
            $type = 'other';
        }
        return array('type' => $type, 'value' => $original);
    }

    public function checkComplexCnC($input)
    {
        $toReturn = array();
        // check if it's an IP address
        if (filter_var($input, FILTER_VALIDATE_IP)) {
            return array('type' => 'ip-dst', 'value' => $input);
        }
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

        if (!preg_match("#\n#", $input)) {
            return array('type' => 'url', 'value' => $input);
        }
        return array('type' => 'other', 'value' => $input);
    }

    private function __returnOddElements($array)
    {
        foreach ($array as $k => $v) {
            if ($k % 2 != 1) {
                unset($array[$k]);
            }
        }
        return array_values($array);
    }

    private function __parse_row($row, $delimiter)
    {
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
    public function checkCSV($input, $settings = array())
    {
        $delimiter = !empty($settings['delimiter']) ? $settings['delimiter'] : ",";
        $rows = str_getcsv($input, "\n");
        $data = array();
        foreach ($rows as $k => $row) {
            if (empty($row[0]) || $row[0] === '#') {
                continue;
            }
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

    public function checkFreeText($input, $settings = array())
    {
        $charactersToTrim = array('\'', '"', ',', '(', ')');
        $iocArray = preg_split("/\r\n|\n|\r|\s|\s+|,|\<|\>|;/", $input);
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
                if (empty($ioc)) {
                    continue;
                }
                if (isset($settings['excluderegex']) && !empty($settings['excluderegex'])) {
                    if (preg_match($settings['excluderegex'], $ioc)) {
                        continue;
                    }
                }
                $typeArray = $this->__resolveType($ioc);
                if ($typeArray === false) {
                    continue;
                }
                $temp = $typeArray;
                if (!isset($temp['value'])) {
                    $temp['value'] = $ioc;
                }
                $resultArray[] = $temp;
            }
        }
        return $resultArray;
    }

    private $__hexHashTypes = array(
        32 => array('single' => array('md5', 'imphash', 'x509-fingerprint-md5'), 'composite' => array('filename|md5', 'filename|imphash')),
        40 => array('single' => array('sha1', 'pehash', 'x509-fingerprint-sha1'), 'composite' => array('filename|sha1', 'filename|pehash')),
        56 => array('single' => array('sha224', 'sha512/224'), 'composite' => array('filename|sha224', 'filename|sha512/224')),
        64 => array('single' => array('sha256', 'authentihash', 'sha512/256', 'x509-fingerprint-sha256'), 'composite' => array('filename|sha256', 'filename|authentihash', 'filename|sha512/256')),
        96 => array('single' => array('sha384'), 'composite' => array('filename|sha384')),
        128 => array('single' => array('sha512'), 'composite' => array('filename|sha512'))
    );

    // algorithms to run through in order
    private $__checks = array('Hashes', 'Email', 'IP', 'DomainOrFilename', 'SimpleRegex', 'AS');

    private function __resolveType($raw_input)
    {
        $input = array(
            'raw' => trim($raw_input)
        );
        $input = $this->__refangInput($input);
        $input = $this->__extractPort($input);

        foreach ($this->__checks as $check) {
            $result = $this->{'__checkFor' . $check}($input);
            if ($result) {
                return $result;
            }
        }
        return false;
    }

    private function __checkForEmail($input)
    {
        // quick filter for an @ to see if we should validate a potential e-mail address
        if (strpos($input['refanged'], '@') !== false) {
            if (filter_var($input['refanged'], FILTER_VALIDATE_EMAIL)) {
                return array('types' => array('email-src', 'email-dst', 'target-email', 'whois-registrant-email'), 'to_ids' => true, 'default_type' => 'email-src', 'value' => $input['refanged']);
            }
        }
        return false;
    }

	private function __checkForAS($input)
	{
		if (preg_match('#^as[0-9]+$#i', $input['raw'])) {
			$input['raw'] = strtoupper($input['raw']);
			return array('types' => array('AS'), 'to_ids' => false, 'default_type' => 'AS', 'value' => $input['raw']);
		}
	}

    private function __checkForHashes($input)
    {
        // handle prepared composite values with the filename|hash format
        if (strpos($input['raw'], '|')) {
            $compositeParts = explode('|', $input['raw']);
            if (count($compositeParts) == 2) {
                if ($this->__resolveFilename($compositeParts[0])) {
                    foreach ($this->__hexHashTypes as $k => $v) {
                        if (strlen($compositeParts[1]) == $k && preg_match("#[0-9a-f]{" . $k . "}$#i", $compositeParts[1])) {
                            return array('types' => $v['composite'], 'to_ids' => true, 'default_type' => $v['composite'][0], 'value' => $input['raw']);
                        }
                    }
                    if (preg_match('#^[0-9]+:[0-9a-zA-Z\/\+]+:[0-9a-zA-Z\/\+]+$#', $compositeParts[1]) && !preg_match('#^[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}$#', $compositeParts[1])) {
                        return array('types' => array('filename|ssdeep'), 'to_ids' => true, 'default_type' => 'filename|ssdeep', 'value' => $input['raw']);
                    }
                }
            }
        }

        // check for hashes
        foreach ($this->__hexHashTypes as $k => $v) {
            if (strlen($input['raw']) == $k && preg_match("#[0-9a-f]{" . $k . "}$#i", $input['raw'])) {
                return array('types' => $v['single'], 'to_ids' => true, 'default_type' => $v['single'][0], 'value' => $input['raw']);
            }
        }
        // ssdeep has a different pattern
        if (preg_match('#^[0-9]+:[0-9a-zA-Z\/\+]+:[0-9a-zA-Z\/\+]+$#', $input['raw']) && !preg_match('#^[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}$#', $input['raw'])) {
            return array('types' => array('ssdeep'), 'to_ids' => true, 'default_type' => 'ssdeep', 'value' => $input['raw']);
        }
        return false;
    }

    private function __extractPort($input)
    {
        // note down and remove the port if it's a url / domain name / hostname / ip
        // input2 from here on is the variable containing the original input with the port removed. It is only used by url / domain name / hostname / ip
        $input['comment'] = false;
        if (preg_match('/(:[0-9]{2,5})$/', $input['refanged'], $input['port'])) {
            $input['comment'] = 'On port ' . substr($input['port'][0], 1);
            $input['refanged_no_port'] = str_replace($input['port'][0], '', $input['refanged']);
            $input['port'] = substr($input['port'][0], 1);
        } else {
            unset($input['port']);
            $input['refanged_no_port'] = $input['refanged'];
        }
        return $input;
    }

    private function __refangInput($input)
    {
        $input['refanged'] = $input['raw'];
        foreach ($this->__refangRegexTable as $regex => $replacement) {
            $input['refanged'] = preg_replace($regex, $replacement, $input['refanged']);
        }
        $input['refanged'] = rtrim($input['refanged'], ".");
		$input['refanged'] = preg_replace_callback(
			'/\[.\]/',
			function ($matches) {
				return trim($matches[0], '[]');
        	},
        	$input['refanged']
		);
        return $input;
    }

    private function __checkForSimpleRegex($input)
    {
        // CVE numbers
        if (preg_match("#^cve-[0-9]{4}-[0-9]{4,9}$#i", $input['raw'])) {
            return array('types' => array('vulnerability'), 'categories' => array('External analysis'), 'to_ids' => false, 'default_type' => 'vulnerability', 'value' => $input['raw']);
        }
	        // Phone numbers - for automatic recognition, needs to start with + or include dashes
		if (!empty($input['raw'])) {
	        if ($input['raw'][0] === '+' || strpos($input['raw'], '-')) {
	            if (preg_match("#^(\+)?([0-9]{1,3}(\(0\))?)?[0-9\/\-]{5,}[0-9]$#i", $input['raw'])) {
	                return array('types' => array('phone-number', 'prtn', 'whois-registrant-phone'), 'categories' => array('Other'), 'to_ids' => false, 'default_type' => 'phone-number', 'value' => $input['raw']);
	            }
	        }
		}
    }

    private function __checkForIP($input)
    {
        if (filter_var($input['refanged_no_port'], FILTER_VALIDATE_IP)) {
            if (isset($input['port'])) {
                return array('types' => array('ip-dst|port', 'ip-src|port', 'ip-src|port/ip-dst|port'), 'to_ids' => true, 'default_type' => 'ip-dst|port', 'comment' => $input['comment'], 'value' => $input['refanged_no_port'] . '|' . $input['port']);
            } else {
                return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'to_ids' => true, 'default_type' => 'ip-dst', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
            }
        }
        // it could still be a CIDR block
        if (strpos($input['refanged_no_port'], '/')) {
            $temp = explode('/', $input['refanged_no_port']);
            if (count($temp) == 2) {
                if (filter_var($temp[0], FILTER_VALIDATE_IP) && is_numeric($temp[1])) {
                    return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'to_ids' => true, 'default_type' => 'ip-dst', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                }
            }
        }
    }

    private function __checkForDomainOrFilename($input)
    {
        if (strpos($input['refanged'], '.') !== false) {
            $temp = explode('.', $input['refanged']);
            // TODO: use a more flexible matching approach, like the one below (that still doesn't support non-ASCII domains)
            //if (filter_var($input, FILTER_VALIDATE_URL)) {
            $domainDetection = true;
            if (preg_match('/^([-\pL\pN]+\.)+[a-z]+(:[0-9]{2,5})?$/iu', $input['refanged'])) {
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
                    return array('types' => array('hostname', 'domain', 'url', 'filename'), 'to_ids' => true, 'default_type' => 'hostname', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                } else {
                    return array('types' => array('domain', 'filename'), 'to_ids' => true, 'default_type' => 'domain', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                }
            } else {
                // check if it is a URL
                // Adding http:// infront of the input in case it was left off. github.com/MISP/MISP should still be counted as a valid link
                if (count($temp) > 1 && (filter_var($input['refanged_no_port'], FILTER_VALIDATE_URL) || filter_var('http://' . $input['refanged_no_port'], FILTER_VALIDATE_URL))) {
                    // Even though some domains are valid, we want to exclude them as they are known security vendors / etc
                    // TODO, replace that with the appropriate warninglist.
                    if (preg_match('/^https:\/\/(www.)?virustotal.com\//i', $input['refanged_no_port'])) {
                        return array('types' => array('link'), 'to_ids' => false, 'default_type' => 'link', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                    }
                    if (preg_match('/^https:\/\/www\.hybrid-analysis\.com\//i', $input['refanged_no_port'])) {
                        return array('types' => array('link'), 'categories' => array('External analysis'), 'to_ids' => false, 'default_type' => 'link', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                    }
                    if (strpos($input['refanged_no_port'], '/')) {
                        return array('types' => array('url'), 'to_ids' => true, 'default_type' => 'url', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                    }
                }
                if ($this->__resolveFilename($input['raw'])) {
                    return array('types' => array('filename'), 'to_ids' => true, 'default_type' => 'filename', 'value' => $input['raw']);
                }
            }
        }
        if (strpos($input['raw'], '\\') !== false) {
            $temp = explode('\\', $input['raw']);
            if (strpos($temp[count($temp)-1], '.') || preg_match('/^.:/i', $temp[0])) {
                if ($this->__resolveFilename($temp[count($temp)-1])) {
                    return array('types' => array('filename'), 'categories' => array('Payload installation'), 'to_ids' => true, 'default_type' => 'filename', 'value' => $input['raw']);
                }
            } else {
                return array('types' => array('regkey'), 'to_ids' => false, 'default_type' => 'regkey', 'value' => $input['raw']);
            }
        }
        return false;
    }

    private function __resolveFilename($param)
    {
        if ((preg_match('/^.:/', $param) || strpos($param, '.') !=0)) {
            $parts = explode('.', $param);
            if (!is_numeric($parts[count($parts)-1]) && ctype_alnum($parts[count($parts)-1])) {
                return true;
            }
        }
        return false;
    }

    private function __generateTLDList()
    {
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
