<?php
require_once __DIR__ . '/TmpFileTool.php';

class ComplexTypeTool
{
    private static $__refangRegexTable = array(
        array(
            'from' => '/^(hxxp|hxtp|htxp|meow|h\[tt\]p)/i',
            'to' => 'http',
            'types' => array('link', 'url')
        ),
        array(
            'from' => '/(\[\.\]|\[dot\]|\(dot\)|\\\\\.)/',
            'to' => '.',
            'types' => array('link', 'url', 'ip-dst', 'ip-src', 'domain|ip', 'domain', 'hostname')
        ),
        array(
            'from' => '/\.+/',
            'to' => '.',
            'types' => array('ip-dst', 'ip-src', 'domain|ip', 'domain', 'hostname')
        ),
        array(
            'from' => '/\[hxxp:\/\/\]/',
            'to' => 'http://',
            'types' => array('link', 'url')
        ),
        array(
            'from' => '/[\@]|\[at\]/',
            'to' => '@',
            'types' => array('email', 'email-src', 'email-dst')
        ),
        array(
            'from' => '/\[:\]/',
            'to' => ':',
            'types' => array('url', 'link')
        )
    );

    private $__tlds = null;

    public static function refangValue($value, $type)
    {
        foreach (self::$__refangRegexTable as $regex) {
            if (in_array($type, $regex['types'])) {
                $value = preg_replace($regex['from'], $regex['to'], $value);
            }
        }
        return $value;
    }

    public function setTLDs($tlds = array())
    {
        $this->__tlds = [];
        foreach ($tlds as $tld) {
            $this->__tlds[$tld] = true;
        }
    }

    public function checkComplexRouter($input, $type, $settings = array())
    {
        switch ($type) {
            case 'File':
                return $this->checkComplexFile($input);
            case 'CnC':
                return $this->checkComplexCnC($input);
            case 'freetext':
            case 'FreeText':
                return $this->checkFreeText($input, $settings);
            case 'csv':
                return $this->checkCSV($input, $settings);
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

    /**
     * Parse a CSV file with the given settings
     * All lines starting with # are stripped
     * The settings can contain the following:
     *     delimiter: Expects a delimiter string (default is a simple comma).
     *                For example, to split the following line: "value1##comma##value2" simply pass $settings['delimiter'] = "##comma##";
     *     values:    Expects an array (or a comma separated string) with numeric values denoting the columns containing indicators. If this is not set then every value will be checked. (column numbers start at 1)
     * @param string $input
     * @param array $settings
     * @return array
     * @throws Exception
     */
    public function checkCSV($input, $settings = array())
    {
        if (empty($input)) {
            return [];
        }

        $delimiter = !empty($settings['delimiter']) ? $settings['delimiter'] : ",";
        if ($delimiter === '\t') {
            $delimiter = "\t";
        }
        $values = !empty($settings['value']) ? $settings['value'] : array();
        if (!is_array($values)) {
            $values = explode(',', $values);
        }
        foreach ($values as $key => $value) {
            $values[$key] = intval($value);
        }

        // Write to tmp file to save memory
        $tmpFile = new TmpFileTool();
        $tmpFile->write($input);
        unset($input);

        $iocArray = [];
        foreach ($tmpFile->csv($delimiter) as $row) {
            if (!empty($row[0][0]) && $row[0][0] === '#') { // Comment
                continue;
            }
            foreach ($row as $elementPos => $element) {
                if (empty($values) || in_array(($elementPos + 1), $values)) {
                    $element = trim($element, " \t\n\r\0\x0B\"\'");
                    if (empty($element)) {
                        continue;
                    }
                    if (!empty($settings['excluderegex']) && preg_match($settings['excluderegex'], $element)) {
                        continue;
                    }
                    $resolvedResult = $this->__resolveType($element);
                    if ($resolvedResult) {
                        $iocArray[] = $resolvedResult;
                    }
                }
            }
        }

        return $iocArray;
    }

    public function checkFreeText($input, $settings = array())
    {
        $charactersToTrim = '\'",() ' . "\t\n\r\0\x0B"; // custom + default PHP trim
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
        foreach ($iocArray as $ioc) {
            $ioc = str_replace("\xc2\xa0", '', $ioc); // remove non breaking space
            $ioc = trim($ioc, $charactersToTrim);
            $ioc = preg_replace('/\p{C}+/u', '', $ioc);
            if (empty($ioc)) {
                continue;
            }
            if (!empty($settings['excluderegex']) && preg_match($settings['excluderegex'], $ioc)) {
                continue;
            }
            $typeArray = $this->__resolveType($ioc);
            if ($typeArray === false) {
                continue;
            }
            // Remove duplicates
            if (isset($resultArray[$typeArray['value']])) {
                continue;
            }
            $resultArray[$typeArray['value']] = $typeArray;
        }
        return array_values($resultArray);
    }

    private $__hexHashTypes = array(
        32 => array('single' => array('md5', 'imphash', 'x509-fingerprint-md5'), 'composite' => array('filename|md5', 'filename|imphash')),
        40 => array('single' => array('sha1', 'pehash', 'x509-fingerprint-sha1', 'cdhash'), 'composite' => array('filename|sha1', 'filename|pehash')),
        56 => array('single' => array('sha224', 'sha512/224'), 'composite' => array('filename|sha224', 'filename|sha512/224')),
        64 => array('single' => array('sha256', 'authentihash', 'sha512/256', 'x509-fingerprint-sha256'), 'composite' => array('filename|sha256', 'filename|authentihash', 'filename|sha512/256')),
        96 => array('single' => array('sha384'), 'composite' => array('filename|sha384')),
        128 => array('single' => array('sha512'), 'composite' => array('filename|sha512'))
    );

    // algorithms to run through in order, without Hashes that are checked separately
    private $__checks = array('Email', 'IP', 'DomainOrFilename', 'SimpleRegex', 'AS', 'BTC');

    /**
     * @param string $raw_input Trimmed value
     * @return array|false
     */
    private function __resolveType($raw_input)
    {
        $input = array('raw' => $raw_input);

        // Check hashes before refang and port extracting, it is not necessary for hashes. This speedups parsing
        // freetexts or CSVs with a lot of hashes.
        $hashes = $this->__checkForHashes($input);
        if ($hashes) {
            return $hashes;
        }

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

    private function __checkForBTC($input)
    {
        if (preg_match("#^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$#i", $input['raw'])) {
            return array('types' => array('btc'), 'categories' => array('Financial fraud'), 'to_ids' => true, 'default_type' => 'btc', 'value' => $input['raw']);
        }
        return false;
    }

    private function __checkForEmail($input)
    {
        // quick filter for an @ to see if we should validate a potential e-mail address
        if (strpos($input['refanged'], '@') !== false) {
            if (filter_var($input['refanged'], FILTER_VALIDATE_EMAIL)) {
                return array('types' => array('email', 'email-src', 'email-dst', 'target-email', 'whois-registrant-email'), 'to_ids' => true, 'default_type' => 'email-src', 'value' => $input['refanged']);
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
        return false;
    }

    private function __checkForHashes($input)
    {
        // handle prepared composite values with the filename|hash format
        if (strpos($input['raw'], '|')) {
            $compositeParts = explode('|', $input['raw']);
            if (count($compositeParts) == 2) {
                if ($this->__resolveFilename($compositeParts[0])) {
                    $hash = $this->__resolveHash($compositeParts[1]);
                    if ($hash) {
                        return array('types' => $hash['composite'], 'to_ids' => true, 'default_type' => $hash['composite'][0], 'value' => $input['raw']);
                    }
                    if ($this->__resolveSsdeep($compositeParts[1])) {
                        return array('types' => array('filename|ssdeep'), 'to_ids' => true, 'default_type' => 'filename|ssdeep', 'value' => $input['raw']);
                    }
                }
            }
        }

        // check for hashes
        $hash = $this->__resolveHash($input['raw']);
        if ($hash) {
            $types = $hash['single'];
            if ($this->__checkForBTC($input)) {
                $types[] = 'btc';
            }
            return array('types' => $types, 'to_ids' => true, 'default_type' => $types[0], 'value' => $input['raw']);
        }
        // ssdeep has a different pattern
        if ($this->__resolveSsdeep($input['raw'])) {
            return array('types' => array('ssdeep'), 'to_ids' => true, 'default_type' => 'ssdeep', 'value' => $input['raw']);
        }
        return false;
    }

    private function __extractPort($input)
    {
        // note down and remove the port if it's a url / domain name / hostname / ip
        // input2 from here on is the variable containing the original input with the port removed. It is only used by url / domain name / hostname / ip
        if (preg_match('/(:[0-9]{2,5})$/', $input['refanged'], $port)) {
            $input['comment'] = 'On port ' . substr($port[0], 1);
            $input['refanged_no_port'] = str_replace($port[0], '', $input['refanged']);
            $input['port'] = substr($port[0], 1);
        } else {
            $input['comment'] = false;
            $input['refanged_no_port'] = $input['refanged'];
        }
        return $input;
    }

    private function __refangInput($input)
    {
        $input['refanged'] = $input['raw'];
        foreach (self::$__refangRegexTable as $regex) {
            $input['refanged'] = preg_replace($regex['from'], $regex['to'], $input['refanged']);
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
            return [
                'types' => ['vulnerability'],
                'categories' => ['External analysis'],
                'to_ids' => false,
                'default_type' => 'vulnerability',
                'value' => strtoupper($input['raw']), // 'CVE' must be uppercase
            ];
        }
        // Phone numbers - for automatic recognition, needs to start with + or include dashes
        if ($input['raw'][0] === '+' || strpos($input['raw'], '-')) {
            if (!preg_match('#^[0-9]{4}-[0-9]{2}-[0-9]{2}$#i', $input['raw']) && preg_match("#^(\+)?([0-9]{1,3}(\(0\))?)?[0-9\/\-]{5,}[0-9]$#i", $input['raw'])) {
                return array('types' => array('phone-number', 'prtn', 'whois-registrant-phone'), 'categories' => array('Other'), 'to_ids' => false, 'default_type' => 'phone-number', 'value' => $input['raw']);
            }
        }
        return false;
    }

    private function __checkForIP(array $input)
    {
        if (filter_var($input['refanged_no_port'], FILTER_VALIDATE_IP)) {
            if (isset($input['port'])) {
                return array('types' => array('ip-dst|port', 'ip-src|port', 'ip-src|port/ip-dst|port'), 'to_ids' => true, 'default_type' => 'ip-dst|port', 'comment' => $input['comment'], 'value' => $input['refanged_no_port'] . '|' . $input['port']);
            } else {
                return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'to_ids' => true, 'default_type' => 'ip-dst', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
            }
        }
        // IPv6 address that is considered as IP address with port
        if (filter_var($input['refanged'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return [
                'types' => ['ip-dst', 'ip-src', 'ip-src/ip-dst'],
                'to_ids' => true,
                'default_type' => 'ip-dst',
                'comment' => '',
                'value' => $input['refanged'],
            ];
        }
        // IPv6 with port in `[1fff:0:a88:85a3::ac1f]:8001` format
        if (isset($input['port']) &&
            !empty($input['refanged_no_port']) &&
            $input['refanged_no_port'][0] === '[' &&
            filter_var(substr($input['refanged_no_port'], 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ) {
            $value = substr($input['refanged_no_port'], 1, -1); // remove brackets
            return [
                'types' => ['ip-dst|port', 'ip-src|port', 'ip-src|port/ip-dst|port'],
                'to_ids' => true,
                'default_type' => 'ip-dst|port',
                'comment' => $input['comment'],
                'value' => "$value|{$input['port']}",
            ];
        }
        // it could still be a CIDR block
        if (strpos($input['refanged_no_port'], '/')) {
            $temp = explode('/', $input['refanged_no_port']);
            if (count($temp) === 2 && filter_var($temp[0], FILTER_VALIDATE_IP) && is_numeric($temp[1])) {
                return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'to_ids' => true, 'default_type' => 'ip-dst', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
            }
        }
        return false;
    }

    private function __checkForDomainOrFilename(array $input)
    {
        if (strpos($input['refanged_no_port'], '.') !== false) {
            $temp = explode('.', $input['refanged_no_port']);
            $domainDetection = true;
            if (preg_match('/^([-\pL\pN]+\.)+[a-z0-9-]+$/iu', $input['refanged_no_port'])) {
                if (!$this->isTld(end($temp))) {
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
                    if (preg_match('/^(https:\/\/(www.)?virustotal.com\/|https:\/\/www\.hybrid-analysis\.com\/)/i', $input['refanged_no_port'])) {
                        return array('types' => array('link'), 'to_ids' => false, 'default_type' => 'link', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
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
            if (strpos(end($temp), '.') || preg_match('/^.:/i', $temp[0])) {
                if ($this->__resolveFilename(end($temp))) {
                    return array('types' => array('filename'), 'categories' => array('Payload installation'), 'to_ids' => true, 'default_type' => 'filename', 'value' => $input['raw']);
                }
            } else if (!empty($temp[0])) {
                return array('types' => array('regkey'), 'to_ids' => false, 'default_type' => 'regkey', 'value' => $input['raw']);
            }
        }
        return false;
    }

    private function __resolveFilename($param)
    {
        if ((preg_match('/^.:/', $param) || strpos($param, '.') != 0)) {
            $parts = explode('.', $param);
            if (!is_numeric(end($parts)) && ctype_alnum(end($parts))) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $value
     * @return bool
     */
    private function __resolveSsdeep($value)
    {
        return preg_match('#^[0-9]+:[0-9a-zA-Z\/\+]+:[0-9a-zA-Z\/\+]+$#', $value) && !preg_match('#^[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}$#', $value);
    }

    /**
     * @param string $value
     * @return bool|string[][]
     */
    private function __resolveHash($value)
    {
        $strlen = strlen($value);
        if (isset($this->__hexHashTypes[$strlen]) && ctype_xdigit($value)) {
            return $this->__hexHashTypes[$strlen];
        }
        return false;
    }

    /**
     * @param string $tld
     * @return bool
     */
    private function isTld($tld)
    {
        if ($this->__tlds === null) {
            $this->setTLDs($this->__generateTLDList());
        }
        return isset($this->__tlds[strtolower($tld)]);
    }

    private function __generateTLDList()
    {
        $tlds = array('biz', 'cat', 'com', 'edu', 'gov', 'int', 'mil', 'net', 'org', 'pro', 'tel', 'aero', 'arpa', 'asia', 'coop', 'info', 'jobs', 'mobi', 'name', 'museum', 'travel', 'onion');
        $char1 = $char2 = 'a';
        for ($i = 0; $i < 26; $i++) {
            for ($j = 0; $j < 26; $j++) {
                $tlds[] = $char1 . $char2;
                $char2++;
            }
            $char1++;
            $char2 = 'a';
        }
        return $tlds;
    }
}
