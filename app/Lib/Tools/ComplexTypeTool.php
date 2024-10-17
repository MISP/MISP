<?php
require_once __DIR__ . '/TmpFileTool.php';

class ComplexTypeTool
{
    const REFANG_REGEX_TABLE = array(
        array(
            'from' => '/^(hxxp|hxtp|htxp|meow|h\[tt\]p)/i',
            'to' => 'http',
            'types' => array('link', 'url')
        ),
        array(
            'from' => '/(\[\.\]|\[dot\]|\(dot\))/',
            'to' => '.',
            'types' => array('link', 'url', 'ip-dst', 'ip-src', 'domain|ip', 'domain', 'hostname', 'email', 'email-src', 'email-dst')
        ),
        array(
            'from' => '/\[hxxp:\/\/\]/',
            'to' => 'http://',
            'types' => array('link', 'url')
        ),
        array(
            'from' => '/\[\@\]|\[at\]/',
            'to' => '@',
            'types' => array('email', 'email-src', 'email-dst')
        ),
        array(
            'from' => '/\[:\]/',
            'to' => ':',
            'types' => array('url', 'link')
        )
    );

    const HEX_HASH_TYPES = [
        32 => ['single' => ['md5', 'imphash', 'x509-fingerprint-md5', 'ja3-fingerprint-md5'], 'composite' => ['filename|md5', 'filename|imphash']],
        40 => ['single' => ['sha1', 'pehash', 'x509-fingerprint-sha1', 'cdhash'], 'composite' => ['filename|sha1', 'filename|pehash']],
        56 => ['single' => ['sha224', 'sha512/224'], 'composite' => ['filename|sha224', 'filename|sha512/224']],
        64 => ['single' => ['sha256', 'authentihash', 'sha512/256', 'x509-fingerprint-sha256'], 'composite' => ['filename|sha256', 'filename|authentihash', 'filename|sha512/256']],
        96 => ['single' => ['sha384'], 'composite' => ['filename|sha384']],
        128 => ['single' => ['sha512'], 'composite' => ['filename|sha512']],
    ];

    private $__tlds;

    /**
     * Hardcoded list if properly warninglist is not available
     * @var string[]
     */
    private $securityVendorDomains = ['virustotal.com', 'hybrid-analysis.com'];

    public static function refangValue($value, $type)
    {
        foreach (self::REFANG_REGEX_TABLE as $regex) {
            if (in_array($type, $regex['types'], true)) {
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

    public function setSecurityVendorDomains(array $securityVendorDomains)
    {
        if (empty($securityVendorDomains)) {
            return; // if provided warninglist is empty, keep hardcoded domains
        }
        $this->securityVendorDomains = $securityVendorDomains;
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
        foreach ($tmpFile->intoParsedCsv($delimiter) as $row) {
            if (!empty($row[0][0]) && $row[0][0] === '#') { // Comment
                continue;
            }
            foreach ($row as $elementPos => $element) {
                if (empty($element)) {
                    continue;
                }
                if (empty($values) || in_array(($elementPos + 1), $values)) {
                    $element = trim($element, " \t\n\r\0\x0B\"\'");
                    if (empty($element)) {
                        continue;
                    }
                    if (!empty($settings['excluderegex']) && preg_match($settings['excluderegex'], $element)) {
                        continue;
                    }
                    $resolvedResult = $this->__resolveType($element);
                    // Do not extract datetime from CSV
                    if ($resolvedResult) {
                        $iocArray[] = $resolvedResult;
                    }
                }
            }
        }

        return $iocArray;
    }

    /**
     * @param string $input
     * @param array $settings
     * @return array
     */
    public function checkFreeText($input, array $settings = [])
    {
        if (empty($input)) {
            return [];
        }

        if ($input[0] === '{') {
            // If input looks like JSON, try to parse it as JSON
            try {
                return $this->parseJson($input, $settings);
            } catch (Exception $e) {}
        }

        $iocArray = $this->parseFreetext($input);

        $resultArray = [];
        foreach ($iocArray as $ioc) {
            $ioc = trim($ioc, '\'".,() ' . "\t\n\r\0\x0B"); // custom + default PHP trim
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
            $typeArray['original_value'] = $ioc;
            $resultArray[$typeArray['value']] = $typeArray;
        }
        return array_values($resultArray);
    }

    /**
     * @param string $input
     * @throws JsonException
     */
    private function parseJson($input, array $settings)
    {
        $parsed = JsonTool::decode($input);

        $values = [];
        array_walk_recursive($parsed, function ($value) use (&$values) {
            if (is_bool($value) || is_int($value) || empty($value)) {
                return; // skip boolean, integer or empty values
            }

            $values[] = $value;
            foreach ($this->parseFreetext($value) as $v) {
                if ($v !== $value) {
                    $values[] = $v;
                }
            }
        });
        unset($parsed);

        $resultArray = [];
        foreach ($values as $ioc) {
            $ioc = trim($ioc, '\'".,() ' . "\t\n\r\0\x0B"); // custom + default PHP trim
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
            $typeArray['original_value'] = $ioc;
            $resultArray[$typeArray['value']] = $typeArray;
        }
        return array_values($resultArray);
    }

    /**
     * @param string $input
     * @return array|string[]
     */
    private function parseFreetext($input)
    {
        // convert non breaking space to normal space and all unicode chars from "other" category
        $input = preg_replace("/\p{C}+|\xc2\xa0/u", ' ', $input);
        $iocArray = preg_split("/\r\n|\n|\r|\s|\s+|,|<|>|;/", $input);

        preg_match_all('/\"([^\"]+)\"/', $input, $matches);
        array_push($iocArray, ...$matches[1]);

        return $iocArray;
    }

    /**
     * @param string $raw_input Trimmed value
     * @return array|false
     */
    private function __resolveType($raw_input)
    {
        // Check if value is clean IP without doing expensive operations.
        if (filter_var($raw_input, FILTER_VALIDATE_IP)) {
            return [
                'types' => ['ip-dst', 'ip-src', 'ip-src/ip-dst'],
                'default_type' => 'ip-dst',
                'value' => $raw_input,
            ];
        }

        $input = ['raw' => $raw_input];

        // Check hashes before refang and port extracting, it is not necessary for hashes. This speedups parsing
        // freetexts or CSVs with a lot of hashes.
        if ($result = $this->__checkForHashes($input)) {
            return $result;
        }

        $input = $this->__refangInput($input);

        // Check email before port extracting, it is not necessary for email. This speedups parsing
        // freetexts or CSVs with a lot of emails.
        if ($result = $this->__checkForEmail($input)) {
            return $result;
        }

        $input = $this->__extractPort($input);
        if ($result = $this->__checkForIP($input)) {
            return $result;
        }
        if ($result = $this->__checkForDomainOrFilename($input)) {
            return $result;
        }
        if ($result = $this->__checkForSimpleRegex($input)) {
            return $result;
        }
        if ($result = $this->__checkForAS($input)) {
            return $result;
        }
        if ($result = $this->__checkForBTC($input)) {
            return $result;
        }
        return false;
    }

    private function __checkForBTC($input)
    {
        if (preg_match("#^([13][a-km-zA-HJ-NP-Z1-9]{25,34})|(bc|tb)1([023456789acdefghjklmnpqrstuvwxyz]{11,71})$#i", $input['raw'])) {
            return [
                'types' => ['btc'],
                'default_type' => 'btc',
                'value' => $input['raw'],
            ];
        }
        return false;
    }

    private function __checkForEmail($input)
    {
        // quick filter for an @ to see if we should validate a potential e-mail address
        if (str_contains($input['refanged'], '@')) {
            if (filter_var($input['refanged'], FILTER_VALIDATE_EMAIL)) {
                return [
                    'types' => array('email', 'email-src', 'email-dst', 'target-email', 'whois-registrant-email'),
                    'default_type' => 'email-src',
                    'value' => $input['refanged'],
                ];
            }
        }
        return false;
    }

    private function __checkForAS($input)
    {
        if (preg_match('#^as[0-9]+$#i', $input['raw'])) {
            $input['raw'] = strtoupper($input['raw']);
            return array('types' => array('AS'), 'default_type' => 'AS', 'value' => $input['raw']);
        }
        return false;
    }

    private function __checkForHashes($input)
    {
        // handle prepared composite values with the filename|hash format
        if (str_contains($input['raw'], '|')) {
            $compositeParts = explode('|', $input['raw']);
            if (count($compositeParts) === 2) {
                if ($this->__resolveFilename($compositeParts[0])) {
                    $hash = $this->__resolveHash($compositeParts[1]);
                    if ($hash) {
                        return array('types' => $hash['composite'], 'default_type' => $hash['composite'][0], 'value' => $input['raw']);
                    }
                    if ($this->__resolveSsdeep($compositeParts[1])) {
                        return array('types' => array('filename|ssdeep'), 'default_type' => 'filename|ssdeep', 'value' => $input['raw']);
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
            return array('types' => $types, 'default_type' => $types[0], 'value' => $input['raw']);
        }
        // ssdeep has a different pattern
        if ($this->__resolveSsdeep($input['raw'])) {
            return array('types' => array('ssdeep'), 'default_type' => 'ssdeep', 'value' => $input['raw']);
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
        $refanged = $input['raw'];
        foreach (self::REFANG_REGEX_TABLE as $regex) {
            $refanged = preg_replace($regex['from'], $regex['to'], $refanged);
        }
        $refanged = rtrim($refanged, ".");
        $input['refanged'] = preg_replace_callback(
            '/\[.\]/',
            function ($matches) {
                return trim($matches[0], '[]');
            },
            $refanged
        );
        return $input;
    }

    private function __checkForSimpleRegex($input)
    {
        // CVE numbers
        if (preg_match("#^cve-[0-9]{4}-[0-9]{4,9}$#i", $input['raw'])) {
            return [
                'types' => ['vulnerability'],
                'default_type' => 'vulnerability',
                'value' => strtoupper($input['raw']), // 'CVE' must be uppercase
            ];
        }

        // Phone numbers - for automatic recognition, needs to start with + or include dashes
        if ($input['raw'][0] === '+' || strpos($input['raw'], '-')) {
            if (!preg_match('#^[0-9]{4}-[0-9]{2}-[0-9]{2}$#i', $input['raw']) && preg_match("#^(\+)?([0-9]{1,3}(\(0\))?)?[0-9\/\-]{5,}[0-9]$#i", $input['raw'])) {
                return array('types' => array('phone-number', 'prtn', 'whois-registrant-phone'), 'default_type' => 'phone-number', 'value' => $input['raw']);
            }
        }
        return false;
    }

    private function __checkForIP(array $input)
    {
        if (filter_var($input['refanged_no_port'], FILTER_VALIDATE_IP)) {
            if (isset($input['port'])) {
                return array('types' => array('ip-dst|port', 'ip-src|port', 'ip-src|port/ip-dst|port'), 'default_type' => 'ip-dst|port', 'comment' => $input['comment'], 'value' => $input['refanged_no_port'] . '|' . $input['port']);
            } else {
                return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'default_type' => 'ip-dst', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
            }
        }
        // IPv6 address that is considered as IP address with port
        if (filter_var($input['refanged'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return [
                'types' => ['ip-dst', 'ip-src', 'ip-src/ip-dst'],
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
                'default_type' => 'ip-dst|port',
                'comment' => $input['comment'],
                'value' => "$value|{$input['port']}",
            ];
        }
        // it could still be a CIDR block
        if (str_contains($input['refanged_no_port'], '/')) {
            $temp = explode('/', $input['refanged_no_port']);
            if (count($temp) === 2 && filter_var($temp[0], FILTER_VALIDATE_IP) && is_numeric($temp[1])) {
                return array('types' => array('ip-dst', 'ip-src', 'ip-src/ip-dst'), 'default_type' => 'ip-dst', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
            }
        }
        return false;
    }

    private function __checkForDomainOrFilename(array $input)
    {
        if (str_contains($input['refanged_no_port'], '.')) {
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
                    return array('types' => array('hostname', 'domain', 'url', 'filename'), 'default_type' => 'hostname', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                } else {
                    return array('types' => array('domain', 'filename'), 'default_type' => 'domain', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                }
            } else {
                // check if it is a URL
                // Adding http:// infront of the input in case it was left off. github.com/MISP/MISP should still be counted as a valid link
                if (count($temp) > 1 && (filter_var($input['refanged_no_port'], FILTER_VALIDATE_URL) || filter_var('http://' . $input['refanged_no_port'], FILTER_VALIDATE_URL))) {
                    // Even though some domains are valid, we want to exclude them as they are known security vendors / etc
                    if ($this->isLink($input['refanged_no_port'])) {
                        return array('types' => array('link'), 'default_type' => 'link', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                    }
                    if (str_contains($input['refanged_no_port'], '/')) {
                        return array('types' => array('url'), 'default_type' => 'url', 'comment' => $input['comment'], 'value' => $input['refanged_no_port']);
                    }
                }
                if ($this->__resolveFilename($input['raw'])) {
                    return array('types' => array('filename'), 'default_type' => 'filename', 'value' => $input['raw']);
                }
            }
        }
        if (str_contains($input['raw'], '\\')) {
            $temp = explode('\\', $input['raw']);
            if (str_contains(end($temp), '.') || preg_match('/^.:/i', $temp[0])) {
                if ($this->__resolveFilename(end($temp))) {
                    return array('types' => array('filename'), 'default_type' => 'filename', 'value' => $input['raw']);
                }
            } else if (!empty($temp[0])) {
                return array('types' => array('regkey'), 'default_type' => 'regkey', 'value' => $input['raw']);
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
        return preg_match('#^[0-9]+:[0-9a-zA-Z/+]+:[0-9a-zA-Z/+]+$#', $value) && !preg_match('#^[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}$#', $value);
    }

    /**
     * @param string $value
     * @return bool|string[][]
     */
    private function __resolveHash($value)
    {
        $strlen = strlen($value);
        if (isset(self::HEX_HASH_TYPES[$strlen]) && ctype_xdigit($value)) {
            return self::HEX_HASH_TYPES[$strlen];
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

    /**
     * Check if URL should be considered as link attribute type
     * @param string $value
     * @return bool
     */
    private function isLink($value)
    {
        if (!preg_match('/^https:\/\/([^\/]*)/i', $value, $matches)) {
            return false;
        }

        $domainToCheck = '';
        $domainParts = array_reverse(explode('.', strtolower($matches[1])));
        foreach ($domainParts as $domainPart) {
            $domainToCheck = $domainPart . $domainToCheck;
            if (in_array($domainToCheck, $this->securityVendorDomains, true)) {
                return true;
            }
            $domainToCheck = '.' . $domainToCheck;
        }
        return false;
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
