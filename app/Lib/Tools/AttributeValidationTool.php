<?php
class AttributeValidationTool
{
    // private
    const HASH_HEX_LENGTH = [
        'authentihash' => 64,
        'md5' => 32,
        'imphash' => 32,
        'telfhash' => 70,
        'sha1' => 40,
        'git-commit-id' => 40,
        'x509-fingerprint-md5' => 32,
        'x509-fingerprint-sha1' => 40,
        'x509-fingerprint-sha256' => 64,
        'ja3-fingerprint-md5' => 32,
        'jarm-fingerprint' => 62,
        'hassh-md5' => 32,
        'hasshserver-md5' => 32,
        'pehash' => 40,
        'sha224' => 56,
        'sha256' => 64,
        'sha384' => 96,
        'sha512' => 128,
        'sha512/224' => 56,
        'sha512/256' => 64,
        'sha3-224' => 56,
        'sha3-256' => 64,
        'sha3-384' => 96,
        'sha3-512' => 128,
        'dom-hash' => 32,
    ];

    /**
     * Do some last second modifications before the validation
     * @param string $type
     * @param mixed $value
     * @return string
     */
    public static function modifyBeforeValidation($type, $value)
    {
        $value = self::handle4ByteUnicode($value);
        switch ($type) {
            case 'ip-src':
            case 'ip-dst':
                return self::normalizeIp($value);
            case 'md5':
            case 'sha1':
            case 'sha224':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha512/224':
            case 'sha512/256':
            case 'sha3-224':
            case 'sha3-256':
            case 'sha3-384':
            case 'sha3-512':
            case 'ja3-fingerprint-md5':
            case 'jarm-fingerprint':
            case 'hassh-md5':
            case 'hasshserver-md5':
            case 'hostname':
            case 'pehash':
            case 'authentihash':
            case 'vhash':
            case 'imphash':
            case 'telfhash':
            case 'tlsh':
            case 'anonymised':
            case 'cdhash':
            case 'email':
            case 'email-src':
            case 'email-dst':
            case 'target-email':
            case 'whois-registrant-email':
            case 'dom-hash':
            case 'onion-address':
                return strtolower($value);
            case 'domain':
                $value = strtolower($value);
                $value = trim($value, '.');
                // Domain is not valid, try to convert to punycode
                if (!self::isDomainValid($value) && function_exists('idn_to_ascii')) {
                    $punyCode = idn_to_ascii($value);
                    if ($punyCode !== false) {
                        $value = $punyCode;
                    }
                }
                return $value;
            case 'domain|ip':
                $value = strtolower($value);
                $parts = explode('|', $value);
                if (!isset($parts[1])) {
                    return $value; // not a composite
                }
                $parts[0] = trim($parts[0], '.');
                // Domain is not valid, try to convert to punycode
                if (!self::isDomainValid($parts[0]) && function_exists('idn_to_ascii')) {
                    $punyCode = idn_to_ascii($parts[0]);
                    if ($punyCode !== false) {
                        $parts[0] = $punyCode;
                    }
                }
                $parts[1] = self::normalizeIp($parts[1]);
                return "$parts[0]|$parts[1]";
            case 'filename|md5':
            case 'filename|sha1':
            case 'filename|imphash':
            case 'filename|sha224':
            case 'filename|sha256':
            case 'filename|sha384':
            case 'filename|sha512':
            case 'filename|sha512/224':
            case 'filename|sha512/256':
            case 'filename|sha3-224':
            case 'filename|sha3-256':
            case 'filename|sha3-384':
            case 'filename|sha3-512':
            case 'filename|authentihash':
            case 'filename|vhash':
            case 'filename|pehash':
            case 'filename|tlsh':
                // Convert hash to lowercase
                $pos = strpos($value, '|');
                return substr($value, 0, $pos) . strtolower(substr($value, $pos));
            case 'http-method':
            case 'hex':
                return strtoupper($value);
            case 'vulnerability':
            case 'weakness':
                $value = str_replace('–', '-', $value);
                return strtoupper($value);
            case 'cc-number':
            case 'bin':
                return preg_replace('/[^0-9]+/', '', $value);
            case 'iban':
            case 'bic':
                $value = strtoupper($value);
                return preg_replace('/[^0-9A-Z]+/', '', $value);
            case 'prtn':
            case 'whois-registrant-phone':
            case 'phone-number':
                if (substr($value, 0, 2) == '00') {
                    $value = '+' . substr($value, 2);
                }
                $value = preg_replace('/\(0\)/', '', $value);
                return preg_replace('/[^\+0-9]+/', '', $value);
            case 'x509-fingerprint-md5':
            case 'x509-fingerprint-sha256':
            case 'x509-fingerprint-sha1':
                $value = str_replace(':', '', $value);
                return strtolower($value);
            case 'ip-dst|port':
            case 'ip-src|port':
                if (substr_count($value, ':') >= 2) { // (ipv6|port) - tokenize ip and port
                    if (strpos($value, '|')) { // 2001:db8::1|80
                        $parts = explode('|', $value);
                    } elseif (str_starts_with($value, '[') && str_contains($value, ']')) { // [2001:db8::1]:80
                        $ipv6 = substr($value, 1, strpos($value, ']')-1);
                        $port = explode(':', substr($value, strpos($value, ']')))[1];
                        $parts = array($ipv6, $port);
                    } elseif (strpos($value, '.')) { // 2001:db8::1.80
                        $parts = explode('.', $value);
                    } elseif (strpos($value, ' port ')) { // 2001:db8::1 port 80
                        $parts = explode(' port ', $value);
                    } elseif (strpos($value, 'p')) { // 2001:db8::1p80
                        $parts = explode('p', $value);
                    } elseif (strpos($value, '#')) { // 2001:db8::1#80
                        $parts = explode('#', $value);
                    } else { // 2001:db8::1:80 this one is ambiguous
                        $temp = explode(':', $value);
                        $parts = array(implode(':', array_slice($temp, 0, count($temp)-1)), end($temp));
                    }
                } elseif (strpos($value, ':')) { // (ipv4:port)
                    $parts = explode(':', $value);
                } elseif (strpos($value, '|')) { // (ipv4|port)
                    $parts = explode('|', $value);
                } else {
                    return $value;
                }
                return self::normalizeIp($parts[0]) . '|' . $parts[1];
            case 'mac-address':
            case 'mac-eui-64':
                $value = str_replace(array('.', ':', '-', ' '), '', strtolower($value));
                return wordwrap($value, 2, ':', true);
            case 'hostname|port':
                $value = strtolower($value);
                return str_replace(':', '|', $value);
            case 'boolean':
                $value = trim(strtolower($value));
                if ('true' === $value) {
                    $value = 1;
                } else if ('false' === $value) {
                    $value = 0;
                }
                return $value ? '1' : '0';
            case 'datetime':
                try {
                    return (new DateTime($value, new DateTimeZone('GMT')))->format('Y-m-d\TH:i:s.uO'); // ISO8601 formatting with microseconds
                } catch (Exception $e) {
                    return $value; // silently skip. Rejection will be done in validation()
                }
            case 'AS':
                if (strtoupper(substr($value, 0, 2)) === 'AS') {
                    $value = substr($value, 2); // remove 'AS'
                }
                if (str_contains($value, '.')) { // maybe value is in asdot notation
                    $parts = explode('.', $value, 2);
                    if (self::isPositiveInteger($parts[0]) && self::isPositiveInteger($parts[1])) {
                        return $parts[0] * 65536 + $parts[1];
                    }
                }
                return $value;
        }
        return $value;
    }

    /**
     * Validate if value is valid for given attribute type.
     * At this point, we can be sure, that composite type is really composite.
     * @param string $type
     * @param string $value
     * @return bool|string
     */
    public static function validate($type, $value)
    {
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
            case 'sha3-224':
            case 'sha3-256':
            case 'sha3-384':
            case 'sha3-512':
            case 'authentihash':
            case 'ja3-fingerprint-md5':
            case 'jarm-fingerprint':
            case 'hassh-md5':
            case 'hasshserver-md5':
            case 'x509-fingerprint-md5':
            case 'x509-fingerprint-sha256':
            case 'x509-fingerprint-sha1':
            case 'git-commit-id':
            case 'dom-hash':
                if (self::isHashValid($type, $value)) {
                    return true;
                }
                $length = self::HASH_HEX_LENGTH[$type];
                return __('Checksum has an invalid length or format (expected: %s hexadecimal characters). Please double check the value or select type "other".', $length);
            case 'tlsh':
                if (self::isTlshValid($value)) {
                    return true;
                }
                return __('Checksum has an invalid length or format (expected: at least 35 hexadecimal characters, optionally starting with t1 instead of hexadecimal characters). Please double check the value or select type "other".');
            case 'telfhash':
                if (self::isTelfhashValid($value)) {
                    return true;
                }
                return __('Checksum has an invalid length or format (expected: %s or %s hexadecimal characters). Please double check the value or select type "other".', 70, 72);
            case 'pehash':
                if (self::isHashValid('pehash', $value)) {
                    return true;
                }
                return __('The input doesn\'t match the expected sha1 format (expected: 40 hexadecimal characters). Keep in mind that MISP currently only supports SHA1 for PEhashes, if you would like to get the support extended to other hash types, make sure to create a github ticket about it at https://github.com/MISP/MISP!');
            case 'ssdeep':
                if (self::isSsdeep($value)) {
                    return true;
                }
                return __('Invalid SSDeep hash. The format has to be blocksize:hash:hash');
            case 'impfuzzy':
                if (substr_count($value, ':') === 2) {
                    $parts = explode(':', $value);
                    if (self::isPositiveInteger($parts[0])) {
                        return true;
                    }
                }
                return __('Invalid impfuzzy format. The format has to be imports:hash:hash');
            case 'cdhash':
                if (preg_match("#^[0-9a-f]{40,}$#", $value)) {
                    return true;
                }
                return __('The input doesn\'t match the expected format (expected: 40 or more hexadecimal characters)');
            case 'http-method':
                if (preg_match("#(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH)#", $value)) {
                    return true;
                }
                return __('Unknown HTTP method.');
            case 'filename|pehash':
                // no newline
                if (preg_match("#^.+\|[0-9a-f]{40}$#", $value)) {
                    return true;
                }
                return __('The input doesn\'t match the expected filename|sha1 format (expected: filename|40 hexadecimal characters). Keep in mind that MISP currently only supports SHA1 for PEhashes, if you would like to get the support extended to other hash types, make sure to create a github ticket about it at https://github.com/MISP/MISP!');
            case 'filename|md5':
            case 'filename|sha1':
            case 'filename|imphash':
            case 'filename|sha224':
            case 'filename|sha256':
            case 'filename|sha384':
            case 'filename|sha512':
            case 'filename|sha512/224':
            case 'filename|sha512/256':
            case 'filename|sha3-224':
            case 'filename|sha3-256':
            case 'filename|sha3-384':
            case 'filename|sha3-512':
            case 'filename|authentihash':
                $hashType = substr($type, 9); // strip `filename|`
                $length = self::HASH_HEX_LENGTH[$hashType];
                if (preg_match("#^.+\|[0-9a-f]{" . $length . "}$#", $value)) {
                    return true;
                }
                return __('Checksum has an invalid length or format (expected: filename|%s hexadecimal characters). Please double check the value or select type "other".', $length);
            case 'filename|ssdeep':
                $composite = explode('|', $value);
                if (str_contains($composite[0], "\n")) {
                    return __('Filename must not contain new line character.');
                }
                if (self::isSsdeep($composite[1])) {
                    return true;
                }
                return __('Invalid ssdeep hash (expected: blocksize:hash:hash).');
            case 'filename|tlsh':
                $composite = explode('|', $value);
                if (str_contains($composite[0], "\n")) {
                    return __('Filename must not contain new line character.');
                }
                if (self::isTlshValid($composite[1])) {
                    return true;
                }
                return __('TLSH hash has an invalid length or format (expected: filename|at least 35 hexadecimal characters, optionally starting with t1 instead of hexadecimal characters). Please double check the value or select type "other".');
            case 'filename|vhash':
                if (preg_match('#^.+\|.+$#', $value)) {
                    return true;
                }
                return __('Checksum has an invalid length or format (expected: filename|string characters). Please double check the value or select type "other".');
            case 'ip-src':
            case 'ip-dst':
                if (str_contains($value, '/')) {
                    $parts = explode("/", $value);
                    if (count($parts) !== 2 || !self::isPositiveInteger($parts[1])) {
                        return __('Invalid CIDR notation value found.');
                    }

                    if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        if ($parts[1] > 32) {
                            return __('Invalid CIDR notation value found, for IPv4 must be lower or equal 32.');
                        }
                    } else if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        if ($parts[1] > 128) {
                            return __('Invalid CIDR notation value found, for IPv6 must be lower or equal 128.');
                        }
                    } else {
                        return __('IP address has an invalid format.');
                    }
                } else if (!filter_var($value, FILTER_VALIDATE_IP)) {
                    return  __('IP address has an invalid format.');
                }
                return true;
            case 'port':
                if (!self::isPortValid($value)) {
                    return __('Port numbers have to be integers between 1 and 65535.');
                }
                return true;
            case 'ip-dst|port':
            case 'ip-src|port':
                $parts = explode('|', $value);
                if (!filter_var($parts[0], FILTER_VALIDATE_IP)) {
                    return __('IP address has an invalid format.');
                }
                if (!self::isPortValid($parts[1])) {
                    return __('Port numbers have to be integers between 1 and 65535.');
                }
                return true;
            case 'onion-address':
                if (preg_match('#^([a-z2-7]{16}|[a-z2-7]{56)\.onion$#', $value)) {
                    return true;
                }
                return __('Onion address has an invalid format.');
            case 'mac-address':
                return preg_match('/^([a-fA-F0-9]{2}[:]?){6}$/', $value) === 1;
            case 'mac-eui-64':
                return preg_match('/^([a-fA-F0-9]{2}[:]?){8}$/', $value) === 1;
            case 'hostname':
            case 'domain':
                if (self::isDomainValid($value)) {
                    return true;
                }
                return __('%s has an invalid format. Please double check the value or select type "other".', ucfirst($type));
            case 'hostname|port':
                $parts = explode('|', $value);
                if (!self::isDomainValid($parts[0])) {
                    return __('Hostname has an invalid format.');
                }
                if (!self::isPortValid($parts[1])) {
                    return __('Port numbers have to be integers between 1 and 65535.');
                }
                return true;
            case 'domain|ip':
                $parts = explode('|', $value);
                if (!self::isDomainValid($parts[0])) {
                    return __('Domain has an invalid format.');
                }
                if (!filter_var($parts[1], FILTER_VALIDATE_IP)) {
                    return __('IP address has an invalid format.');
                }
                return true;
            case 'email':
            case 'email-src':
            case 'eppn':
            case 'email-dst':
            case 'target-email':
            case 'whois-registrant-email':
            case 'dns-soa-email':
            case 'jabber-id':
                // we don't use the native function to prevent issues with partial email addresses
                if (preg_match("#^.[^\s]*\@.*\..*$#i", $value)) {
                    return true;
                }
                return __('Email address has an invalid format. Please double check the value or select type "other".');
            case 'vulnerability':
                if (preg_match("#^CVE-[0-9]{4}-[0-9]{4,}$#", $value)) {
                    return true;
                }
                return __('Invalid format. Expected: CVE-xxxx-xxxx...');
            case 'weakness':
                if (preg_match("#^CWE-[0-9]+$#", $value)) {
                    return true;
                }
                return __('Invalid format. Expected: CWE-x...');
            case 'windows-service-name':
            case 'windows-service-displayname':
                if (strlen($value) > 256 || preg_match('#[\\\/]#', $value)) {
                    return __('Invalid format. Only values shorter than 256 characters that don\'t include any forward or backward slashes are allowed.');
                }
                return true;
            case 'mutex':
            case 'process-state':
            case 'snort':
            case 'bro':
            case 'zeek':
            case 'community-id':
            case 'anonymised':
            case 'pattern-in-file':
            case 'pattern-in-traffic':
            case 'pattern-in-memory':
            case 'filename-pattern':
            case 'pgp-public-key':
            case 'pgp-private-key':
            case 'yara':
            case 'stix2-pattern':
            case 'sigma':
            case 'gene':
            case 'kusto-query':
            case 'mime-type':
            case 'identity-card-number':
            case 'cookie':
            case 'attachment':
            case 'malware-sample':
            case 'comment':
            case 'text':
            case 'other':
            case 'cpe':
            case 'email-attachment':
            case 'email-body':
            case 'email-header':
            case 'first-name':
            case 'middle-name':
            case 'last-name':
            case 'full-name':
                return true;
            case 'link':
                // Moved to a native function whilst still enforcing the scheme as a requirement
                return (bool)filter_var($value, FILTER_VALIDATE_URL);
            case 'hex':
                return ctype_xdigit($value);
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
            case 'email-reply-to':
            case 'email-x-mailer':
            case 'email-mime-boundary':
            case 'email-thread-index':
            case 'email-message-id':
            case 'github-username':
            case 'github-repository':
            case 'github-organisation':
            case 'twitter-id':
            case 'dkim':
            case 'dkim-signature':
            case 'favicon-mmh3':
            case 'chrome-extension-id':
            case 'mobile-application-id':
            case 'azure-application-id':
            case 'named pipe':
                if (str_contains($value, "\n")) {
                    return __('Value must not contain new line character.');
                }
                return true;
            case 'ssh-fingerprint':
                if (self::isSshFingerprint($value)) {
                    return true;
                }
                return __('SSH fingerprint must be in MD5 or SHA256 format.');
            case 'datetime':
                if (strtotime($value) !== false) {
                    return true;
                }
                return __('Datetime has to be in the ISO 8601 format.');
            case 'size-in-bytes':
            case 'counter':
                if (self::isPositiveInteger($value)) {
                    return true;
                }
                return __('The value has to be a whole number greater or equal 0.');
            /*  case 'targeted-threat-index':
                  if (!is_numeric($value) || $value < 0 || $value > 10) {
                      return __('The value has to be a number between 0 and 10.');
                  }
                return true;*/
            case 'integer':
                if (is_int($value)) {
                    return true;
                }
                return __('The value has to be an integer value.');
            case 'iban':
            case 'bic':
            case 'btc':
            case 'dash':
            case 'xmr':
                return preg_match('/^[a-zA-Z0-9]+$/', $value) === 1;
            case 'vhash':
                return preg_match('/^.+$/', $value) === 1;
            case 'bin':
            case 'cc-number':
            case 'bank-account-nr':
            case 'aba-rtn':
            case 'prtn':
            case 'phone-number':
            case 'whois-registrant-phone':
            case 'float':
                return is_numeric($value);
            case 'cortex':
                return JsonTool::isValid($value);
            case 'boolean':
                return $value == 1 || $value == 0;
            case 'AS':
                if (self::isPositiveInteger($value) && $value <= 4294967295) {
                    return true;
                }
                return __('AS number have to be integer between 1 and 4294967295');
        }
        throw new InvalidArgumentException("Unknown attribute type $type.");
    }

    /**
     * This method will generate all valid types for given value.
     * @param array $types Typos to check
     * @param array $compositeTypes Composite types
     * @param string $value Values to check
     * @return array
     */
    public static function validTypesForValue(array $types, array $compositeTypes, $value)
    {
        $possibleTypes = [];
        foreach ($types as $type) {
            if (in_array($type, $compositeTypes, true) && substr_count($value, '|') !== 1) {
                continue; // value is not in composite format
            }
            $modifiedValue = AttributeValidationTool::modifyBeforeValidation($type, $value);
            if (AttributeValidationTool::validate($type, $modifiedValue) === true) {
                $possibleTypes[] = $type;
            }
        }
        return $possibleTypes;
    }

    /**
     * @param string $value
     * @return bool
     */
    private static function isDomainValid($value)
    {
        return preg_match("#^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}$#i", $value) === 1;
    }

    /**
     * @param string $value
     * @return bool
     */
    private static function isPortValid($value)
    {
        return self::isPositiveInteger($value) && $value >= 1 && $value <= 65535;
    }

    /**
     * @param string $value
     * @return bool
     */
    private static function isTlshValid($value)
    {
        if ($value[0] === 't') {
            $value = substr($value, 1);
        }
        return strlen($value) > 35 && ctype_xdigit($value);
    }

    /**
     * @param string $value
     * @return bool
     */
    private static function isTelfhashValid($value)
    {
        return strlen($value) == 70 || strlen($value) == 72;
    }


    /**
     * @param string $type
     * @param string $value
     * @return bool
     */
    private static function isHashValid($type, $value)
    {
        return strlen($value) === self::HASH_HEX_LENGTH[$type] && ctype_xdigit($value);
    }

    /**
     * Returns true if input value is positive integer or zero.
     * @param int|string $value
     * @return bool
     */
    private static function isPositiveInteger($value)
    {
        return (is_int($value) && $value >= 0) || ctype_digit($value);
    }

    /**
     * @param string $value
     * @return bool
     */
    private static function isSsdeep($value)
    {
        return preg_match('#^([0-9]+):([0-9a-zA-Z/+]*):([0-9a-zA-Z/+]*)$#', $value);
    }

    /**
     * @param string $value
     * @return bool
     */
    private static function isSshFingerprint($value)
    {
        if (str_starts_with($value, 'SHA256:')) {
            $value = substr($value, 7);
            $decoded = base64_decode($value, true);
            return $decoded && strlen($decoded) === 32;
        } else if (str_starts_with($value, 'MD5:')) {
            $value = substr($value, 4);
        }

        $value = str_replace(':', '', $value);
        return self::isHashValid('md5', $value);
    }

    /**
     * @param string $value
     * @return string
     */
    private static function normalizeIp($value)
    {
        // If IP is a CIDR
        if (strpos($value, '/')) {
            list($ip, $range) = explode('/', $value, 2);

            // Compress IPv6
            if (strpos($ip, ':') && $converted = inet_pton($ip)) {
                $ip = inet_ntop($converted);
            }

            // If IP is in CIDR format, but the network is 32 for IPv4 or 128 for IPv6, normalize to non CIDR type
            if (($range === '32' && strpos($value, '.')) || ($range === '128' && strpos($value, ':'))) {
                return $ip;
            }

            return "$ip/$range";
        }

        // Compress IPv6
        if (strpos($value, ':') && $converted = inet_pton($value)) {
            return inet_ntop($converted);
        }

        return $value;
    }
    
    /**
     * Temporary solution for utf8 columns until we migrate to utf8mb4.
     * via https://stackoverflow.com/questions/16496554/can-php-detect-4-byte-encoded-utf8-chars
     * @param string $input
     * @return string
     */
    private static function handle4ByteUnicode($input)
    {
        return preg_replace(
            '%(?:
            \xF0[\x90-\xBF][\x80-\xBF]{2}
            | [\xF1-\xF3][\x80-\xBF]{3}
            | \xF4[\x80-\x8F][\x80-\xBF]{2}
            )%xs',
            '?',
            $input
        );
    }
}
