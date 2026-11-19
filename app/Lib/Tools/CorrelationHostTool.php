<?php

class CorrelationHostTool
{
    const DOMAIN_TYPES = [
        'domain',
        'hostname',
        'domain|ip',
        'hostname|port',
    ];

    const IP_TYPES = [
        'ip-src',
        'ip-dst',
        'ip-src|port',
        'ip-dst|port',
    ];

    const URL_TYPE = 'url';

    public static function supportedTypes()
    {
        return array_merge(
            self::DOMAIN_TYPES,
            self::IP_TYPES,
            [self::URL_TYPE]
        );
    }

    public static function supportsType($type)
    {
        return in_array($type, self::supportedTypes(), true);
    }

    /**
     * Return the value shared by two host-related attributes.
     *
     * Exact non-URL values are handled by MISP's normal correlation path.
     * This method only returns relationships added by host-aware matching.
     *
     * @param array $source Simple Attribute array
     * @param array $target Simple Attribute array
     * @return string|null
     */
    public static function correlationValue(array $source, array $target)
    {
        if (!self::supportsType($source['type']) ||
            !self::supportsType($target['type'])) {
            return null;
        }

        $sourceIsUrl = $source['type'] === self::URL_TYPE;
        $targetIsUrl = $target['type'] === self::URL_TYPE;
        if ($sourceIsUrl && $targetIsUrl) {
            return null;
        }

        foreach (self::extractHostTokens($source) as $sourceToken) {
            foreach (self::extractHostTokens($target) as $targetToken) {
                if ($sourceToken['kind'] !== $targetToken['kind']) {
                    continue;
                }

                if ($sourceToken['kind'] === 'ip') {
                    if (($sourceIsUrl || $targetIsUrl) &&
                        $sourceToken['value'] === $targetToken['value']) {
                        return $sourceToken['value'];
                    }
                    continue;
                }

                $matchingDomain = self::matchingDomain(
                    $sourceToken['value'],
                    $targetToken['value']
                );
                if ($matchingDomain === null) {
                    continue;
                }

                if ($sourceIsUrl || $targetIsUrl ||
                    $sourceToken['value'] !== $targetToken['value']) {
                    return $matchingDomain;
                }
            }
        }
        return null;
    }

    /**
     * Extract normalized DNS names and IP addresses represented by an
     * Attribute. URL values contribute only their parsed host component.
     *
     * @param array $attribute Simple Attribute array
     * @return array
     */
    public static function extractHostTokens(array $attribute)
    {
        $type = $attribute['type'];
        $value1 = $attribute['value1'] ?? '';
        $value2 = $attribute['value2'] ?? '';

        if ($type === self::URL_TYPE) {
            $host = self::extractUrlHost($value1);
            return $host === null ? [] : [self::makeToken($host)];
        }

        if (in_array($type, self::IP_TYPES, true)) {
            $host = self::normalizeHost($value1);
            return self::isIp($host) ? [self::makeToken($host)] : [];
        }

        if (!in_array($type, self::DOMAIN_TYPES, true)) {
            return [];
        }

        $tokens = [];
        $host = self::normalizeHost($value1);
        if ($host !== null && !self::isIp($host)) {
            $tokens[] = self::makeToken($host);
        }
        if ($type === 'domain|ip') {
            $ip = self::normalizeHost($value2);
            if (self::isIp($ip)) {
                $tokens[] = self::makeToken($ip);
            }
        }
        return $tokens;
    }

    /**
     * Values used to find a small candidate set before exact PHP matching.
     *
     * @param array $attribute Simple Attribute array
     * @return array
     */
    public static function candidateSearchValues(array $attribute)
    {
        $values = [];
        foreach (self::extractHostTokens($attribute) as $token) {
            $values[] = $token['value'];
            if ($token['kind'] === 'domain') {
                $values = array_merge(
                    $values,
                    self::parentDomains($token['value'])
                );
            }
        }
        return array_values(array_unique($values));
    }

    private static function extractUrlHost($url)
    {
        $url = trim($url);
        if ($url === '') {
            return null;
        }

        $host = @parse_url($url, PHP_URL_HOST);
        if ($host === null &&
            !preg_match('/^[a-z][a-z0-9+.-]*:/i', $url)) {
            $host = @parse_url('//' . ltrim($url, '/'), PHP_URL_HOST);
        }
        if (!is_string($host)) {
            return null;
        }
        return self::normalizeHost($host);
    }

    private static function normalizeHost($host)
    {
        if (!is_string($host)) {
            return null;
        }
        $host = trim($host);
        if (strlen($host) > 1 && $host[0] === '[' &&
            substr($host, -1) === ']') {
            $host = substr($host, 1, -1);
        }
        $host = strtolower(rtrim($host, '.'));
        if ($host === '') {
            return null;
        }

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $binary = @inet_pton($host);
            return $binary === false ? $host : inet_ntop($binary);
        }

        if (strlen($host) > 253 ||
            preg_match('/[\s\/@\[\]]/', $host)) {
            return null;
        }
        return $host;
    }

    private static function makeToken($host)
    {
        return [
            'kind' => self::isIp($host) ? 'ip' : 'domain',
            'value' => $host,
        ];
    }

    private static function isIp($host)
    {
        return is_string($host) &&
            filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    private static function matchingDomain($first, $second)
    {
        if ($first === $second) {
            return $first;
        }
        if (self::isSubdomain($first, $second)) {
            return $second;
        }
        if (self::isSubdomain($second, $first)) {
            return $first;
        }
        return null;
    }

    private static function isSubdomain($candidate, $parent)
    {
        return str_ends_with($candidate, '.' . $parent);
    }

    private static function parentDomains($host)
    {
        $labels = explode('.', $host);
        $parents = [];
        while (count($labels) > 2) {
            array_shift($labels);
            $parents[] = implode('.', $labels);
        }
        return $parents;
    }
}
