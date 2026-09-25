<?php
App::uses('FastLookupConfig', 'Tools');

/** Fixed-size postings and the corresponding live containment predicates. */
class FastLookupValueTool
{
    private $attribute;
    private $db;
    private $columns;
    private $fallback = [];

    public function __construct($attribute)
    {
        $this->attribute = $attribute;
        $this->db = $attribute->getDataSource();
        $this->columns = FastLookupConfig::columnSchemas($attribute);
    }

    public function prepareAttributes(array $rows)
    {
        $prepared = [];
        foreach (array_chunk($rows, 100) as $batch) {
            $values = [];
            foreach ($batch as $index => $row) {
                foreach (['value1', 'value2'] as $component) {
                    $value = (string)($row[$component] ?? '');
                    if ($value !== '' && $this->supportsWeights($component)) {
                        $values[$index][$component] = $value;
                    }
                }
            }
            $weights = $this->weights($values);
            foreach ($batch as $index => $row) {
                $tokens = [];
                foreach (['value1', 'value2'] as $component) {
                    $value = (string)($row[$component] ?? '');
                    if ($value === '') {
                        continue;
                    }
                    if ($this->supportsWeights($component)) {
                        $weight = $weights[$index][$component];
                        // Empty/ignorable weights use exact SQL discovery at read
                        // time, including the usually empty value2 column.
                        if ($weight !== '') {
                            $tokens[] = $this->exactToken($component, $weight);
                        }
                    } else {
                        $tokens[] = self::token('E', $value);
                    }
                }
                $ipComponent = self::ipComponent($row['type']);
                if ($ipComponent !== null) {
                    $network = self::network((string)($row[$ipComponent] ?? ''));
                    if ($network !== null) {
                        $tokens[] = self::networkToken($network[0], $network[1]);
                    }
                }
                if (self::domainType($row['type'])) {
                    $domain = self::domain((string)($row['value1'] ?? ''));
                    if ($domain !== null) {
                        $tokens[] = self::token('D', $domain);
                    }
                }
                $prepared[] = [
                    'id' => (string)$row['id'],
                    'type' => $row['type'],
                    'tokens' => array_values(array_unique($tokens, SORT_STRING)),
                ];
            }
        }
        return $prepared;
    }

    /** Input ordinals are retained through tokenization and Redis batching. */
    public function queryTokens(array $values, array $types)
    {
        $requests = [];
        $this->fallback = [];
        foreach ($values as $index => $value) {
            foreach (['value1', 'value2'] as $component) {
                if (!$this->representable($value, $component)) {
                    continue;
                }
                if ($this->supportsWeights($component)) {
                    $requests[$index][$component] = $value;
                } else {
                    $this->fallback[$index][$component] = true;
                }
            }
        }
        $weights = $this->weights($requests);
        $queries = [];
        $hasIpType = false;
        $hasDomainType = false;
        foreach ($types as $type) {
            $hasIpType = $hasIpType || self::ipComponent($type) !== null;
            $hasDomainType = $hasDomainType || self::domainType($type);
        }
        foreach ($values as $index => $value) {
            $tokens = [];
            foreach ($weights[$index] ?? [] as $component => $weight) {
                if ($weight === '') {
                    $this->fallback[$index][$component] = true;
                    continue;
                }
                $tokens[$this->exactToken($component, $weight)] = 'exact';
            }
            $ip = filter_var($value, FILTER_VALIDATE_IP) ? inet_pton($value) : false;
            $domain = $ip === false ? self::domain($value) : null;
            $networkTokens = [];
            if ($ip !== false && $hasIpType) {
                for ($prefix = 0, $maximum = strlen($ip) * 8; $prefix <= $maximum; ++$prefix) {
                    $networkTokens[] = self::networkToken($ip, $prefix);
                }
            }
            $domainTokens = [];
            if ($domain !== null && $hasDomainType) {
                foreach (self::parents($domain) as $parent) {
                    $domainTokens[] = self::token('D', $parent);
                }
            }
            $queries[$index] = [];
            foreach ($types as $type) {
                foreach ($tokens as $token => $kind) {
                    $queries[$index][] = ['type' => $type, 'token' => $token, 'kind' => $kind];
                }
                if ($networkTokens && self::ipComponent($type) !== null) {
                    foreach ($networkTokens as $token) {
                        $queries[$index][] = ['type' => $type, 'token' => $token, 'kind' => 'ip_range'];
                    }
                }
                if ($domainTokens && self::domainType($type)) {
                    foreach ($domainTokens as $token) {
                        $queries[$index][] = ['type' => $type, 'token' => $token, 'kind' => 'domain'];
                    }
                }
            }
        }
        return $queries;
    }

    /** Components requiring SQL discovery after the most recent queryTokens. */
    public function exactFallbackComponents()
    {
        return $this->fallback;
    }

    public function expandedMatches(string $input, array $attribute)
    {
        $matches = ['ip_ranges' => [], 'domains' => []];
        $component = self::ipComponent($attribute['type']);
        if ($component !== null && filter_var($input, FILTER_VALIDATE_IP)) {
            $stored = (string)($attribute[$component] ?? '');
            $network = self::network($stored);
            $ip = inet_pton($input);
            if ($network !== null && strlen($ip) === strlen($network[0]) && self::masked($ip, $network[1]) === $network[0]) {
                $matches['ip_ranges'][] = $stored;
            }
        }
        if (self::domainType($attribute['type'])) {
            $inputDomain = self::domain($input);
            $stored = (string)($attribute['value1'] ?? '');
            $domain = self::domain($stored);
            if ($inputDomain !== null && $domain !== null && in_array($domain, self::parents($inputDomain), true)) {
                $matches['domains'][] = $stored;
            }
        }
        return $matches;
    }

    public function representable($value, $component)
    {
        $schema = $this->columns[$component];
        $threeByte = in_array($schema['charset'], ['utf8', 'utf8mb3'], true)
            || preg_match('/^utf8(?:mb3)?_/', $schema['collate']) === 1;
        return !$threeByte || preg_match('/[\xF0-\xF4]/', $value) !== 1;
    }

    private function supportsWeights($component)
    {
        $driver = $this->db->config['datasource'] ?? get_class($this->db);
        if (stripos($driver, 'mysql') === false && stripos($driver, 'mariadb') === false) {
            return false;
        }
        // These legacy single-level PAD SPACE collations have fixed-width
        // weights. Other collations retain exact correctness through SQL.
        return preg_match('/^utf8(?:mb3|mb4)?_(?:unicode_ci|general_ci|bin)$/D', $this->columns[$component]['collate']) === 1;
    }

    private function weights(array $values)
    {
        $weights = [];
        foreach (array_chunk($values, 100, true) as $batch) {
            $branches = [];
            $unique = [];
            $destinations = [];
            foreach ($batch as $index => $components) {
                foreach ($components as $component => $value) {
                    $collation = $this->columns[$component]['collate'];
                    $identity = $collation . "\0" . $value;
                    if (isset($unique[$identity])) {
                        list($firstIndex, $firstComponent) = $unique[$identity];
                        $destinations[$firstIndex][$firstComponent][] = [$index, $component];
                        continue;
                    }
                    $unique[$identity] = [$index, $component];
                    $destinations[$index][$component] = [[$index, $component]];
                    $charset = explode('_', $collation, 2)[0];
                    $expression = 'CONVERT(' . $this->db->value($value, 'string') . ' USING ' . $charset . ') COLLATE ' . $collation;
                    $pad = 'CONVERT(' . $this->db->value(' ', 'string') . ' USING ' . $charset . ') COLLATE ' . $collation;
                    $branches[] = 'SELECT ' . (int)$index . ' AS input_index, ' . $this->db->value($component, 'string')
                        . ' AS component, WEIGHT_STRING(RTRIM(' . $expression . ')) AS weight, WEIGHT_STRING(' . $pad . ') AS pad_weight';
                }
            }
            if (!$branches) {
                continue;
            }
            $statement = $this->db->rawQuery(implode(' UNION ALL ', $branches));
            if (!is_object($statement)) {
                throw new RuntimeException('Could not derive IOC collation weights.');
            }
            try {
                while (($row = $statement->fetch(PDO::FETCH_ASSOC)) !== false) {
                    $index = (int)$row['input_index'];
                    $component = $row['component'];
                    if (!isset($batch[$index][$component]) || !is_string($row['weight'] ?? null)
                        || !is_string($row['pad_weight'] ?? null) || $row['pad_weight'] === '') {
                        throw new RuntimeException('Invalid IOC collation weight response.');
                    }
                    $weight = $row['weight'];
                    $pad = $row['pad_weight'];
                    // SQL padding ignores characters with the same weight as a
                    // space too (e.g. NBSP under unicode_ci), not only ASCII SP.
                    while (strlen($weight) >= strlen($pad) && substr($weight, -strlen($pad)) === $pad) {
                        $weight = substr($weight, 0, -strlen($pad));
                    }
                    foreach ($destinations[$index][$component] ?? [[$index, $component]] as list($destinationIndex, $destinationComponent)) {
                        $weights[$destinationIndex][$destinationComponent] = $weight;
                    }
                }
            } finally {
                $statement->closeCursor();
            }
            foreach ($batch as $index => $components) {
                foreach ($components as $component => $value) {
                    if (!isset($weights[$index][$component])) {
                        throw new RuntimeException('Incomplete IOC collation weight response.');
                    }
                }
            }
        }
        return $weights;
    }

    private function exactToken($component, $weight)
    {
        return self::token('E', $this->columns[$component]['collate'] . "\0" . $weight);
    }

    private static function token($kind, $value)
    {
        return $kind . substr(hash('sha256', $value, true), 0, 16);
    }

    private static function ipComponent($type)
    {
        if (in_array($type, ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'], true)) {
            return 'value1';
        }
        return $type === 'domain|ip' ? 'value2' : null;
    }

    private static function domainType($type)
    {
        return $type === 'domain' || $type === 'domain|ip';
    }

    private static function network($value)
    {
        $parts = explode('/', $value);
        if (count($parts) !== 2 || !filter_var($parts[0], FILTER_VALIDATE_IP) || !ctype_digit($parts[1]) || strlen($parts[1]) > 3) {
            return null;
        }
        $ip = inet_pton($parts[0]);
        $prefix = (int)$parts[1];
        if ($prefix > strlen($ip) * 8) {
            return null;
        }
        return [self::masked($ip, $prefix), $prefix];
    }

    private static function masked($ip, $prefix)
    {
        $full = intdiv($prefix, 8);
        $remaining = $prefix % 8;
        $network = substr($ip, 0, $full);
        if ($remaining) {
            $network .= chr(ord($ip[$full]) & (0xff << (8 - $remaining)));
            ++$full;
        }
        return $network . str_repeat("\0", strlen($ip) - $full);
    }

    private static function networkToken($ip, $prefix)
    {
        return self::token('I', chr(strlen($ip) === 4 ? 4 : 6) . chr($prefix) . self::masked($ip, $prefix));
    }

    private static function domain($value)
    {
        $value = strtolower(rtrim($value, '.'));
        if (preg_match('/[^\x00-\x7f]/', $value)) {
            if (!function_exists('idn_to_ascii')) {
                return null;
            }
            $value = idn_to_ascii($value, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($value === false) {
                return null;
            }
        }
        if (strlen($value) > 253 || !preg_match('/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/D', $value)) {
            return null;
        }
        foreach (explode('.', $value) as $label) {
            if (strlen($label) > 63) {
                return null;
            }
        }
        return $value;
    }

    private static function parents($domain)
    {
        $parents = [];
        while (strpos($domain, '.') !== false) {
            $parents[] = $domain;
            $domain = substr($domain, strpos($domain, '.') + 1);
        }
        return $parents;
    }
}
