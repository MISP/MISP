<?php
App::uses('FastLookupConfig', 'Tools');

/** Tokens for the Bloom pre-filter and range/domain postings, and the live containment predicates. */
class FastLookupValueTool
{
    /**
     * Tokens only select candidates; every candidate is re-verified against
     * live SQL values. A 64-bit digest therefore trades a negligible collision
     * rate (about 3e-4 expected collisions among 1e8 tokens) for 8 bytes saved
     * in every posting field and reverse-manifest entry.
     */
    const DIGEST_BYTES = 8;
    /**
     * Port halves of composites are never indexed: a bare port would match most
     * of these attributes, and at scale a single port posting would exceed the
     * posting size limit. Standalone port attributes are excluded for the same reason.
     */
    const UNINDEXED_COMPONENTS = ['ip-src|port' => 'value2', 'ip-dst|port' => 'value2', 'hostname|port' => 'value2'];

    private $attribute;
    private $db;
    private $columns;
    private $padWeights = [];

    public function __construct($attribute)
    {
        $this->attribute = $attribute;
        $this->db = $attribute->getDataSource();
        $this->columns = FastLookupConfig::columnSchemas($attribute);
    }

    /** SELECT list for attribute scans; the database computes collation weights in the scan. */
    public function scanColumns(string $alias): string
    {
        $columns = [];
        foreach (['id', 'type', 'value1', 'value2'] as $field) {
            $columns[] = $this->db->name($alias . '.' . $field) . ' AS ' . $this->db->name($field);
        }
        foreach (['value1' => 'weight1', 'value2' => 'weight2'] as $component => $name) {
            $expression = $this->supportsWeights($component)
                ? 'WEIGHT_STRING(RTRIM(' . $this->db->name($alias . '.' . $component) . '))'
                : 'NULL';
            $columns[] = $expression . ' AS ' . $this->db->name($name);
        }
        return implode(', ', $columns);
    }

    /** Rows come from a scan using scanColumns(); no further weight queries are made. */
    public function prepareScannedAttributes(array $rows)
    {
        $prepared = [];
        foreach ($rows as $row) {
            $tokens = [];
            foreach (['value1' => 'weight1', 'value2' => 'weight2'] as $component => $weightField) {
                $value = (string)($row[$component] ?? '');
                if ($value === '' || !self::indexesComponent($row['type'], $component)) {
                    continue;
                }
                if ($this->supportsWeights($component)) {
                    if (!is_string($row[$weightField] ?? null)) {
                        throw new RuntimeException('Invalid IOC collation weight response.');
                    }
                    // Empty/ignorable weights use exact SQL discovery at read time.
                    $weight = $this->stripPadding($component, $row[$weightField]);
                    if ($weight !== '') {
                        $tokens[] = $this->exactToken($component, $weight);
                    }
                } else {
                    $tokens[] = self::token('E', $value);
                }
            }
            $networks = [];
            $ipComponent = self::ipComponent($row['type']);
            if ($ipComponent !== null) {
                $network = self::network((string)($row[$ipComponent] ?? ''));
                if ($network !== null) {
                    $tokens[] = self::networkToken($network[0], $network[1]);
                    $networks[] = [strlen($network[0]) === 4 ? 4 : 6, $network[1]];
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
                'networks' => $networks,
            ];
        }
        return $prepared;
    }

    /** Pad-strips a WEIGHT_STRING(RTRIM(column)) value like an input weight. */
    public function stripColumnPadding(string $component, string $weight): string
    {
        return $this->stripPadding($component, $weight);
    }

    /** SQL padding ignores characters weighing like a space (e.g. NBSP under unicode_ci). */
    private function stripPadding(string $component, string $weight): string
    {
        $collation = $this->columns[$component]['collate'];
        return self::stripPaddingWeight($weight, $this->padWeight($collation));
    }

    /** Lazily fetched and memoized: the weight of a single space under a given collation. */
    private function padWeight(string $collation): string
    {
        if (!isset($this->padWeights[$collation])) {
            $statement = $this->db->rawQuery('SELECT WEIGHT_STRING(' . $this->padExpression($collation) . ') AS pad_weight');
            if (!is_object($statement)) {
                throw new RuntimeException('Could not derive IOC collation weights.');
            }
            try {
                $row = $statement->fetch(PDO::FETCH_ASSOC);
            } finally {
                $statement->closeCursor();
            }
            if (!is_array($row) || !is_string($row['pad_weight'] ?? null) || $row['pad_weight'] === '') {
                throw new RuntimeException('Invalid IOC collation weight response.');
            }
            $this->padWeights[$collation] = $row['pad_weight'];
        }
        return $this->padWeights[$collation];
    }

    /** A single space, converted and collated, for use inside WEIGHT_STRING(). */
    private function padExpression(string $collation): string
    {
        $charset = explode('_', $collation, 2)[0];
        return 'CONVERT(' . $this->db->value(' ', 'string') . ' USING ' . $charset . ') COLLATE ' . $collation;
    }

    private static function stripPaddingWeight(string $weight, string $pad): string
    {
        while (strlen($weight) >= strlen($pad) && substr($weight, -strlen($pad)) === $pad) {
            $weight = substr($weight, 0, -strlen($pad));
        }
        return $weight;
    }

    /**
     * Input ordinals are retained through tokenization and Redis batching.
     * @param array|null $fallback Receives [input index][component] => true for SQL-only discovery.
     * @param array|null $weights Receives [input index][component] => pad-stripped weight.
     * @param array|null $prefixLengths [4|6 => [length => true]]; null generates every length.
     */
    public function queryTokens(array $values, array $types, &$fallback = null, &$weights = null, ?array $prefixLengths = null)
    {
        $requests = [];
        $fallback = [];
        foreach ($values as $index => $value) {
            foreach (['value1', 'value2'] as $component) {
                if (!$this->representable($value, $component)) {
                    continue;
                }
                if ($this->supportsWeights($component)) {
                    $requests[$index][$component] = $value;
                } else {
                    $fallback[$index][$component] = true;
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
                    continue;
                }
                $tokens[$this->exactToken($component, $weight)] = 'exact';
            }
            $ip = filter_var($value, FILTER_VALIDATE_IP) ? inet_pton($value) : false;
            $domain = $ip === false ? self::domain($value) : null;
            $networkTokens = [];
            if ($ip !== false && $hasIpType) {
                $family = strlen($ip) === 4 ? 4 : 6;
                for ($prefix = 0, $maximum = strlen($ip) * 8; $prefix <= $maximum; ++$prefix) {
                    if ($prefixLengths !== null && !isset($prefixLengths[$family][$prefix])) {
                        continue;
                    }
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
            foreach ($tokens as $token => $kind) {
                $queries[$index][] = ['token' => (string)$token, 'kind' => $kind];
            }
            foreach ($networkTokens as $token) {
                $queries[$index][] = ['token' => $token, 'kind' => 'ip_range'];
            }
            foreach ($domainTokens as $token) {
                $queries[$index][] = ['token' => $token, 'kind' => 'domain'];
            }
        }
        return $queries;
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

    public static function indexesComponent(string $type, string $component): bool
    {
        return (self::UNINDEXED_COMPONENTS[$type] ?? null) !== $component;
    }

    public function representable($value, $component)
    {
        $schema = $this->columns[$component];
        $threeByte = in_array($schema['charset'], ['utf8', 'utf8mb3'], true)
            || preg_match('/^utf8(?:mb3)?_/', $schema['collate']) === 1;
        return !$threeByte || preg_match('/[\xF0-\xF4]/', $value) !== 1;
    }

    private $supportsWeights = [];

    private function supportsWeights($component)
    {
        if (!isset($this->supportsWeights[$component])) {
            $this->supportsWeights[$component] = $this->collationSupportsWeights($component);
        }
        return $this->supportsWeights[$component];
    }

    private function collationSupportsWeights($component)
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
        $columns = [];
        $unique = [];
        $destinations = [];
        $collations = [];
        foreach ($values as $index => $components) {
            foreach ($components as $component => $value) {
                $collation = $this->columns[$component]['collate'];
                $identity = $collation . "\0" . $value;
                if (!isset($unique[$identity])) {
                    $unique[$identity] = count($columns);
                    $charset = explode('_', $collation, 2)[0];
                    $expression = 'CONVERT(' . $this->db->value($value, 'string') . ' USING ' . $charset . ') COLLATE ' . $collation;
                    $columns[] = 'WEIGHT_STRING(RTRIM(' . $expression . ')) AS ' . $this->db->name('w' . count($columns));
                    $collations[$collation] = true;
                }
                $destinations[$unique[$identity]][] = [$index, $component];
            }
        }
        if (!$columns) {
            return [];
        }
        $valueColumns = count($columns);
        $pads = [];
        foreach (array_keys($collations) as $collation) {
            if (!isset($this->padWeights[$collation])) {
                $pads[count($columns)] = $collation;
                $columns[] = 'WEIGHT_STRING(' . $this->padExpression($collation) . ') AS ' . $this->db->name('p' . count($pads));
            }
        }
        $statement = $this->db->rawQuery('SELECT ' . implode(', ', $columns));
        if (!is_object($statement)) {
            throw new RuntimeException('Could not derive IOC collation weights.');
        }
        try {
            $row = $statement->fetch(PDO::FETCH_NUM);
        } finally {
            $statement->closeCursor();
        }
        if (!is_array($row) || count($row) !== count($columns)) {
            throw new RuntimeException('Invalid IOC collation weight response.');
        }
        $row = array_values($row);
        foreach ($pads as $position => $collation) {
            if (!is_string($row[$position]) || $row[$position] === '') {
                throw new RuntimeException('Invalid IOC collation weight response.');
            }
            $this->padWeights[$collation] = $row[$position];
        }
        $weights = [];
        for ($n = 0; $n < $valueColumns; ++$n) {
            if (!is_string($row[$n])) {
                throw new RuntimeException('Invalid IOC collation weight response.');
            }
            foreach ($destinations[$n] as [$index, $component]) {
                $weights[$index][$component] = self::stripPaddingWeight($row[$n], $this->padWeights[$this->columns[$component]['collate']]);
            }
        }
        ksort($weights);
        return $weights;
    }

    private function exactToken($component, $weight)
    {
        return self::token('E', $this->columns[$component]['collate'] . "\0" . $weight);
    }

    private static function token($kind, $value)
    {
        return $kind . substr(hash('sha256', $value, true), 0, self::DIGEST_BYTES);
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
