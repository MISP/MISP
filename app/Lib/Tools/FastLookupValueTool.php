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
    /** Every ASCII code point, with leading, interior and trailing spaces; checked against SQL before a collation's ASCII weight table is trusted. */
    const ASCII_PROBE = " The Quick\tBrown Fox !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f end  ";

    private $attribute;
    private $db;
    private $columns;
    private $padWeights = [];
    /** Per collation: byte => weight for 0x00-0x7F, or false once the probe disagreed with SQL. */
    private $asciiWeights = [];

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
                    // An empty weight is never indexed, and never matched at read time.
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

    /**
     * WEIGHT_STRING(RTRIM(v)) per value, pad-stripped. For ASCII-only values in
     * these single-level collations it is the concatenation of per-byte weights,
     * derived in PHP from a table the database verified against a probe.
     */
    private function weights(array $values)
    {
        $columns = [];
        $unique = [];
        $destinations = [];
        $collations = [];
        $ascii = [];
        foreach ($values as $index => $components) {
            foreach ($components as $component => $value) {
                $collation = $this->columns[$component]['collate'];
                $collations[$collation] = true;
                if (($this->asciiWeights[$collation] ?? null) !== false && is_string($value) && preg_match('/\A[\x00-\x7F]*\z/', $value) === 1) {
                    $ascii[$index][$component] = $value;
                    continue;
                }
                $identity = $collation . "\0" . $value;
                if (!isset($unique[$identity])) {
                    $unique[$identity] = count($columns);
                    $columns[] = 'WEIGHT_STRING(RTRIM(' . $this->literalExpression($value, $collation) . ')) AS ' . $this->db->name('w' . count($columns));
                }
                $destinations[$unique[$identity]][] = [$index, $component];
            }
        }
        $valueColumns = count($columns);
        $tables = [];
        foreach ($ascii as $components) {
            foreach (array_keys($components) as $component) {
                $collation = $this->columns[$component]['collate'];
                if (!isset($this->asciiWeights[$collation]) && !in_array($collation, $tables, true)) {
                    $tables[count($columns)] = $collation;
                    $charset = explode('_', $collation, 2)[0];
                    for ($n = 0; $n < 128; ++$n) {
                        $columns[] = 'WEIGHT_STRING(CONVERT(CHAR(' . $n . ') USING ' . $charset . ') COLLATE ' . $collation . ') AS ' . $this->db->name('t' . count($tables) . '_' . $n);
                    }
                    $columns[] = 'WEIGHT_STRING(RTRIM(' . $this->literalExpression(self::ASCII_PROBE, $collation) . ')) AS ' . $this->db->name('q' . count($tables));
                }
            }
        }
        $pads = [];
        foreach (array_keys($collations) as $collation) {
            if (!isset($this->padWeights[$collation])) {
                $pads[count($columns)] = $collation;
                $columns[] = 'WEIGHT_STRING(' . $this->padExpression($collation) . ') AS ' . $this->db->name('p' . count($pads));
            }
        }
        $computed = [];
        if ($columns) {
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
            }
            $verified = [];
            foreach ($tables as $position => $collation) {
                $table = [];
                for ($n = 0; $n <= 128; ++$n) {
                    if (!is_string($row[$position + $n])) {
                        throw new RuntimeException('Invalid IOC collation weight response.');
                    }
                    if ($n < 128) {
                        $table[chr($n)] = $row[$position + $n];
                    }
                }
                $verified[$collation] = strtr(rtrim(self::ASCII_PROBE, ' '), $table) === $row[$position + 128] ? $table : false;
            }
            for ($n = 0; $n < $valueColumns; ++$n) {
                if (!is_string($row[$n])) {
                    throw new RuntimeException('Invalid IOC collation weight response.');
                }
            }
            foreach ($pads as $position => $collation) {
                $this->padWeights[$collation] = $row[$position];
            }
            $this->asciiWeights = $verified + $this->asciiWeights;
            for ($n = 0; $n < $valueColumns; ++$n) {
                foreach ($destinations[$n] as [$index, $component]) {
                    $computed[$index][$component] = self::stripPaddingWeight($row[$n], $this->padWeights[$this->columns[$component]['collate']]);
                }
            }
        }
        $rejected = [];
        foreach ($ascii as $index => $components) {
            foreach ($components as $component => $value) {
                $collation = $this->columns[$component]['collate'];
                if ($this->asciiWeights[$collation] === false) {
                    $rejected[$index][$component] = $value;
                    continue;
                }
                // RTRIM removes trailing spaces only.
                $computed[$index][$component] = self::stripPaddingWeight(strtr(rtrim($value, ' '), $this->asciiWeights[$collation]), $this->padWeights[$collation]);
            }
        }
        if ($rejected) {
            foreach ($this->weights($rejected) as $index => $components) {
                foreach ($components as $component => $weight) {
                    $computed[$index][$component] = $weight;
                }
            }
        }
        $weights = [];
        foreach ($values as $index => $components) {
            foreach (array_keys($components) as $component) {
                $weights[$index][$component] = $computed[$index][$component];
            }
        }
        ksort($weights);
        return $weights;
    }

    private function literalExpression($value, string $collation): string
    {
        $charset = explode('_', $collation, 2)[0];
        return 'CONVERT(' . $this->db->value($value, 'string') . ' USING ' . $charset . ') COLLATE ' . $collation;
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
