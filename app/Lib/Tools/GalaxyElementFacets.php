<?php
require_once __DIR__ . '/IndexFilterState.php';

/**
 * Which galaxy element keys a galaxy's cluster list can be filtered on, and
 * how the `meta_<key>` filter parameters read.
 *
 * A key qualifies when its values repeat across clusters: `country` on threat
 * actors does, `external_id` on attack patterns does not.
 */
class GalaxyElementFacets
{
    const PARAM_PREFIX = 'meta_';
    const SEPARATOR = '||';
    const MAX_KEYS = 6;
    const MAX_VALUES = 250;
    const MAX_VALUE_LENGTH = 100;
    const SKIPPED_KEYS = ['refs', 'synonyms', 'links'];

    /**
     * @param array $summaries key => ['rows' => int, 'clusters' => int, 'values' => int]
     * @return string[] the keys to offer, most widely used first
     */
    public static function selectKeys(array $summaries)
    {
        $keys = [];
        foreach ($summaries as $key => $summary) {
            $key = (string)$key;
            $values = (int)$summary['values'];
            if (!self::isUsableKey($key)
                || $values < 2
                || $values > self::MAX_VALUES
                || (int)$summary['rows'] < 2 * $values
            ) {
                continue;
            }
            $keys[$key] = (int)$summary['clusters'];
        }
        uksort($keys, function ($a, $b) use ($keys) {
            return [$keys[$b], $a] <=> [$keys[$a], $b];
        });
        return array_slice(array_keys($keys), 0, self::MAX_KEYS);
    }

    /**
     * @param string $key
     * @return bool
     */
    public static function isUsableKey($key)
    {
        return preg_match('/^[A-Za-z0-9_.-]+$/', $key) === 1
            && !in_array($key, self::SKIPPED_KEYS, true);
    }

    /**
     * Whether a value can be offered: it has to survive the trip through a
     * named URL segment and the picker's value syntax.
     *
     * @param string $value
     * @return bool
     */
    public static function isUsableValue($value)
    {
        $value = (string)$value;
        return trim($value) !== ''
            && mb_strlen($value) <= self::MAX_VALUE_LENGTH
            && strpos($value, '/') === false
            && strpos($value, self::SEPARATOR) === false
            && $value[0] !== '!';
    }

    /**
     * @param string $key
     * @return string
     */
    public static function label($key)
    {
        $key = preg_replace('/^(cfr|mitre)[-_]/i', '', $key);
        return ucfirst(trim(preg_replace('/[-_.]+/', ' ', $key)));
    }

    /**
     * @param array $params request parameters, named or posted
     * @return array key => ['include' => string[], 'exclude' => string[]]
     */
    public static function filtersFromParams(array $params)
    {
        $filters = [];
        foreach ($params as $name => $raw) {
            $name = (string)$name;
            if (strpos($name, self::PARAM_PREFIX) !== 0) {
                continue;
            }
            $key = substr($name, strlen(self::PARAM_PREFIX));
            if (!self::isUsableKey($key)) {
                continue;
            }
            $raw = is_array($raw) ? implode(self::SEPARATOR, $raw) : (string)$raw;
            $filter = ['include' => [], 'exclude' => []];
            foreach (IndexFilterState::pieces($raw, self::SEPARATOR) as [$value, $excluded]) {
                $filter[$excluded ? 'exclude' : 'include'][] = $value;
            }
            if ($filter['include'] || $filter['exclude']) {
                $filters[$key] = $filter;
            }
        }
        return $filters;
    }
}
