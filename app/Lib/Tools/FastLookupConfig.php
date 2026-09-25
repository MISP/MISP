<?php

/** Membership settings and database identity shared by writers and readers. */
class FastLookupConfig
{
    const NORMALIZATION_VERSION = 1;
    const DEFAULT_MAX_VALUES = 10000;
    const DEFAULT_TYPES = [
        'domain', 'domain|ip', 'hostname', 'hostname|port', 'ip-src', 'ip-dst',
        'ip-src|port', 'ip-dst|port', 'md5', 'sha1', 'sha256', 'sha512',
        'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha512',
        'malware-sample',
    ];

    public static function scope($attribute = null)
    {
        $setting = Configure::read('MISP.fast_lookup_attribute_types');
        $types = $setting === null ? self::DEFAULT_TYPES : self::parseTypes($setting, $attribute);
        sort($types, SORT_STRING);
        $published = Configure::read('MISP.fast_lookup_published_only');
        if ($published === null) {
            $published = true;
        } elseif (!in_array($published, [true, false, 0, 1, '0', '1'], true)) {
            throw new InvalidArgumentException('MISP.fast_lookup_published_only must be a boolean.');
        }
        $maximum = Configure::read('MISP.fast_lookup_max_values');
        $maximum = $maximum === null ? self::DEFAULT_MAX_VALUES : self::positiveInteger($maximum);
        return [
            'attribute_types' => $types,
            'published_only' => (bool)$published,
            'max_values' => $maximum,
            'matching' => ['exact', 'ip_cidr', 'parent_domain'],
        ];
    }

    /** Report invalid settings without inventing a usable membership scope. */
    public static function diagnosticScope($attribute = null): array
    {
        try {
            return self::scope($attribute);
        } catch (InvalidArgumentException $e) {
            $setting = Configure::read('MISP.fast_lookup_attribute_types');
            if ($setting === null) {
                $types = self::DEFAULT_TYPES;
            } elseif (is_string($setting)) {
                $types = array_values(array_unique(array_filter(array_map('trim', explode(',', $setting)), 'strlen')));
            } else {
                $types = null;
            }
            if ($types !== null) {
                sort($types, SORT_STRING);
            }
            $published = Configure::read('MISP.fast_lookup_published_only');
            $published = $published === null ? true
                : (in_array($published, [true, false, 0, 1, '0', '1'], true) ? (bool)$published : null);
            $maximum = Configure::read('MISP.fast_lookup_max_values');
            try {
                $maximum = $maximum === null ? self::DEFAULT_MAX_VALUES : self::positiveInteger($maximum);
            } catch (InvalidArgumentException $e) {
                $maximum = null;
            }
            return [
                'attribute_types' => $types,
                'published_only' => $published,
                'max_values' => $maximum,
                'matching' => ['exact', 'ip_cidr', 'parent_domain'],
                'configuration_valid' => false,
            ];
        }
    }

    /** Settings validation returns the convention expected by Server. */
    public static function validateTypeSetting($value)
    {
        try {
            self::parseTypes($value);
            return true;
        } catch (InvalidArgumentException $e) {
            return $e->getMessage();
        }
    }

    public static function namespaceFor($attribute)
    {
        return json_encode(self::databaseIdentity($attribute), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public static function fingerprint($attribute)
    {
        $scope = self::scope($attribute);
        unset($scope['max_values']);
        $db = $attribute->getDataSource();
        $version = 'unknown';
        if (method_exists($db, 'getConnection')) {
            $connection = $db->getConnection();
            if (is_object($connection) && method_exists($connection, 'getAttribute')) {
                $version = (string)$connection->getAttribute(PDO::ATTR_SERVER_VERSION);
            }
        }
        $identity = [
            'database' => self::databaseIdentity($attribute),
            'database_version' => $version,
            'columns' => self::columnSchemas($attribute),
            'scope' => $scope,
            'normalization_version' => self::NORMALIZATION_VERSION,
            'idna' => function_exists('idn_to_ascii') ? (defined('INTL_ICU_VERSION') ? INTL_ICU_VERSION : 'available') : 'unavailable',
        ];
        return hash('sha256', json_encode($identity, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public static function columnSchemas($attribute)
    {
        $columns = [];
        foreach (['value1', 'value2'] as $component) {
            $schema = $attribute->schema($component);
            $columns[$component] = [
                'charset' => strtolower($schema['charset'] ?? ''),
                'collate' => strtolower($schema['collate'] ?? ''),
            ];
        }
        return $columns;
    }

    private static function databaseIdentity($attribute)
    {
        $db = $attribute->getDataSource();
        $identity = array_intersect_key($db->config, array_flip([
            'datasource', 'host', 'port', 'database', 'schema', 'prefix', 'unix_socket',
        ]));
        $identity['table'] = $db->fullTableName($attribute);
        ksort($identity);
        return $identity;
    }

    private static function parseTypes($value, $attribute = null)
    {
        if (!is_string($value) || trim($value) === '') {
            throw new InvalidArgumentException('Select at least one comma-separated MISP attribute type.');
        }
        if ($attribute === null) {
            $attribute = ClassRegistry::init('MispAttribute');
        }
        $definitions = $attribute->typeDefinitions;
        $types = [];
        foreach (explode(',', $value) as $type) {
            $type = trim($type);
            if ($type === '' || !array_key_exists($type, $definitions)) {
                throw new InvalidArgumentException('Unknown MISP attribute type: ' . $type);
            }
            $types[$type] = true;
        }
        return array_keys($types);
    }

    private static function positiveInteger($value)
    {
        if ((!is_int($value) && !is_string($value)) || !preg_match('/^[1-9][0-9]*$/D', (string)$value)) {
            throw new InvalidArgumentException('MISP.fast_lookup_max_values must be a positive integer.');
        }
        $maximum = (string)PHP_INT_MAX;
        $value = (string)$value;
        if (strlen($value) > strlen($maximum) || (strlen($value) === strlen($maximum) && strcmp($value, $maximum) > 0)) {
            throw new InvalidArgumentException('MISP.fast_lookup_max_values exceeds the supported integer range.');
        }
        return (int)$value;
    }
}
