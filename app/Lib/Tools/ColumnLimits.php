<?php
App::uses('Mysql', 'Model/Datasource/Database');

/**
 * How much text each column of a model's table can hold.
 *
 * The database runs in strict mode, so a value longer than its column is a
 * PDOException — an "Internal Error" page — rather than a truncation. This is
 * the one source both halves of the guard read: AppModel turns it into a
 * validation rule on every model, and MispFormHelper into a `maxlength` on
 * every field it draws.
 *
 * CakePHP's describe() reports TEXT, MEDIUMTEXT and LONGTEXT alike as 'text'
 * with no length, so the limits come from information_schema instead. The unit
 * matters: a VARCHAR(n) holds n characters whatever the charset, a TEXT holds
 * n bytes, which a UTF-8 string reaches well before n characters.
 *
 * Each entry: ['limit' => int, 'unit' => 'chars'|'bytes'].
 */
class ColumnLimits
{
    const CACHE_CONFIG = '_cake_model_';

    const CHAR_TYPES = ['char', 'varchar'];
    const BYTE_TYPES = ['binary', 'varbinary', 'tinytext', 'text', 'mediumtext'];

    /** @var array per-request memo, keyed by datasource + table */
    private static $memo = [];

    /**
     * @param Model $Model
     * @return array field => ['limit' => int, 'unit' => 'chars'|'bytes']
     */
    public static function of(Model $Model)
    {
        if (empty($Model->useTable)) {
            return [];
        }
        $db = $Model->getDataSource();
        if (!$db instanceof Mysql) {
            return [];
        }
        $table = $db->fullTableName($Model, false, false);
        $key = $Model->useDbConfig . '_' . $table;
        if (isset(self::$memo[$key])) {
            return self::$memo[$key];
        }
        $cacheKey = 'column_limits_' . preg_replace('/[^A-Za-z0-9_]/', '_', $key);
        $cached = self::cacheEnabled() ? Cache::read($cacheKey, self::CACHE_CONFIG) : false;
        if (is_array($cached)) {
            return self::$memo[$key] = $cached;
        }
        $limits = self::fetch($db, $table);
        if (self::cacheEnabled()) {
            Cache::write($cacheKey, $limits, self::CACHE_CONFIG);
        }
        return self::$memo[$key] = $limits;
    }

    /**
     * Whether $value fits a column of the given limit.
     *
     * @param mixed $value
     * @param array $limit one entry of of()
     * @return bool
     */
    public static function fits($value, array $limit)
    {
        if (!is_string($value) && !is_numeric($value)) {
            return true;
        }
        $length = $limit['unit'] === 'chars'
            ? mb_strlen((string)$value, 'UTF-8')
            : strlen((string)$value);
        return $length <= $limit['limit'];
    }

    public static function message($field, array $limit)
    {
        $label = Inflector::humanize($field);
        return $limit['unit'] === 'chars'
            ? __('%s cannot be longer than %s characters.', $label, $limit['limit'])
            : __('%s cannot be longer than %s bytes.', $label, $limit['limit']);
    }

    private static function fetch(Mysql $db, $table)
    {
        $rows = $db->fetchAll(
            'SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, CHARACTER_OCTET_LENGTH'
            . ' FROM information_schema.COLUMNS'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            [$table],
            ['cache' => false]
        );
        $limits = [];
        foreach ($rows ?: [] as $row) {
            $row = array_change_key_case(reset($row), CASE_UPPER);
            $type = strtolower($row['DATA_TYPE']);
            if (in_array($type, self::CHAR_TYPES, true)) {
                $limit = (int)$row['CHARACTER_MAXIMUM_LENGTH'];
                $unit = 'chars';
            } elseif (in_array($type, self::BYTE_TYPES, true)) {
                $limit = (int)($row['CHARACTER_OCTET_LENGTH'] ?: $row['CHARACTER_MAXIMUM_LENGTH']);
                $unit = 'bytes';
            } else {
                continue;
            }
            if ($limit > 0) {
                $limits[$row['COLUMN_NAME']] = ['limit' => $limit, 'unit' => $unit];
            }
        }
        return $limits;
    }

    private static function cacheEnabled()
    {
        return in_array(self::CACHE_CONFIG, Cache::configured(), true);
    }
}
