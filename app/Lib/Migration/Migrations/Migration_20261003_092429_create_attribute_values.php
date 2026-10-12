<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Create the attribute_values dictionary
 */
class Migration_20261003_092429_create_attribute_values extends AbstractMigration
{
    public $description = 'Create the attribute_values dictionary';

    public $requiresLogout = false;

    const TABLE = 'attribute_values';

    /**
     * Characters of the value covered by the case-insensitive lookup index.
     */
    const VALUE_PREFIX = 128;

    const PGSQL_VALUE_INDEX = 'idx_attribute_values_value';

    const PGSQL_SEARCH_INDEX = 'idx_attribute_values_value_search';

    /**
     * On PostgreSQL, refuse with instructions when pg_trgm cannot be created,
     * rather than failing on the bare CREATE EXTENSION error.
     *
     * @return bool
     * @throws RuntimeException
     */
    public function beforeUp()
    {
        if ($this->inspector()->flavour() !== SchemaInspector::FLAVOUR_PGSQL) {
            return true;
        }
        $statement = $this->inspector()->getDataSource()->rawQuery(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pg_trgm')::int AS installed, " .
            "EXISTS (SELECT 1 FROM pg_catalog.pg_available_extensions WHERE name = 'pg_trgm')::int AS available, " .
            "has_database_privilege(current_database(), 'CREATE')::int AS may_create"
        );
        $state = $statement->fetch(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        $error = self::pgTrgmProblem(
            (bool)(int)$state['installed'],
            (bool)(int)$state['available'],
            (bool)(int)$state['may_create']
        );
        if ($error !== null) {
            throw new RuntimeException($error);
        }
        return true;
    }

    /**
     * Each step is guarded, so a retry after a partial failure declares only
     * what is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $pgsql = $inspector->flavour() === SchemaInspector::FLAVOUR_PGSQL;
        $variables = $inspector->serverVariables();
        $collation = self::mysqlCollation(isset($variables['version']) ? $variables['version'] : '');

        if (!$inspector->hasTable(self::TABLE)) {
            $schema->createTable(self::TABLE, array(
                'id' => array('type' => 'biginteger', 'key' => 'primary', 'unsigned' => true, 'null' => false),
                'value' => array(
                    'type' => 'text',
                    'null' => false,
                    'charset' => 'utf8mb4',
                    'collate' => $collation,
                ),
                'hash' => array('type' => 'varbinary', 'length' => 16, 'null' => false),
            ), array(
                'indexes' => array('hash' => array('unique' => true)),
                'engine' => 'InnoDB',
                'charset' => 'utf8mb4',
                'collate' => $collation,
            ));
        }
        if (!$inspector->hasNamedIndex(self::TABLE, $pgsql ? self::PGSQL_VALUE_INDEX : 'value')) {
            $schema->rawSql(array(
                'mysql' => sprintf(
                    'ALTER TABLE `%s` ADD INDEX `value` (`value`(%d));',
                    self::TABLE,
                    self::VALUE_PREFIX
                ),
                'pgsql' => sprintf(
                    'CREATE INDEX "%s" ON "%s" (lower(left("value", %d)));',
                    self::PGSQL_VALUE_INDEX,
                    self::TABLE,
                    self::VALUE_PREFIX
                ),
            ));
        }
        if (!$inspector->hasNamedIndex(self::TABLE, $pgsql ? self::PGSQL_SEARCH_INDEX : 'value_search')) {
            $schema->rawSql(array(
                'mysql' => sprintf('ALTER TABLE `%s` ADD FULLTEXT INDEX `value_search` (`value`);', self::TABLE),
                'pgsql' => array(
                    'CREATE EXTENSION IF NOT EXISTS pg_trgm;',
                    sprintf(
                        'CREATE INDEX "%s" ON "%s" USING gin ("value" gin_trgm_ops);',
                        self::PGSQL_SEARCH_INDEX,
                        self::TABLE
                    ),
                ),
            ));
        }
    }

    /**
     * The case- and accent-insensitive collation of attribute_values.value
     * for a MySQL-family server, by its version string. Never
     * utf8mb4_unicode_ci: it weighs every 4-byte character the same.
     *
     * @param string $serverVersion As SELECT VERSION() reports it.
     * @return string
     */
    public static function mysqlCollation($serverVersion)
    {
        if (preg_match('/^(\d+)\.(\d+)/', (string)$serverVersion, $parts)) {
            $version = (int)$parts[1] * 100 + (int)$parts[2];
            if (stripos($serverVersion, 'mariadb') !== false) {
                if ($version >= 1010) {
                    return 'utf8mb4_uca1400_ai_ci';
                }
            } elseif ($version >= 800) {
                return 'utf8mb4_0900_ai_ci';
            }
        }
        return 'utf8mb4_unicode_520_ci';
    }

    /**
     * @param bool $installed
     * @param bool $available
     * @param bool $mayCreate
     * @return string|null Why pg_trgm cannot be had, or null when it can.
     */
    public static function pgTrgmProblem($installed, $available, $mayCreate)
    {
        if ($installed) {
            return null;
        }
        if (!$available) {
            return 'The PostgreSQL extension pg_trgm is not installed on the database server. Install the PostgreSQL contrib package (postgresql-contrib on RHEL; Debian and Ubuntu ship it with the server) and run the update again. See docs/CONFIG.postgresql.md.';
        }
        if (!$mayCreate) {
            return 'The database user may not create the PostgreSQL extension pg_trgm. Grant it CREATE on the database (GRANT CREATE ON DATABASE <database> TO <user>;), or have a superuser run CREATE EXTENSION pg_trgm; in the MISP database, then run the update again. See docs/CONFIG.postgresql.md.';
        }
        return null;
    }
}
