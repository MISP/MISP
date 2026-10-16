<?php

App::uses('AbstractMigration', 'Migration');
App::uses('TableConverger', 'Migration');
require_once __DIR__ . '/Migration_20261016_180337_schema_v3_attribute_values.php';

/**
 * Create the attribute_values dictionary
 */
class Migration_20261003_092429_create_attribute_values extends AbstractMigration
{
    public $description = 'Create the attribute_values dictionary';

    public $requiresLogout = false;

    const TABLE = 'attribute_values';

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
     * Created at the 3.0 target, which its schema v3 migration then finds
     * met. Converged, so a retry after a partial failure declares only what
     * is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        TableConverger::converge(
            $inspector,
            $schema,
            self::TABLE,
            Migration_20261016_180337_schema_v3_attribute_values::TARGET,
            TableConverger::session($inspector)
        );
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
