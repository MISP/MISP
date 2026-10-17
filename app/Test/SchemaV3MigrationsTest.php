<?php
/**
 * The schema v3 migrations: one TableMigration for every table the 3.0
 * schema has, each target a fixed point of itself on every server, run in
 * the order the upgrade needs.
 */

require_once __DIR__ . '/TableConvergerTest.php';
require_once APPLIBS . 'Migration/TagNameMerger.php';
require_once APPLIBS . 'Tools/CorrelationRemapTool.php';

use PHPUnit\Framework\TestCase;

class SchemaV3MigrationsTest extends TestCase
{
    const SLUG = 'schema_v3_';

    /** The two that are not a table's, first. */
    const LEAD = array('schema_v3_database_collation', 'schema_v3_drop_tasks');

    /** Emptied and created at the target, right after the lead, to free their disk early. */
    const RECREATED = array('default_correlations', 'no_acl_correlations', 'over_correlating_values', 'fuzzy_correlate_ssdeep');

    /** The biggest tables, last. */
    const TAIL = array('sightings', 'object_references', 'objects', 'attribute_values', 'attribute_tags', 'attributes');

    /** Dropped by the migration that once converged them, which keeps its place. */
    const DROPPED = array('correlations');

    /** @var array|null id => migration, everything on disk, in id order */
    private static $migrations;

    /**
     * @return array id => migration
     */
    private static function migrations()
    {
        if (self::$migrations === null) {
            self::$migrations = array();
            foreach (glob(APPLIBS . 'Migration/Migrations/' . AbstractMigration::CLASS_PREFIX . '*.php') as $file) {
                $class = basename($file, '.php');
                require_once $file;
                self::$migrations[AbstractMigration::idFromClassName($class)] = new $class();
            }
            ksort(self::$migrations);
        }
        return self::$migrations;
    }

    /**
     * @param string $id
     * @return string
     */
    private static function slug($id)
    {
        return substr($id, strlen('20261016_180200_'));
    }

    /**
     * @return array id => migration of the set, in id order
     */
    private static function set()
    {
        $set = array();
        foreach (self::migrations() as $id => $migration) {
            if (strpos(self::slug($id), self::SLUG) === 0) {
                $set[$id] = $migration;
            }
        }
        return $set;
    }

    /**
     * @return array table => migration
     */
    private static function tableMigrations()
    {
        $tables = array();
        foreach (self::set() as $migration) {
            if ($migration instanceof TableMigration) {
                $tables[$migration::TABLE] = $migration;
            }
        }
        return $tables;
    }

    public function testTheSetRunsInOneBlockInItsOrder()
    {
        $set = self::set();
        $ids = array_keys($set);
        $this->assertGreaterThan(count(self::LEAD) + count(self::RECREATED) + count(self::TAIL), count($ids));

        $first = DateTime::createFromFormat('Ymd_His', substr($ids[0], 0, 15));
        foreach ($ids as $n => $id) {
            $at = clone $first;
            $this->assertSame($at->modify("+$n seconds")->format('Ymd_His'), substr($id, 0, 15), "$id is not one second after the one before");
        }
        foreach (array_keys(self::migrations()) as $id) {
            if (!isset($set[$id])) {
                $this->assertTrue($id < $ids[0] || $id > end($ids), "$id runs in the middle of the set");
            }
        }

        $this->assertSame(self::LEAD, array_map(array(self::class, 'slug'), array_slice($ids, 0, count(self::LEAD))));
        $tables = array();
        foreach (array_slice($set, count(self::LEAD)) as $id => $migration) {
            $table = substr(self::slug($id), strlen(self::SLUG));
            if (in_array($table, self::DROPPED, true)) {
                $this->assertNotInstanceOf('TableMigration', $migration, $id);
                $this->assertSame('Schema modernisation: drop ' . $table, $migration->description);
                continue;
            }
            $this->assertInstanceOf('TableMigration', $migration, $id);
            $this->assertSame(self::SLUG . $migration::TABLE, self::slug($id));
            $this->assertSame('Schema modernisation: ' . $migration::TABLE, $migration->description);
            $this->assertSame(in_array($migration::TABLE, self::RECREATED, true), $migration::RECREATE, $id);
            $tables[] = $migration::TABLE;
        }
        $this->assertSame(self::RECREATED, array_slice($tables, 0, count(self::RECREATED)));
        $this->assertSame(self::TAIL, array_slice($tables, -count(self::TAIL)));
        $this->assertSame(array_values(array_unique($tables)), $tables, 'a table has two migrations');
    }

    /**
     * The tables a fresh install has once every earlier migration has run,
     * read offline: the install baseline's, then what each migration's up()
     * creates, drops or renames, played against that list.
     */
    public function testEveryTableOfTheSchemaHasOneMigration()
    {
        preg_match_all('/CREATE TABLE (?:IF NOT EXISTS )?`(\w+)`/', file_get_contents(APPLIBS . '../../INSTALL/MYSQL.sql'), $m);
        $tables = array_fill_keys($m[1], true);
        $first = key(self::set());
        foreach (self::migrations() as $id => $migration) {
            if ($id >= $first) {
                break;
            }
            $schema = array();
            foreach (array_keys($tables) as $table) {
                $schema[$table] = array('columns' => array());
            }
            $migration->setSchemaInspector(new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, $schema));
            $builder = new SchemaBuilder(new MysqlGrammar(new MigrationTestMysqlExtended(TableConvergerTest::MARIADB)));
            $migration->up($builder);
            foreach ($builder->operations() as $operation) {
                $arguments = $operation['arguments'];
                if ($operation['operation'] === 'createTable') {
                    $tables[$arguments[0]] = true;
                } elseif ($operation['operation'] === 'dropTable') {
                    unset($tables[$arguments[0]]);
                } elseif ($operation['operation'] === 'renameTable') {
                    unset($tables[$arguments[0]]);
                    $tables[$arguments[1]] = true;
                }
            }
        }
        $expected = array_diff(array_keys($tables), SchemaTargetGenerator::EXCLUDED_TABLES);
        sort($expected);
        $covered = array_keys(self::tableMigrations());
        sort($covered);
        $this->assertSame($expected, $covered);
    }

    /**
     * A dropped table goes where it is there, and its migration is a no-op
     * where it is not, so a re-run or a fresh 3.0 install finds nothing to do.
     */
    public function testEveryDroppedTableIsDroppedOnlyWhereItIsThere()
    {
        $dropped = array();
        foreach (self::set() as $id => $migration) {
            $table = substr(self::slug($id), strlen(self::SLUG));
            if (!in_array($table, self::DROPPED, true)) {
                continue;
            }
            $this->assertContains($table, SchemaTargetGenerator::EXCLUDED_TABLES);
            foreach (array(true, false) as $present) {
                $migration->setSchemaInspector(new MigrationTestInspector(
                    SchemaInspector::FLAVOUR_MYSQL,
                    $present ? array($table => array('columns' => array())) : array()
                ));
                $builder = new SchemaBuilder(new MysqlGrammar(new MigrationTestMysqlExtended(TableConvergerTest::MARIADB)));
                $migration->up($builder);
                $this->assertSame($present ? array("DROP TABLE `$table`;") : array(), $builder->toSql(), "$table, present: " . json_encode($present));
            }
            $dropped[] = $table;
        }
        $this->assertSame(self::DROPPED, $dropped);
    }

    /**
     * Each target read back from a table built to it plans nothing, on every
     * server: the converge has a resting point.
     */
    public function testEveryTargetIsItsOwnFixedPoint()
    {
        foreach (self::tableMigrations() as $table => $migration) {
            foreach (array(TableConvergerTest::MARIADB, TableConvergerTest::MYSQL) as $version) {
                $inspector = new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, array(
                    $table => array('definition' => TableConvergerTest::mysqlLive($migration::TARGET, $version)),
                ));
                $inspector->version = $version;
                $plan = TableConverger::plan($inspector, $table, $migration::TARGET);
                $this->assertTrue(TableConverger::isEmpty($plan), "$table on $version: " . json_encode($plan));
            }
            $inspector = new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL, array(
                $table => array('definition' => TableConvergerTest::pgsqlLive($table, $migration::TARGET)),
            ));
            $plan = TableConverger::plan($inspector, $table, $migration::TARGET);
            $this->assertTrue(TableConverger::isEmpty($plan), "$table on PostgreSQL: " . json_encode($plan));
        }
    }

    /**
     * Where the table is missing, the target is created on every engine.
     */
    public function testEveryTargetRendersAsACreationOnEveryEngine()
    {
        $grammars = array(
            'MariaDB' => new MysqlGrammar(new MigrationTestMysqlExtended(TableConvergerTest::MARIADB)),
            'MySQL' => new MysqlGrammar(new MigrationTestMysqlExtended(TableConvergerTest::MYSQL)),
            'PostgreSQL' => new PostgresGrammar(new MigrationTestPostgres()),
        );
        foreach (self::tableMigrations() as $table => $migration) {
            $schema = new SchemaBuilder($grammars['MariaDB']);
            TableConverger::converge(new MigrationTestInspector(), $schema, $table, $migration::TARGET);
            foreach ($grammars as $engine => $grammar) {
                $created = preg_grep('/^CREATE TABLE /', $schema->toSql($grammar));
                $this->assertCount(1, $created, "$table on $engine");
                $this->assertStringContainsString(
                    $engine === 'PostgreSQL' ? "\"$table\"" : "`$table`",
                    reset($created),
                    "$table on $engine"
                );
            }
        }
    }
}
