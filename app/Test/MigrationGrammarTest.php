<?php
/**
 * Grammar rendering tests (PRD section 9.1) - the flavour-agnostic half of the
 * migration DSL, asserted at the SQL-string level.
 *
 * There is no PostgreSQL instance to run against yet, so this is where the
 * PostgreSQL grammar is actually verified: every operation is rendered for both
 * engines and compared against the statement each one is supposed to produce.
 *
 * Three things are being pinned here.
 *
 * 1. **The borrowed half behaves as assumed.** The whole design rests on
 *    DboSource::buildColumn() plus the drivers' own $columns and
 *    $fieldParameters maps doing the type and hint work - boolean becoming
 *    tinyint(1) here and boolean there, collate and unsigned appearing on one
 *    engine and vanishing on the other, with no branch of ours involved. If that
 *    assumption is wrong the design is wrong, so it is asserted rather than
 *    trusted.
 *
 * 2. **The parts CakePHP has no answer for.** Positional `after`, prefix-length
 *    indexes, FULLTEXT, RENAME COLUMN, RENAME TABLE, index DDL, and the
 *    mediumtext / longtext / varbinary types Cake's maps are missing.
 *
 * 3. **The refusals.** enum, an unknown type and a PostgreSQL FULLTEXT are hard
 *    errors with a message naming the way out, because a migration that quietly
 *    renders to nothing on one engine is the failure this subsystem exists to
 *    end.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class MigrationGrammarTest extends TestCase
{
    /** @var MysqlGrammar */
    private $mysql;

    /** @var PostgresGrammar */
    private $pgsql;

    protected function setUp(): void
    {
        $this->mysql = new MysqlGrammar(new MigrationTestMysql());
        $this->pgsql = new PostgresGrammar(new MigrationTestPostgres());
    }

    // ------------------------------------------------------------- selection

    public function testForDataSourcePicksTheGrammarByDriver()
    {
        $this->assertInstanceOf(
            'MysqlGrammar',
            AbstractGrammar::forDataSource(new MigrationTestMysql())
        );
        $this->assertInstanceOf(
            'PostgresGrammar',
            AbstractGrammar::forDataSource(new MigrationTestPostgres())
        );
    }

    /**
     * MISP never runs vanilla Mysql - database.default.php offers MysqlExtended
     * and three subclasses of it, so that is what a migration will really be
     * rendered against. It classifies as MySQL, and renders the same column;
     * the only difference is the literal, because MysqlExtended::value()
     * returns integers unquoted where Cake's quotes them.
     */
    public function testTheDriverMispActuallyRunsRendersAnEquivalentColumn()
    {
        $db = new MigrationTestMysqlExtended();
        $grammar = AbstractGrammar::forDataSource($db);
        $this->assertInstanceOf('MysqlGrammar', $grammar);
        $this->assertSame(AbstractGrammar::FLAVOUR_MYSQL, $grammar->flavour());

        $this->assertSame(
            array('ALTER TABLE `event_templates` ADD `exposed` tinyint(1) DEFAULT 0 NOT NULL AFTER `misp_default`;'),
            $grammar->addColumn('event_templates', 'exposed', 'boolean', array(
                'null' => false,
                'default' => 0,
                'after' => 'misp_default',
            ))
        );
    }

    /**
     * The offline path `migrationApply --dry-run` renders its second flavour
     * through.
     *
     * Not a convenience: PostgresGrammar needs a Postgres datasource for its
     * type map and quoting, and constructing one throws unless pdo_pgsql is
     * loaded. It is loaded on essentially no MISP host, so without this the one
     * half of a dry run that nobody can otherwise check is the half that would
     * never print.
     */
    public function testOfflineBuildsAGrammarWithNoConnection()
    {
        $this->assertInstanceOf('MysqlGrammar', AbstractGrammar::offline(AbstractGrammar::FLAVOUR_MYSQL));
        $this->assertInstanceOf('PostgresGrammar', AbstractGrammar::offline(AbstractGrammar::FLAVOUR_PGSQL));
    }

    /**
     * The offline datasources are the real drivers with the constructor skipped,
     * not stand-ins for them. That is what makes what a dry run prints worth
     * reading: the type map, the field parameters and the identifier quoting are
     * the engine's own, and the connection is the only thing missing.
     *
     * MysqlExtended rather than Mysql on purpose - MISP ships four datasources
     * and all of them are MysqlExtended or a subclass, so that is the rendering
     * an author needs to see.
     */
    public function testTheOfflineDataSourcesAreTheRealDrivers()
    {
        $this->assertInstanceOf(
            'MysqlExtended',
            AbstractGrammar::offline(AbstractGrammar::FLAVOUR_MYSQL)->getDataSource()
        );
        $this->assertInstanceOf(
            'Postgres',
            AbstractGrammar::offline(AbstractGrammar::FLAVOUR_PGSQL)->getDataSource()
        );
    }

    /**
     * And rendering through them works end to end with nothing connected -
     * every piece the drivers need, from the $columns map to the quoting of a
     * default, is reachable without a socket.
     */
    public function testOfflineRendersWithoutAConnection()
    {
        $column = array('null' => false, 'default' => 0, 'after' => 'misp_default');

        $this->assertSame(
            array('ALTER TABLE `event_templates` ADD `exposed` tinyint(1) DEFAULT 0 NOT NULL AFTER `misp_default`;'),
            AbstractGrammar::offline(AbstractGrammar::FLAVOUR_MYSQL)
                ->addColumn('event_templates', 'exposed', 'boolean', $column)
        );
        $this->assertSame(
            array('ALTER TABLE "event_templates" ADD "exposed" boolean DEFAULT \'FALSE\' NOT NULL;'),
            AbstractGrammar::offline(AbstractGrammar::FLAVOUR_PGSQL)
                ->addColumn('event_templates', 'exposed', 'boolean', $column)
        );
    }

    public function testOfflineRejectsAFlavourWithNoGrammar()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('sqlite');
        AbstractGrammar::offline('sqlite');
    }

    /**
     * flavours() is what the dry run iterates, so its contents decide which
     * engines an author is shown - a flavour missing from it is a flavour
     * nobody checks before shipping.
     */
    public function testFlavoursListsEveryRenderableEngine()
    {
        $this->assertSame(
            array(AbstractGrammar::FLAVOUR_MYSQL, AbstractGrammar::FLAVOUR_PGSQL),
            AbstractGrammar::flavours()
        );
        foreach (AbstractGrammar::flavours() as $flavour) {
            $this->assertSame($flavour, AbstractGrammar::offline($flavour)->flavour());
        }
    }

    public function testFlavourNames()
    {
        $this->assertSame(AbstractGrammar::FLAVOUR_MYSQL, $this->mysql->flavour());
        $this->assertSame(AbstractGrammar::FLAVOUR_PGSQL, $this->pgsql->flavour());
    }

    // ------------------------------------------------------------ addColumn

    /**
     * The PRD's worked example: legacy case 157, as the new system writes it.
     * boolean -> tinyint(1) vs boolean, and AFTER honoured vs dropped.
     */
    public function testAddBooleanColumnWithPosition()
    {
        $options = array('null' => false, 'default' => 0, 'after' => 'misp_default');

        $this->assertSame(
            array("ALTER TABLE `event_templates` ADD `exposed` tinyint(1) DEFAULT '0' NOT NULL AFTER `misp_default`;"),
            $this->mysql->addColumn('event_templates', 'exposed', 'boolean', $options)
        );
        $this->assertSame(
            array('ALTER TABLE "event_templates" ADD "exposed" boolean DEFAULT \'FALSE\' NOT NULL;'),
            $this->pgsql->addColumn('event_templates', 'exposed', 'boolean', $options)
        );
    }

    /**
     * A key column added on its own carries its constraint: MySQL refuses an
     * AUTO_INCREMENT column that is not made a key in the same statement, and
     * PostgreSQL accepts the same spelling. FIRST is MySQL's, and dropped with
     * a note on PostgreSQL like AFTER is.
     */
    public function testAddAPrimaryKeyColumnToAnExistingTable()
    {
        $this->assertSame(
            array('ALTER TABLE `bruteforces` ADD `id` int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;'),
            $this->mysql->addColumn('bruteforces', 'id', 'primary_key', array('first' => true))
        );
        $this->assertSame(
            array('ALTER TABLE "bruteforces" ADD "id" serial NOT NULL PRIMARY KEY;'),
            $this->pgsql->addColumn('bruteforces', 'id', 'primary_key', array('first' => true))
        );
        $hints = $this->pgsql->takeDroppedHints();
        $this->assertCount(1, $hints);
        $this->assertStringContainsString('FIRST', $hints[0]);

        $this->assertSame(
            array('ALTER TABLE `t` ADD `x` int(11) DEFAULT 0 NOT NULL;'),
            $this->mysql->addColumn('t', 'x', 'integer', array('null' => false, 'default' => 0)),
            'an ordinary column carries no key clause'
        );
    }

    /**
     * Dropping the key leaves the columns. PostgreSQL drops it by its default
     * constraint name, which is the one every baseline-created table has.
     */
    public function testDropPrimaryKey()
    {
        $this->assertSame(
            array('ALTER TABLE `system_settings` DROP PRIMARY KEY;'),
            $this->mysql->dropPrimaryKey('system_settings')
        );
        $this->assertSame(
            array('ALTER TABLE "system_settings" DROP CONSTRAINT "system_settings_pkey";'),
            $this->pgsql->dropPrimaryKey('system_settings')
        );
    }

    /**
     * charset, collate and unsigned are declared in Mysql::$fieldParameters and
     * nowhere in Postgres, so one engine emits them and the other drops them
     * with no branching in the grammars at all.
     */
    public function testStorageHintsAreEmittedOnMysqlAndDroppedOnPostgres()
    {
        $string = array('length' => 40, 'null' => false, 'charset' => 'ascii', 'collate' => 'ascii_general_ci');
        $this->assertSame(
            array('ALTER TABLE `collections` ADD `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL;'),
            $this->mysql->addColumn('collections', 'uuid', 'string', $string)
        );
        $this->assertSame(
            array('ALTER TABLE "collections" ADD "uuid" varchar(40) NOT NULL;'),
            $this->pgsql->addColumn('collections', 'uuid', 'string', $string)
        );

        $unsigned = array('null' => false, 'unsigned' => true);
        $this->assertSame(
            array('ALTER TABLE `collections` ADD `org_id` int(11) UNSIGNED NOT NULL;'),
            $this->mysql->addColumn('collections', 'org_id', 'integer', $unsigned)
        );
        $this->assertSame(
            array('ALTER TABLE "collections" ADD "org_id" integer NOT NULL;'),
            $this->pgsql->addColumn('collections', 'org_id', 'integer', $unsigned)
        );
    }

    /**
     * The three types the MISP schema uses that Cake's maps do not define.
     * mediumtext and longtext are MySQL storage tiers of one logical type, so
     * both collapse to text on PostgreSQL; varbinary becomes bytea.
     */
    public function testExtendedTypesRenderOnBothEngines()
    {
        $this->assertSame(
            array('ALTER TABLE `collections` ADD `description` mediumtext DEFAULT NULL;'),
            $this->mysql->addColumn('collections', 'description', 'mediumtext', array('null' => true))
        );
        $this->assertSame(
            array('ALTER TABLE "collections" ADD "description" text DEFAULT NULL;'),
            $this->pgsql->addColumn('collections', 'description', 'mediumtext', array('null' => true))
        );

        $this->assertSame(
            array('ALTER TABLE `logs` ADD `payload` longtext DEFAULT NULL;'),
            $this->mysql->addColumn('logs', 'payload', 'longtext', array('null' => true))
        );
        $this->assertSame(
            array('ALTER TABLE "logs" ADD "payload" text DEFAULT NULL;'),
            $this->pgsql->addColumn('logs', 'payload', 'longtext', array('null' => true))
        );

        $this->assertSame(
            array('ALTER TABLE `attachments` ADD `digest` varbinary(64) DEFAULT NULL;'),
            $this->mysql->addColumn('attachments', 'digest', 'varbinary', array('length' => 64, 'null' => true))
        );
        $this->assertSame(
            array('ALTER TABLE "attachments" ADD "digest" bytea DEFAULT NULL;'),
            $this->pgsql->addColumn('attachments', 'digest', 'varbinary', array('length' => 64, 'null' => true))
        );
    }

    /**
     * Cake's Postgres map declares biginteger with limit 20, which renders as
     * bigint(20) - a PostgreSQL syntax error. PostgresGrammar corrects the map
     * rather than passing the error through. MySQL keeps its display width.
     */
    public function testPostgresDropsLengthModifiersItsTypesCannotCarry()
    {
        $this->assertSame(
            array('ALTER TABLE `jobs` ADD `bytes` bigint(20) NOT NULL;'),
            $this->mysql->addColumn('jobs', 'bytes', 'biginteger', array('null' => false))
        );
        $this->assertSame(
            array('ALTER TABLE "jobs" ADD "bytes" bigint NOT NULL;'),
            $this->pgsql->addColumn('jobs', 'bytes', 'biginteger', array('null' => false))
        );
    }

    /**
     * The same correction for a length the migration author supplied - restating
     * a MySQL display width must not produce integer(11) on PostgreSQL.
     */
    public function testPostgresDropsAuthorSuppliedLengthOnTypesThatCannotCarryOne()
    {
        $spec = array('length' => 11, 'null' => false, 'default' => 0);
        $this->assertSame(
            array('ALTER TABLE `events` ADD `count` int(11) DEFAULT 0 NOT NULL;'),
            $this->mysql->addColumn('events', 'count', 'integer', $spec)
        );
        $this->assertSame(
            array('ALTER TABLE "events" ADD "count" integer DEFAULT 0 NOT NULL;'),
            $this->pgsql->addColumn('events', 'count', 'integer', $spec)
        );
    }

    // --------------------------------------------------------- changeColumn

    /**
     * MySQL carries type, nullability and default in one MODIFY. PostgreSQL has
     * to split them, which is why every grammar method returns an array.
     */
    public function testChangeColumnIsOneStatementOnMysqlAndThreeOnPostgres()
    {
        $options = array('null' => false, 'default' => 0);

        $this->assertSame(
            array('ALTER TABLE `galaxies` MODIFY `distribution` tinyint(4) DEFAULT 0 NOT NULL;'),
            $this->mysql->changeColumn('galaxies', 'distribution', 'tinyinteger', $options)
        );
        $this->assertSame(
            array(
                'ALTER TABLE "galaxies" ALTER COLUMN "distribution" TYPE smallint USING "distribution"::smallint;',
                'ALTER TABLE "galaxies" ALTER COLUMN "distribution" SET NOT NULL;',
                'ALTER TABLE "galaxies" ALTER COLUMN "distribution" SET DEFAULT 0;',
            ),
            $this->pgsql->changeColumn('galaxies', 'distribution', 'tinyinteger', $options)
        );
    }

    public function testChangeColumnDropsNotNullAndDefaultWhenAskedTo()
    {
        $options = array('null' => true, 'default' => null);
        $this->assertSame(
            array(
                'ALTER TABLE "galaxies" ALTER COLUMN "x" TYPE varchar(255) USING "x"::varchar(255);',
                'ALTER TABLE "galaxies" ALTER COLUMN "x" DROP NOT NULL;',
                'ALTER TABLE "galaxies" ALTER COLUMN "x" DROP DEFAULT;',
            ),
            $this->pgsql->changeColumn('galaxies', 'x', 'string', $options)
        );
        $this->assertSame(
            array('ALTER TABLE `galaxies` MODIFY `x` varchar(255) DEFAULT NULL;'),
            $this->mysql->changeColumn('galaxies', 'x', 'string', $options)
        );
    }

    /**
     * The trap this guard exists for. Left to itself, MySQL's MODIFY would drop
     * a NOT NULL the caller never mentioned while PostgreSQL kept it, so the two
     * engines would quietly end up with different columns. Rather than emulate
     * one engine's behaviour on the other - which would mean reading the live
     * schema mid-render - the DSL makes the caller say.
     */
    public function testRedefiningAColumnRequiresNullAndDefaultToBeStated()
    {
        foreach (array($this->mysql, $this->pgsql) as $grammar) {
            try {
                $grammar->changeColumn('galaxies', 'x', 'string');
                $this->fail('an incomplete redefinition should not render on ' . $grammar->flavour());
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('null', $e->getMessage());
                $this->assertStringContainsString('default', $e->getMessage());
            }

            try {
                $grammar->changeColumn('galaxies', 'x', 'string', array('null' => false));
                $this->fail('a half-stated redefinition should not render on ' . $grammar->flavour());
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('default', $e->getMessage());
            }

            try {
                $grammar->renameColumn('galaxies', 'a', 'b', 'string', array('null' => false));
                $this->fail('renameColumn redefines too, on ' . $grammar->flavour());
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('default', $e->getMessage());
            }
        }
    }

    // --------------------------------------------------------- renameColumn

    /**
     * MySQL's CHANGE renames and redefines in one statement; PostgreSQL renames
     * and then restates the definition, so both engines end in the same place.
     * That is why the DSL asks for a type on a rename.
     */
    public function testRenameColumn()
    {
        $options = array('length' => 255, 'null' => false, 'default' => null);

        $this->assertSame(
            array('ALTER TABLE `servers` CHANGE `old_name` `new_name` varchar(255) NOT NULL;'),
            $this->mysql->renameColumn('servers', 'old_name', 'new_name', 'string', $options)
        );
        $this->assertSame(
            array(
                'ALTER TABLE "servers" RENAME COLUMN "old_name" TO "new_name";',
                'ALTER TABLE "servers" ALTER COLUMN "new_name" TYPE varchar(255) USING "new_name"::varchar(255);',
                'ALTER TABLE "servers" ALTER COLUMN "new_name" SET NOT NULL;',
                'ALTER TABLE "servers" ALTER COLUMN "new_name" DROP DEFAULT;',
            ),
            $this->pgsql->renameColumn('servers', 'old_name', 'new_name', 'string', $options)
        );
    }

    public function testDropColumnIsIdenticalBarQuoting()
    {
        $this->assertSame(
            array('ALTER TABLE `servers` DROP COLUMN `junk`;'),
            $this->mysql->dropColumn('servers', 'junk')
        );
        $this->assertSame(
            array('ALTER TABLE "servers" DROP COLUMN "junk";'),
            $this->pgsql->dropColumn('servers', 'junk')
        );
    }

    // --------------------------------------------------------------- indexes

    public function testAddIndex()
    {
        $this->assertSame(
            array('ALTER TABLE `event_templates` ADD INDEX `exposed` (`exposed`);'),
            $this->mysql->addIndex('event_templates', 'exposed')
        );
        $this->assertSame(
            array('CREATE INDEX "idx_event_templates_exposed" ON "event_templates" ("exposed");'),
            $this->pgsql->addIndex('event_templates', 'exposed')
        );
    }

    public function testAddUniqueIndex()
    {
        $this->assertSame(
            array('ALTER TABLE `collections` ADD UNIQUE INDEX `uuid` (`uuid`);'),
            $this->mysql->addIndex('collections', 'uuid', array('unique' => true))
        );
        $this->assertSame(
            array('CREATE UNIQUE INDEX "idx_collections_uuid" ON "collections" ("uuid");'),
            $this->pgsql->addIndex('collections', 'uuid', array('unique' => true))
        );
    }

    public function testAddCompositeIndexKeepsColumnOrder()
    {
        $columns = array('event_id', 'object_id');
        $this->assertSame(
            array('ALTER TABLE `objects` ADD INDEX `lookup` (`event_id`, `object_id`);'),
            $this->mysql->addIndex('objects', $columns, array('name' => 'lookup'))
        );
        $this->assertSame(
            array('CREATE INDEX "idx_objects_lookup" ON "objects" ("event_id", "object_id");'),
            $this->pgsql->addIndex('objects', $columns, array('name' => 'lookup'))
        );
    }

    /**
     * A prefix length is not a cosmetic hint - dropping it changes what the
     * index indexes - so PostgreSQL records the loss instead of swallowing it.
     */
    public function testPrefixLengthIsHonouredOnMysqlAndReportedWhenDropped()
    {
        $this->assertSame(
            array('ALTER TABLE `objects` ADD INDEX `meta-category` (`meta-category`(16));'),
            $this->mysql->addIndex('objects', 'meta-category', array('length' => 16))
        );
        $this->assertSame(array(), $this->mysql->takeDroppedHints());

        $this->assertSame(
            array('CREATE INDEX "idx_objects_meta-category" ON "objects" ("meta-category");'),
            $this->pgsql->addIndex('objects', 'meta-category', array('length' => 16))
        );
        $dropped = $this->pgsql->takeDroppedHints();
        $this->assertCount(1, $dropped);
        $this->assertStringContainsString('Prefix length dropped', $dropped[0]);
        // Taking them clears them.
        $this->assertSame(array(), $this->pgsql->takeDroppedHints());
    }

    public function testCompositePrefixLengthAppliesPerColumn()
    {
        $this->assertSame(
            array('ALTER TABLE `attributes` ADD INDEX `pair` (`value1`(32), `type`);'),
            $this->mysql->addIndex(
                'attributes',
                array('value1', 'type'),
                array('name' => 'pair', 'length' => array('value1' => 32))
            )
        );
    }

    public function testPositionalHintIsReportedWhenDroppedOnPostgres()
    {
        $this->pgsql->addColumn('t', 'c', 'integer', array('after' => 'b'));
        $dropped = $this->pgsql->takeDroppedHints();
        $this->assertCount(1, $dropped);
        $this->assertStringContainsString('Column position dropped', $dropped[0]);
    }

    public function testDropIndexMirrorsTheNameAddIndexWouldHaveUsed()
    {
        $this->assertSame(
            array('ALTER TABLE `collections` DROP INDEX `uuid`;'),
            $this->mysql->dropIndex('collections', 'uuid')
        );
        $this->assertSame(
            array('DROP INDEX "idx_collections_uuid";'),
            $this->pgsql->dropIndex('collections', 'uuid')
        );
    }

    /**
     * MySQL index names only have to be unique within their table; PostgreSQL's
     * share one namespace per schema. So an explicit name is honoured verbatim
     * on MySQL and prefixed on PostgreSQL - and a name that is already prefixed
     * is left alone, so addIndex() and dropIndex() agree whichever form the
     * migration used.
     */
    public function testIndexNaming()
    {
        $this->assertSame('exposed', $this->mysql->indexName('event_templates', 'exposed'));
        $this->assertSame('a_b', $this->mysql->indexName('t', array('a', 'b')));
        $this->assertSame('custom', $this->mysql->indexName('t', 'a', array('name' => 'custom')));

        $this->assertSame('idx_event_templates_exposed', $this->pgsql->indexName('event_templates', 'exposed'));
        $this->assertSame('idx_t_a_b', $this->pgsql->indexName('t', array('a', 'b')));
        $this->assertSame('idx_t_custom', $this->pgsql->indexName('t', 'a', array('name' => 'custom')));
        $this->assertSame('idx_t_custom', $this->pgsql->indexName('t', 'a', array('name' => 'idx_t_custom')));
    }

    public function testFulltextRendersOnMysqlAndIsRejectedOnPostgres()
    {
        $options = array('fulltext' => true, 'name' => 'value_ft');
        $this->assertSame(
            array('ALTER TABLE `attributes` ADD FULLTEXT INDEX `value_ft` (`value1`, `value2`);'),
            $this->mysql->addIndex('attributes', array('value1', 'value2'), $options)
        );

        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('rawSql()');
        $this->pgsql->addIndex('attributes', array('value1', 'value2'), $options);
    }

    // ---------------------------------------------------------------- tables

    /**
     * The PRD's second worked example. Note what differs: PostgreSQL takes the
     * indexes out of the table body into statements of their own, and drops the
     * ENGINE / CHARSET / COLLATE suffix - the latter not by anything here, but
     * because Cake's Postgres driver declares no $tableParameters at all.
     */
    public function testCreateTable()
    {
        $columns = array(
            'id' => array('type' => 'primary_key'),
            'collection_id' => array('type' => 'integer', 'null' => false, 'unsigned' => true),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => 'ascii_general_ci'),
            'created' => array('type' => 'datetime', 'null' => false),
        );
        $options = array(
            'indexes' => array(
                'collection_id' => array(),
                'uuid' => array('unique' => true),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collate' => 'utf8mb4_unicode_ci',
        );

        $expectedMysql = "CREATE TABLE `collection_shares` (\n"
            . "    `id` int(11) NOT NULL AUTO_INCREMENT,\n"
            . "    `collection_id` int(11) UNSIGNED NOT NULL,\n"
            . "    `uuid` varchar(40) COLLATE ascii_general_ci NOT NULL,\n"
            . "    `created` datetime NOT NULL,\n"
            . "    PRIMARY KEY (`id`),\n"
            . "    INDEX `collection_id` (`collection_id`),\n"
            . "    UNIQUE INDEX `uuid` (`uuid`)\n"
            . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
        $this->assertSame(
            array($expectedMysql),
            $this->mysql->createTable('collection_shares', $columns, $options)
        );

        $expectedPgsql = "CREATE TABLE \"collection_shares\" (\n"
            . "    \"id\" serial NOT NULL,\n"
            . "    \"collection_id\" integer NOT NULL,\n"
            . "    \"uuid\" varchar(40) NOT NULL,\n"
            . "    \"created\" timestamp NOT NULL,\n"
            . "    PRIMARY KEY (\"id\")\n"
            . ");";
        $this->assertSame(
            array(
                $expectedPgsql,
                'CREATE INDEX "idx_collection_shares_collection_id" ON "collection_shares" ("collection_id");',
                'CREATE UNIQUE INDEX "idx_collection_shares_uuid" ON "collection_shares" ("uuid");',
            ),
            $this->pgsql->createTable('collection_shares', $columns, $options)
        );
    }

    /**
     * Cake's map entry for `primary_key` holds only the trailing modifier - the
     * driver expects an integer column flagged primary. Passing the DSL type
     * through verbatim would emit a column with no type at all, so the grammar
     * folds it.
     */
    public function testPrimaryKeyIsFoldedIntoAnIntegerColumn()
    {
        $columns = array('id' => array('type' => 'primary_key'));
        $this->assertStringContainsString(
            '`id` int(11) NOT NULL AUTO_INCREMENT',
            $this->mysql->createTable('t', $columns)[0]
        );
        $this->assertStringContainsString(
            '"id" serial NOT NULL',
            $this->pgsql->createTable('t', $columns)[0]
        );
    }

    public function testRenameAndDropTable()
    {
        $this->assertSame(
            array('RENAME TABLE `old_t` TO `new_t`;'),
            $this->mysql->renameTable('old_t', 'new_t')
        );
        $this->assertSame(
            array('ALTER TABLE "old_t" RENAME TO "new_t";'),
            $this->pgsql->renameTable('old_t', 'new_t')
        );

        $this->assertSame(array('DROP TABLE `gone`;'), $this->mysql->dropTable('gone'));
        $this->assertSame(array('DROP TABLE "gone";'), $this->pgsql->dropTable('gone'));
    }

    // -------------------------------------------------------------- refusals

    public function testEnumIsRejectedOnBothEngines()
    {
        foreach (array($this->mysql, $this->pgsql) as $grammar) {
            try {
                $grammar->addColumn('t', 'e', 'enum', array());
                $this->fail('enum should not render on ' . $grammar->flavour());
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('rawSql()', $e->getMessage());
            }
        }
    }

    public function testUnknownTypeIsRejectedAndTheMessageListsWhatIsAvailable()
    {
        try {
            $this->mysql->addColumn('t', 'x', 'jsonb', array());
            $this->fail('an unknown type should not render');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('jsonb', $e->getMessage());
            $this->assertStringContainsString('mediumtext', $e->getMessage());
            $this->assertStringContainsString('rawSql()', $e->getMessage());
        }
    }

    public function testColumnWithoutATypeIsRejected()
    {
        $this->expectException('InvalidArgumentException');
        $this->mysql->createTable('t', array('c' => array()));
    }

    // ------------------------------------------------------ the type-map swap

    /**
     * The extension is swapped into the public $db->columns for the duration of
     * a buildColumn() call, so it must come back exactly as it was - including
     * when rendering throws. Model::schema() and value() read that same property.
     */
    public function testTheTypeMapSwapIsRestored()
    {
        foreach (array($this->mysql, $this->pgsql) as $grammar) {
            $db = $grammar->getDataSource();
            $before = $db->columns;

            $grammar->addColumn('t', 'c', 'mediumtext', array('null' => true));
            $this->assertSame($before, $db->columns, 'restored after a successful render');

            try {
                $grammar->addColumn('t', 'c', 'jsonb', array());
            } catch (InvalidArgumentException $e) {
                // expected
            }
            $this->assertSame($before, $db->columns, 'restored after a failed render');

            $this->assertArrayNotHasKey('mediumtext', $db->columns, 'the driver map itself is untouched');
        }
    }

    /**
     * Additive means additive: a type CakePHP already defines is never
     * redefined out from under Model::schema() while the map is swapped in.
     */
    public function testTheExtensionNeverShadowsADriverType()
    {
        foreach (array($this->mysql, $this->pgsql) as $grammar) {
            $db = $grammar->getDataSource();
            $reflection = new ReflectionMethod(get_class($grammar), 'mergedColumns');
            $reflection->setAccessible(true);
            $merged = $reflection->invoke($grammar);

            foreach ($db->columns as $type => $definition) {
                $this->assertSame(
                    $definition['name'],
                    $merged[$type]['name'],
                    sprintf('%s must not redefine the driver type "%s"', get_class($grammar), $type)
                );
            }
        }
    }
}
