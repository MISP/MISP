<?php
/**
 * SchemaBuilder tests (PRD section 9.1) - the accumulate-then-emit half of the
 * migration DSL.
 *
 * MigrationGrammarTest covers what a single operation renders to. This file
 * covers the things only the builder can get wrong: that operations come out in
 * the order the migration declared them even when table-scoped and
 * schema-scoped calls are interleaved, that nothing is executed, that the same
 * declaration can be re-rendered for an engine that is not connected (which is
 * what makes a two-flavour --dry-run possible without a PostgreSQL server), and
 * that rawSql() refuses to be a silent no-op.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class SchemaBuilderTest extends TestCase
{
    /** @var MysqlGrammar */
    private $mysqlGrammar;

    /** @var PostgresGrammar */
    private $pgsqlGrammar;

    protected function setUp(): void
    {
        $this->mysqlGrammar = new MysqlGrammar(new MigrationTestMysql());
        $this->pgsqlGrammar = new PostgresGrammar(new MigrationTestPostgres());
    }

    /**
     * @return SchemaBuilder
     */
    private function mysql()
    {
        return new SchemaBuilder($this->mysqlGrammar);
    }

    /**
     * @return SchemaBuilder
     */
    private function pgsql()
    {
        return new SchemaBuilder($this->pgsqlGrammar);
    }

    // -------------------------------------------------------------- assembly

    public function testForDataSourcePicksTheGrammar()
    {
        $this->assertSame(
            AbstractGrammar::FLAVOUR_MYSQL,
            SchemaBuilder::forDataSource(new MigrationTestMysql())->getGrammar()->flavour()
        );
        $this->assertSame(
            AbstractGrammar::FLAVOUR_PGSQL,
            SchemaBuilder::forDataSource(new MigrationTestPostgres())->getGrammar()->flavour()
        );
    }

    public function testAFreshBuilderIsEmpty()
    {
        $schema = $this->mysql();
        $this->assertTrue($schema->isEmpty());
        $this->assertSame(array(), $schema->toSql());

        $schema->dropTable('t');
        $this->assertFalse($schema->isEmpty());
    }

    public function testTableScopedCallsChain()
    {
        $schema = $this->mysql();
        $table = $schema->table('event_templates');
        $this->assertSame($table, $table->addColumn('exposed', 'boolean', array('null' => false, 'default' => 0)));
        $this->assertSame($table, $table->addIndex('exposed'));
        $this->assertCount(2, $schema->operations());
    }

    /**
     * The reason SchemaTableBuilder pushes each call straight back into the
     * SchemaBuilder rather than batching per table: a migration that adds a
     * column, creates a table and then indexes the column must get exactly that
     * sequence, not all the event_templates work bunched together.
     */
    public function testOrderIsDeclarationOrderAcrossScopes()
    {
        $schema = $this->mysql();
        $schema->table('event_templates')->addColumn('exposed', 'boolean', array('null' => false, 'default' => 0));
        $schema->createTable('audit', array('id' => array('type' => 'primary_key')));
        $schema->table('event_templates')->addIndex('exposed');
        $schema->renameTable('audit', 'audit_log');
        $schema->dropTable('old_audit');

        $statements = $schema->toSql();
        $this->assertCount(5, $statements);
        $this->assertStringStartsWith('ALTER TABLE `event_templates` ADD `exposed`', $statements[0]);
        $this->assertStringStartsWith('CREATE TABLE `audit`', $statements[1]);
        $this->assertSame('ALTER TABLE `event_templates` ADD INDEX `exposed` (`exposed`);', $statements[2]);
        $this->assertSame('RENAME TABLE `audit` TO `audit_log`;', $statements[3]);
        $this->assertSame('DROP TABLE `old_audit`;', $statements[4]);
    }

    /**
     * One declared operation can be several statements, and they land in the
     * right place in the sequence rather than at the end.
     */
    public function testAnOperationThatRendersToSeveralStatementsStaysInPlace()
    {
        $schema = $this->pgsql();
        $schema->dropTable('before');
        $schema->table('galaxies')->renameColumn('kind', 'type', 'tinyinteger', array('null' => false, 'default' => 0));
        $schema->dropTable('after');

        $this->assertSame(
            array(
                'DROP TABLE "before";',
                'ALTER TABLE "galaxies" RENAME COLUMN "kind" TO "type";',
                "ALTER TABLE \"galaxies\"\n" .
                "    ALTER COLUMN \"type\" TYPE smallint USING \"type\"::smallint,\n" .
                "    ALTER COLUMN \"type\" SET NOT NULL,\n" .
                "    ALTER COLUMN \"type\" SET DEFAULT 0;",
                'DROP TABLE "after";',
            ),
            $schema->toSql()
        );
    }

    /**
     * Operations are kept as data, not as rendered strings, so the same
     * declaration can be handed a second grammar. That is what lets
     * `migrationApply --dry-run` print both engines' SQL with only a MySQL
     * connection in the room.
     */
    public function testTheSameDeclarationCanBeRenderedForAnotherEngine()
    {
        $schema = $this->mysql();
        $schema->table('event_templates')
            ->addColumn('exposed', 'boolean', array('null' => false, 'default' => 0, 'after' => 'misp_default'))
            ->addIndex('exposed');

        $this->assertSame(
            array(
                "ALTER TABLE `event_templates` ADD `exposed` tinyint(1) DEFAULT '0' NOT NULL AFTER `misp_default`;",
                'ALTER TABLE `event_templates` ADD INDEX `exposed` (`exposed`);',
            ),
            $schema->toSql()
        );
        $this->assertSame(
            array(
                'ALTER TABLE "event_templates" ADD "exposed" boolean DEFAULT \'FALSE\' NOT NULL;',
                'CREATE INDEX "idx_event_templates_exposed" ON "event_templates" ("exposed");',
            ),
            $schema->toSql($this->pgsqlGrammar)
        );
        // Rendering does not consume the declaration.
        $this->assertCount(2, $schema->operations());
    }

    public function testOperationsAreStoredUnrendered()
    {
        $schema = $this->mysql();
        $schema->table('t')->dropColumn('c');

        $this->assertSame(
            array(array('operation' => 'dropColumn', 'arguments' => array('t', 'c'))),
            $schema->operations()
        );
    }

    // ------------------------------------------------- one statement per table

    /**
     * Every ALTER TABLE may rebuild the table on MySQL, so a run of changes to
     * one table is one statement. PostgreSQL gets one ALTER TABLE for the
     * column changes, with the index statements in their place around it.
     */
    public function testConsecutiveChangesToOneTableShareOneStatement()
    {
        $schema = $this->mysql();
        $schema->table('events')
            ->dropIndex('sharing_group_id')
            ->changeColumn('org_id', 'biginteger', array('null' => false, 'default' => null))
            ->changeColumn('timestamp', 'biginteger', array('null' => false, 'default' => 0))
            ->addIndex(array('distribution', 'sharing_group_id'), array('name' => 'idx_evt_acl'));

        $this->assertSame(
            array(
                "ALTER TABLE `events`\n" .
                "    DROP INDEX `sharing_group_id`,\n" .
                "    MODIFY `org_id` bigint(20) NOT NULL,\n" .
                "    MODIFY `timestamp` bigint(20) DEFAULT 0 NOT NULL,\n" .
                "    ADD INDEX `idx_evt_acl` (`distribution`, `sharing_group_id`);",
            ),
            $schema->toSql()
        );
        $this->assertSame(
            array(
                'DROP INDEX "idx_events_sharing_group_id";',
                "ALTER TABLE \"events\"\n" .
                "    ALTER COLUMN \"org_id\" TYPE bigint USING \"org_id\"::bigint,\n" .
                "    ALTER COLUMN \"org_id\" SET NOT NULL,\n" .
                "    ALTER COLUMN \"org_id\" DROP DEFAULT,\n" .
                "    ALTER COLUMN \"timestamp\" TYPE bigint USING \"timestamp\"::bigint,\n" .
                "    ALTER COLUMN \"timestamp\" SET NOT NULL,\n" .
                "    ALTER COLUMN \"timestamp\" SET DEFAULT 0;",
                'CREATE INDEX "idx_evt_acl" ON "events" ("distribution", "sharing_group_id");',
            ),
            $schema->toSql($this->pgsqlGrammar)
        );
    }

    public function testAnotherTableOrOperationInBetweenEndsTheStatement()
    {
        $schema = $this->mysql();
        $schema->table('a')->addIndex('x');
        $schema->table('b')->addIndex('x');
        $schema->table('a')->addIndex('y');
        $schema->rawSql(array('mysql' => 'OPTIMIZE TABLE `a`;', 'pgsql' => 'VACUUM ANALYZE a;'));
        $schema->table('a')->addIndex('z');

        $this->assertSame(
            array(
                'ALTER TABLE `a` ADD INDEX `x` (`x`);',
                'ALTER TABLE `b` ADD INDEX `x` (`x`);',
                'ALTER TABLE `a` ADD INDEX `y` (`y`);',
                'OPTIMIZE TABLE `a`;',
                'ALTER TABLE `a` ADD INDEX `z` (`z`);',
            ),
            $schema->toSql()
        );
    }

    /**
     * Adding or dropping a column is instant on its own, but beside an index
     * change the server rebuilds the table for it instead.
     */
    public function testColumnAdditionsAndDropsOnlyShareAStatementWithEachOther()
    {
        $schema = $this->mysql();
        $schema->table('t')
            ->addColumn('x', 'integer', array('null' => true))
            ->dropColumn('c')
            ->addIndex('b')
            ->changeColumn('a', 'biginteger', array('null' => true, 'default' => null))
            ->dropColumn('d');

        $this->assertSame(
            array(
                "ALTER TABLE `t`\n    ADD `x` int(11) DEFAULT NULL,\n    DROP COLUMN `c`;",
                "ALTER TABLE `t`\n    ADD INDEX `b` (`b`),\n    MODIFY `a` bigint(20) DEFAULT NULL;",
                'ALTER TABLE `t` DROP COLUMN `d`;',
            ),
            $schema->toSql()
        );
    }

    /**
     * Sequences that work as separate statements but not reliably as one,
     * because MySQL resolves the column clauses of one ALTER TABLE against the
     * table as it was before the statement. Most fail outright as one statement
     * on MariaDB 10.11 or PostgreSQL 16; MariaDB happens to take a column
     * dropped and added back, and one placed after a column added beside it,
     * but they are split all the same.
     *
     * @dataProvider dependentSequences
     */
    public function testAnOperationThatDependsOnAnEarlierOneStartsANewStatement($declare)
    {
        $schema = $this->mysql();
        $declare($schema->table('t'));
        $this->assertCount(2, $schema->toSql());
    }

    public function dependentSequences()
    {
        $null = array('null' => true, 'default' => null);
        return array(
            'a column changed twice' => array(function ($t) use ($null) {
                $t->changeColumn('a', 'biginteger', $null)->changeColumn('a', 'integer', $null);
            }),
            'a column changed after it was renamed' => array(function ($t) use ($null) {
                $t->renameColumn('a', 'a2', 'integer', $null)->changeColumn('a2', 'biginteger', $null);
            }),
            'a column renamed after it was changed' => array(function ($t) use ($null) {
                $t->changeColumn('a', 'biginteger', $null)->renameColumn('a', 'a2', 'integer', $null);
            }),
            'a column dropped and added back' => array(function ($t) use ($null) {
                $t->dropColumn('b')->addColumn('b', 'biginteger', $null);
            }),
            'a column placed after one added in the statement' => array(function ($t) use ($null) {
                $t->addColumn('x', 'integer', $null)->addColumn('y', 'integer', $null + array('after' => 'x'));
            }),
            'an index dropped after it was added' => array(function ($t) {
                $t->addIndex('b', array('name' => 'ib'))->dropIndex('ib');
            }),
            'a column renamed under an index added in the statement' => array(function ($t) use ($null) {
                $t->addIndex('b')->renameColumn('b', 'b2', 'integer', $null);
            }),
        );
    }

    /**
     * The counterparts that one statement handles: they stay together.
     *
     * @dataProvider independentSequences
     */
    public function testIndependentOperationsStayInOneStatement($declare)
    {
        $schema = $this->mysql();
        $declare($schema->table('t'));
        $this->assertCount(1, $schema->toSql());
    }

    public function independentSequences()
    {
        $null = array('null' => true, 'default' => null);
        return array(
            'an index dropped and added back under its name' => array(function ($t) {
                $t->dropIndex('ia')->addIndex(array('a', 'b'), array('name' => 'ia'));
            }),
            'an index over a column renamed in the statement' => array(function ($t) use ($null) {
                $t->renameColumn('a', 'a2', 'integer', $null)->addIndex('a2');
            }),
            'a column changed under an index added in the statement' => array(function ($t) use ($null) {
                $t->addIndex('b')->changeColumn('b', 'biginteger', $null);
            }),
            'a primary key replaced' => array(function ($t) use ($null) {
                $t->addIndex('n', array('unique' => true))->dropPrimaryKey();
            }),
        );
    }

    // ------------------------------------------------ what is already there

    /**
     * @param string $flavour
     * @param array $schema
     * @return MigrationTestInspector
     */
    private function live($flavour, array $schema)
    {
        return new MigrationTestInspector($flavour, $schema);
    }

    /**
     * A re-run after a partial apply: only what did not land is rendered, still
     * as one statement, and nothing in it is a clause the server would refuse.
     */
    public function testWhatIsAlreadyThereIsLeftOutOfTheStatement()
    {
        $schema = $this->mysql();
        $schema->table('events')
            ->dropIndex('sharing_group_id')
            ->dropIndex('org_id')
            ->addIndex(array('distribution', 'sharing_group_id'), array('name' => 'idx_evt_acl'))
            ->addIndex(array('timestamp', 'published'), array('name' => 'idx_evt_ts_pub'));

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            'events' => array(
                'columns' => array('id', 'org_id', 'distribution', 'sharing_group_id', 'timestamp', 'published'),
                'indexes' => array(
                    'PRIMARY' => array('id'),
                    'sharing_group_id' => array('sharing_group_id'),
                    'idx_evt_acl' => array('distribution', 'sharing_group_id'),
                ),
            ),
        )));

        $this->assertSame(
            array(
                "ALTER TABLE `events`\n" .
                "    DROP INDEX `sharing_group_id`,\n" .
                "    ADD INDEX `idx_evt_ts_pub` (`timestamp`, `published`);",
            ),
            $schema->toSql()
        );
        $this->assertSame(
            array(
                'events: index org_id is already gone',
                'events: index idx_evt_acl is already there',
            ),
            $skipped
        );
    }

    public function testADeclarationThatHasFullyLandedRendersNothing()
    {
        $schema = $this->mysql();
        $schema->table('t')
            ->addColumn('x', 'integer', array('null' => true))
            ->dropColumn('gone')
            ->addIndex('x')
            ->dropPrimaryKey();

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array('columns' => array('x'), 'indexes' => array('x' => array('x'))),
        )));

        $this->assertSame(array(), $schema->toSql());
        $this->assertSame(
            array(
                't: column x is already there',
                't: column gone is already gone',
                't: index x is already there',
                't: the primary key is already gone',
            ),
            $skipped
        );
    }

    /**
     * Each operation is checked against the table as the ones kept before it
     * leave it, not as it was when the migration started.
     */
    public function testAnOperationIsCheckedAfterTheOnesBeforeIt()
    {
        $schema = $this->mysql();
        $null = array('null' => true, 'default' => null);
        $schema->table('t')
            ->dropIndex('ia')
            ->addIndex(array('a', 'b'), array('name' => 'ia'))
            ->dropColumn('c')
            ->addColumn('c', 'biginteger', $null)
            ->addColumn('x', 'integer', $null)
            ->dropColumn('x');

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array('columns' => array('a', 'b', 'c'), 'indexes' => array('ia' => array('a'))),
        )));

        $this->assertSame(array(), $skipped);
        $this->assertCount(6, $schema->operations());
    }

    /**
     * Dropping or renaming a column changes the indexes over it differently on
     * each engine, so an operation on one of them is kept, not guessed about.
     */
    public function testIndexesOverADroppedOrRenamedColumnAreNotGuessedAbout()
    {
        $schema = $this->mysql();
        $null = array('null' => true, 'default' => null);
        $schema->table('t')
            ->dropColumn('b')
            ->dropIndex('ib')
            ->addIndex('ab', array('name' => 'iab'))
            ->renameColumn('a', 'a2', 'integer', $null)
            ->dropPrimaryKey();

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array(
                'columns' => array('a', 'b'),
                'indexes' => array('PRIMARY' => array('a'), 'ib' => array('b'), 'iab' => array('a', 'b')),
            ),
        )));

        $this->assertSame(array(), $skipped);
        $this->assertCount(5, $schema->operations());
    }

    public function testARenameThatHasLandedIsLeftOut()
    {
        $schema = $this->mysql();
        $schema->table('t')->renameColumn('a', 'a2', 'integer', array('null' => true, 'default' => null));

        $skipped = $schema->skipSatisfied($this->live('mysql', array('t' => array('columns' => array('a2')))));

        $this->assertSame(array('t: column a is already renamed to a2'), $skipped);
        $this->assertSame(array(), $schema->toSql());
    }

    /**
     * Never left out: a column change, which would need the full definition
     * compared; anything on a table the migration creates, which is written
     * against the declaration; anything on a table that is not there; and
     * anything after hand-written SQL.
     */
    public function testWhatCannotBeKnownIsKept()
    {
        $schema = $this->mysql();
        $null = array('null' => true, 'default' => null);
        $schema->table('t')->changeColumn('a', 'biginteger', $null);
        $schema->createTable('n', array('a' => 'integer'));
        $schema->table('n')->addIndex('a');
        $schema->table('missing')->dropColumn('a');
        $schema->rawSql(array('mysql' => 'SELECT 1;', 'pgsql' => 'SELECT 1;'));
        $schema->table('u')->addColumn('a', 'integer', $null);

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array('columns' => array('a')),
            'u' => array('columns' => array('a')),
        )));

        $this->assertSame(array(), $skipped);
        $this->assertCount(6, $schema->operations());
    }

    /**
     * On PostgreSQL a table's indexes are statements of their own, so a run
     * that stopped after the CREATE TABLE leaves the table without some of
     * them: the table is left out, the missing indexes are not.
     */
    public function testATableThatIsAlreadyThereStillGetsItsMissingIndexes()
    {
        $schema = $this->pgsql();
        $schema->createTable('t', array(
            'id' => array('type' => 'primary_key'),
            'a' => array('type' => 'integer', 'null' => true),
            'b' => array('type' => 'integer', 'null' => true),
        ), array('indexes' => array('a' => array(), 'b_lookup' => array('column' => array('b', 'a')))));
        $schema->table('t')->addIndex('id', array('name' => 'id_copy'));

        $skipped = $schema->skipSatisfied($this->live('pgsql', array(
            't' => array(
                'columns' => array('id', 'a', 'b'),
                'indexes' => array('PRIMARY' => array('id'), 'idx_t_a' => array('a')),
            ),
        )));

        $this->assertSame(array('t: the table is already there'), $skipped);
        $this->assertSame(
            array(
                'CREATE INDEX "idx_t_b_lookup" ON "t" ("b", "a");',
                'CREATE INDEX "idx_t_id_copy" ON "t" ("id");',
            ),
            $schema->toSql()
        );
    }

    public function testATableThatIsAlreadyCompleteRendersNothing()
    {
        $schema = $this->mysql();
        $schema->createTable(
            't',
            array('id' => array('type' => 'primary_key'), 'a' => 'integer'),
            array('indexes' => array('a' => array('unique' => true)))
        );

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array('columns' => array('id', 'a'), 'indexes' => array('PRIMARY' => array('id'), 'a' => array('a'))),
        )));

        $this->assertSame(array('t: the table is already there'), $skipped);
        $this->assertSame(array(), $schema->toSql());
    }

    public function testTableDropsAndRenamesThatHaveLandedAreLeftOut()
    {
        $schema = $this->mysql();
        $schema->dropTable('gone');
        $schema->renameTable('old', 'new');
        $schema->table('new')->addIndex('a');

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            'new' => array('columns' => array('a'), 'indexes' => array('a' => array('a'))),
        )));

        $this->assertSame(
            array(
                'gone: the table is already gone',
                'old: the table is already renamed to new',
                'new: index a is already there',
            ),
            $skipped
        );
        $this->assertSame(array(), $schema->toSql());
    }

    /**
     * A table dropped and created again - emptied, in effect - is both, every
     * time: the migration asked for a fresh table, not for one to exist.
     */
    public function testATableDroppedAndCreatedAgainKeepsBoth()
    {
        $schema = $this->mysql();
        $schema->dropTable('t');
        $schema->createTable('t', array('a' => 'integer'), array('indexes' => array('a' => array())));
        $schema->table('t')->addIndex('a', array('name' => 'a_again'));

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array('columns' => array('a'), 'indexes' => array('a' => array('a'), 'a_again' => array('a'))),
        )));

        $this->assertSame(array(), $skipped);
        $this->assertCount(3, $schema->operations());

        $retry = $this->mysql();
        $retry->dropTable('t');
        $retry->createTable('t', array('a' => 'integer'));
        $this->assertSame(
            array('t: the table is already gone'),
            $retry->skipSatisfied($this->live('mysql', array())),
            'after the drop landed and the create did not'
        );
        $this->assertCount(1, $retry->operations());
    }

    public function testMysqlNamesAreComparedWithoutCase()
    {
        $schema = $this->mysql();
        $schema->table('t')
            ->addColumn('Value1', 'integer', array('null' => true))
            ->addIndex('a', array('name' => 'IDX_A'));

        $skipped = $schema->skipSatisfied($this->live('mysql', array(
            't' => array('columns' => array('value1', 'a'), 'indexes' => array('idx_a' => array('a'))),
        )));

        $this->assertCount(2, $skipped);
    }

    /**
     * PostgreSQL index names are the grammar's own, prefixed with the table, and
     * a quoted name is matched with its case.
     */
    public function testPostgresMatchesItsOwnIndexNames()
    {
        $schema = $this->pgsql();
        $schema->table('t')
            ->addIndex('a')
            ->dropIndex('b')
            ->addColumn('A', 'integer', array('null' => true));

        $skipped = $schema->skipSatisfied($this->live('pgsql', array(
            't' => array('columns' => array('a', 'b'), 'indexes' => array('idx_t_a' => array('a'), 'idx_t_b' => array('b'))),
        )));

        $this->assertSame(array('t: index idx_t_a is already there'), $skipped);
        $this->assertSame(
            array('DROP INDEX "idx_t_b";', 'ALTER TABLE "t" ADD "A" integer DEFAULT NULL;'),
            $schema->toSql()
        );
    }

    public function testASchemaReadFromAnotherEngineIsRefused()
    {
        $this->expectException('LogicException');
        $this->mysql()->skipSatisfied($this->live('pgsql', array()));
    }

    public function testRawSqlPositionsStillCountTheOperationsLeftOut()
    {
        $schema = $this->mysql();
        $schema->table('t')->addColumn('a', 'integer', array('null' => true));
        $schema->rawSql(array('pgsql' => 'SELECT 1;'));
        $schema->skipSatisfied($this->live('mysql', array('t' => array('columns' => array('a')))));

        $this->expectExceptionMessage('position 1');
        $schema->toSql();
    }

    // ---------------------------------------------------------------- rawSql

    public function testRawSqlIsPassedThroughVerbatimForTheRenderedFlavour()
    {
        $mysqlSql = "ALTER TABLE `attributes` ADD FULLTEXT INDEX `value_ft` (`value1`);";
        $pgsqlSql = "CREATE INDEX idx_attributes_value_ft ON attributes USING gin(to_tsvector('simple', value1));";

        $schema = $this->mysql();
        $schema->rawSql(array('mysql' => $mysqlSql, 'pgsql' => $pgsqlSql));

        $this->assertSame(array($mysqlSql), $schema->toSql());
        $this->assertSame(array($pgsqlSql), $schema->toSql($this->pgsqlGrammar));
    }

    public function testRawSqlAcceptsSeveralStatementsForOneFlavour()
    {
        $schema = $this->mysql();
        $schema->rawSql(array(
            'mysql' => array('SET foreign_key_checks = 0;', 'SET foreign_key_checks = 1;'),
            'pgsql' => 'SELECT 1;',
        ));

        $this->assertSame(
            array('SET foreign_key_checks = 0;', 'SET foreign_key_checks = 1;'),
            $schema->toSql()
        );
    }

    /**
     * An empty list is not a missing flavour. It says, in so many words, that
     * this engine has nothing to run here - the spelling for a MySQL storage
     * option that PostgreSQL has no counterpart to, or the mirror image - and
     * it renders as no statement at all rather than as an empty one.
     */
    public function testRawSqlWithAnEmptyListForAFlavourIsAnExplicitNoOp()
    {
        $schema = $this->mysql();
        $schema->rawSql(array('mysql' => 'ALTER TABLE `tags` ROW_FORMAT=DYNAMIC;', 'pgsql' => array()));

        $this->assertSame(array('ALTER TABLE `tags` ROW_FORMAT=DYNAMIC;'), $schema->toSql());
        $this->assertSame(array(), $schema->toSql($this->pgsqlGrammar));
    }

    public function testRawSqlInterleavesWithDeclaredOperations()
    {
        $schema = $this->mysql();
        $schema->table('t')->addColumn('a', 'integer', array('null' => true));
        $schema->rawSql(array('mysql' => 'OPTIMIZE TABLE `t`;', 'pgsql' => 'VACUUM ANALYZE t;'));
        $schema->table('t')->addColumn('b', 'integer', array('null' => true));

        $statements = $schema->toSql();
        $this->assertSame('OPTIMIZE TABLE `t`;', $statements[1]);
        $this->assertCount(3, $statements);
    }

    /**
     * The point of the escape hatch is that it does not become a back door.
     * A rawSql() with nothing to say for the engine being rendered is a hard
     * error - a migration that quietly does nothing on one engine leaves that
     * engine's schema behind the code that expects it, which is the failure this
     * whole subsystem exists to end.
     */
    public function testRawSqlMissingTheRenderedFlavourIsAHardError()
    {
        $schema = $this->mysql();
        $schema->rawSql(array('mysql' => 'OPTIMIZE TABLE `a`;'));

        // Fine on the flavour it declares.
        $this->assertSame(array('OPTIMIZE TABLE `a`;'), $schema->toSql());

        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('has no "pgsql" statement');
        $schema->toSql($this->pgsqlGrammar);
    }

    public function testTheMissingFlavourErrorNamesThePosition()
    {
        $schema = $this->pgsql();
        $schema->dropTable('a');
        $schema->dropTable('b');
        $schema->rawSql(array('mysql' => 'OPTIMIZE TABLE `a`;'));

        try {
            $schema->toSql();
            $this->fail('a missing flavour should not render');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('position 2', $e->getMessage());
            $this->assertStringContainsString('mysql', $e->getMessage());
        }
    }

    public function testRawSqlRejectsAnUnknownFlavourKeyImmediately()
    {
        $schema = $this->mysql();
        try {
            // The kind of typo that would otherwise only surface as a missing
            // flavour, and only on the engine nobody was testing.
            $schema->rawSql(array('mysql' => 'SELECT 1;', 'postgres' => 'SELECT 1;'));
            $this->fail('an unknown flavour key should be rejected');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('postgres', $e->getMessage());
            $this->assertStringContainsString('pgsql', $e->getMessage());
        }
        $this->assertTrue($schema->isEmpty(), 'a rejected rawSql() must not be recorded');
    }

    public function testRawSqlRejectsAnEmptyMap()
    {
        $this->expectException('InvalidArgumentException');
        $this->mysql()->rawSql(array());
    }

    // ------------------------------------------------------------ no side effects

    /**
     * The builder emits; it never executes. If it ever tried, the connectionless
     * datasource these tests run against would fail loudly - which is itself
     * part of the assertion.
     */
    public function testBuildingNeverTouchesTheConnection()
    {
        $schema = $this->mysql();
        $schema->createTable('t', array('id' => array('type' => 'primary_key')));
        $schema->table('t')->addColumn('c', 'string', array('null' => true));
        $schema->table('t')->dropIndex('c');
        $schema->dropTable('t');

        $this->assertCount(4, $schema->toSql());
        $this->assertCount(4, $schema->toSql(), 'rendering twice is stable and side-effect free');
    }
}
