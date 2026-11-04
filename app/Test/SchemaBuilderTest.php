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
        $schema->table('galaxies')->changeColumn('distribution', 'tinyinteger', array('null' => false, 'default' => 0));
        $schema->dropTable('after');

        $this->assertSame(
            array(
                'DROP TABLE "before";',
                'ALTER TABLE "galaxies" ALTER COLUMN "distribution" TYPE smallint USING "distribution"::smallint;',
                'ALTER TABLE "galaxies" ALTER COLUMN "distribution" SET NOT NULL;',
                'ALTER TABLE "galaxies" ALTER COLUMN "distribution" SET DEFAULT 0;',
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
