<?php
/**
 * SqlDialect rendering tests - the runtime half of the portability work,
 * asserted at the SQL-string level.
 *
 * The same reasoning as the grammar suite applies here, for the same reason:
 * there is no PostgreSQL instance to run any of this against, and on a normal
 * MISP host there cannot be one - pdo_pgsql is not installed and app/composer.json
 * requires neither PDO extension. So the PostgreSQL half of every method is
 * verified here or nowhere.
 *
 * Three things are being pinned.
 *
 * 1. **The MySQL rendering still matches what MISP issues today.** Every
 *    expression below appears verbatim somewhere in the tree - AuditLog's and
 *    Log's date histograms, Sighting's date grouping, the dashboard evolution
 *    widgets, AccessLog's table maintenance, Correlation's on-demand counters -
 *    so the assertions double as a record of the statement each future call site
 *    has to keep producing. Phase 8 changes live MySQL paths for a benefit that
 *    only materialises on an engine nobody runs yet; this is where "unchanged on
 *    MySQL" stops being a claim.
 *
 * 2. **The PostgreSQL rendering is valid PostgreSQL**, including the two places
 *    it is deliberately not the obvious transliteration: `(x)::date` rather than
 *    `CAST(x AS DATE)`, and setval()'s three-argument form.
 *
 * 3. **The refusals.** An upsert without its conflict columns is rejected on
 *    both engines, MySQL included - the same strictness, and for the same
 *    reason, as the schema DSL's changeColumn.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class SqlDialectTest extends TestCase
{
    /** @var SqlDialect */
    private $mysql;

    /** @var SqlDialect */
    private $pgsql;

    protected function setUp(): void
    {
        // MysqlExtended, not Mysql: MISP never runs vanilla Mysql, and the
        // difference reaches this class through value().
        $this->mysql = new SqlDialect(new MigrationTestMysqlExtended());
        $this->pgsql = new SqlDialect(new MigrationTestPostgres());
    }

    // ------------------------------------------------------------- selection

    public function testFlavourFollowsTheDriver()
    {
        $this->assertSame(SqlDialect::FLAVOUR_MYSQL, $this->mysql->flavour());
        $this->assertSame(SqlDialect::FLAVOUR_PGSQL, $this->pgsql->flavour());
    }

    /**
     * The test mirrors AppModel::isMysql(), so every driver MISP ships -
     * MysqlExtended and the observer variants - has to classify as MySQL, and
     * so does the vanilla base class nothing actually runs.
     */
    public function testEveryMysqlDriverClassifiesAsMysql()
    {
        $vanilla = new SqlDialect(new MigrationTestMysql());
        $this->assertSame(SqlDialect::FLAVOUR_MYSQL, $vanilla->flavour());
        $this->assertSame('DATE(created)', $vanilla->dateOf('created'));
    }

    /**
     * Quoting deliberately gets no dialect methods - $db->name() and
     * $db->value() already exist and are already correct on every driver - so
     * the datasource has to stay reachable from a caller holding a dialect.
     */
    public function testTheDatasourceStaysReachableForQuoting()
    {
        $db = new MigrationTestPostgres();
        $dialect = new SqlDialect($db);
        $this->assertSame($db, $dialect->getDataSource());
        $this->assertSame('"expire"', $dialect->getDataSource()->name('expire'));
    }

    // ----------------------------------------------------------- expressions

    public function testDateOf()
    {
        $this->assertSame('DATE(created)', $this->mysql->dateOf('created'));
        $this->assertSame('(created)::date', $this->pgsql->dateOf('created'));
    }

    /**
     * `::` binds tighter than nearly every other operator, so an
     * unparenthesised compound expression would cast only its last term. The
     * parentheses are not cosmetic.
     */
    public function testDateOfParenthesisesACompoundExpression()
    {
        $this->assertSame(
            "(created + interval '1 day')::date",
            $this->pgsql->dateOf("created + interval '1 day'")
        );
    }

    public function testUnixTimestamp()
    {
        $this->assertSame('UNIX_TIMESTAMP(created)', $this->mysql->unixTimestamp('created'));
        $this->assertSame('EXTRACT(EPOCH FROM created)::bigint', $this->pgsql->unixTimestamp('created'));
    }

    public function testFromUnixtime()
    {
        $this->assertSame('FROM_UNIXTIME(t)', $this->mysql->fromUnixtime('t'));
        $this->assertSame('to_timestamp(t)', $this->pgsql->fromUnixtime('t'));
    }

    /**
     * The MySQL sites in the tree spell the format string with double quotes,
     * which only works while ANSI_QUOTES is off - under it the server reads
     * "%Y-%m" as an identifier. Single quotes mean the same thing on both
     * engines under every mode, so that is what is rendered.
     */
    public function testFormatYearMonthUsesSingleQuotesOnBothEngines()
    {
        $this->assertSame(
            "DATE_FORMAT(date_created, '%Y-%m')",
            $this->mysql->formatYearMonth('date_created')
        );
        $this->assertSame(
            "to_char(date_created, 'YYYY-MM')",
            $this->pgsql->formatYearMonth('date_created')
        );
    }

    /**
     * The expressions have to nest, because every real use in MISP is a
     * composition rather than a single call. These three are the shapes
     * currently written out by hand: the audit-log and log date histograms, the
     * sighting date grouping, and the event-evolution dashboard widget.
     */
    public function testTheExpressionsComposeIntoTheShapesMispAlreadyIssues()
    {
        $this->assertSame(
            'UNIX_TIMESTAMP(DATE(created))',
            $this->mysql->unixTimestamp($this->mysql->dateOf('created'))
        );
        $this->assertSame(
            'EXTRACT(EPOCH FROM (created)::date)::bigint',
            $this->pgsql->unixTimestamp($this->pgsql->dateOf('created'))
        );

        $this->assertSame(
            'DATE(FROM_UNIXTIME(Sighting.date_sighting))',
            $this->mysql->dateOf($this->mysql->fromUnixtime('Sighting.date_sighting'))
        );
        $this->assertSame(
            '(to_timestamp(Sighting.date_sighting))::date',
            $this->pgsql->dateOf($this->pgsql->fromUnixtime('Sighting.date_sighting'))
        );

        $this->assertSame(
            "DATE_FORMAT(FROM_UNIXTIME(Event.publish_timestamp), '%Y-%m')",
            $this->mysql->formatYearMonth($this->mysql->fromUnixtime('Event.publish_timestamp'))
        );
        $this->assertSame(
            "to_char(to_timestamp(Event.publish_timestamp), 'YYYY-MM')",
            $this->pgsql->formatYearMonth($this->pgsql->fromUnixtime('Event.publish_timestamp'))
        );
    }

    /**
     * The pattern is a value and is quoted through the driver; the expression
     * is SQL and is not, so a caller that wants an identifier quoted asks
     * name() for it.
     */
    public function testRegexpMatchQuotesThePatternAndNotTheExpression()
    {
        $this->assertSame(
            "`value` REGEXP '^abc'",
            $this->mysql->regexpMatch($this->mysql->getDataSource()->name('value'), '^abc')
        );
        $this->assertSame(
            '"value" ~ \'^abc\'',
            $this->pgsql->regexpMatch($this->pgsql->getDataSource()->name('value'), '^abc')
        );
    }

    public function testRegexpMatchQuotesAPatternContainingAQuote()
    {
        $this->assertSame(
            "col REGEXP 'it''s'",
            $this->mysql->regexpMatch('col', "it's")
        );
        $this->assertSame(
            "col ~ 'it''s'",
            $this->pgsql->regexpMatch('col', "it's")
        );
    }

    /**
     * An expression is a fragment: it gets embedded in a larger query or in a
     * CakePHP `fields` array, so a trailing semicolon would be a syntax error
     * rather than a harmless flourish. Statements are the other way round.
     */
    public function testExpressionsAreFragmentsAndStatementsAreNot()
    {
        $expressions = array(
            $this->pgsql->dateOf('created'),
            $this->pgsql->unixTimestamp('created'),
            $this->pgsql->fromUnixtime('t'),
            $this->pgsql->formatYearMonth('created'),
            $this->pgsql->regexpMatch('col', 'x'),
        );
        foreach ($expressions as $expression) {
            $this->assertStringEndsNotWith(';', $expression);
        }

        $this->assertStringEndsWith(';', $this->pgsql->optimizeTable('t'));
        $this->assertStringEndsWith(';', $this->pgsql->resetSequence('t', 'id'));
        $this->assertStringEndsWith(';', $this->pgsql->upsert('INSERT INTO t (a) VALUES (1)', array('a'), array('a')));
    }

    // ------------------------------------------------------------ statements

    public function testOptimizeTable()
    {
        $this->assertSame(
            'OPTIMIZE TABLE `access_logs`;',
            $this->mysql->optimizeTable('access_logs')
        );
        $this->assertSame(
            'VACUUM ANALYZE "access_logs";',
            $this->pgsql->optimizeTable('access_logs')
        );
    }

    /**
     * Correlation::generateTopOnDemand()'s statement, which is the only upsert
     * in the tree. Everything before the clause this method appends is already
     * portable - PostgreSQL has left() too - so the whole statement has to come
     * back unaltered apart from the tail.
     */
    public function testUpsertAppendsTheEnginesConflictClause()
    {
        $insert = "INSERT INTO attr_value_counts (value, cnt_v1)\n"
            . "SELECT LEFT(a.value1, 64) AS value, COUNT(*) AS c\n"
            . "FROM attributes a\n"
            . "GROUP BY LEFT(a.value1, 64)";

        $this->assertSame(
            $insert . ' ON DUPLICATE KEY UPDATE `cnt_v1` = VALUES(`cnt_v1`);',
            $this->mysql->upsert($insert, array('value'), array('cnt_v1'))
        );
        $this->assertSame(
            $insert . ' ON CONFLICT ("value") DO UPDATE SET "cnt_v1" = EXCLUDED."cnt_v1";',
            $this->pgsql->upsert($insert, array('value'), array('cnt_v1'))
        );
    }

    public function testUpsertHandlesSeveralColumnsOnBothSidesOfTheClause()
    {
        $insert = 'INSERT INTO t (a, b, c) VALUES (1, 2, 3)';

        $this->assertSame(
            $insert . ' ON DUPLICATE KEY UPDATE `b` = VALUES(`b`), `c` = VALUES(`c`);',
            $this->mysql->upsert($insert, array('a'), array('b', 'c'))
        );
        $this->assertSame(
            $insert . ' ON CONFLICT ("a", "b") DO UPDATE SET "c" = EXCLUDED."c";',
            $this->pgsql->upsert($insert, array('a', 'b'), array('c'))
        );
    }

    /**
     * The statements this replaces are written with their semicolon attached,
     * so a caller that pastes one in unedited must not end up with the clause
     * dangling after the end of the statement.
     */
    public function testUpsertTrimsATrailingSemicolonFromTheInsert()
    {
        $this->assertSame(
            'INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE `a` = VALUES(`a`);',
            $this->mysql->upsert("INSERT INTO t (a) VALUES (1);\n", array('a'), array('a'))
        );
    }

    /**
     * MySQL infers the conflicting key and would happily render without this,
     * which is exactly why it is refused there too: an author working on the
     * only engine they can run would otherwise omit the one part PostgreSQL
     * cannot supply for itself, and nothing would notice until it ran there.
     */
    public function testUpsertRefusesToGuessTheConflictColumnsOnEitherEngine()
    {
        foreach (array($this->mysql, $this->pgsql) as $dialect) {
            try {
                $dialect->upsert('INSERT INTO t (a) VALUES (1)', array(), array('a'));
                $this->fail('An upsert with no conflict columns should have been refused.');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('PostgreSQL cannot', $e->getMessage());
            }
        }
    }

    public function testUpsertRefusesAnEmptyUpdateList()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('at least one column to update');
        $this->pgsql->upsert('INSERT INTO t (a) VALUES (1)', array('a'), array());
    }

    /**
     * The null is the point of the method: MySQL tracks the high-water mark
     * itself, so the four call sites that currently open-code this behind an
     * isMysql() branch become "run it if you got one".
     */
    public function testResetSequenceIsANoOpOnMysql()
    {
        $this->assertNull($this->mysql->resetSequence('roles', 'id'));
    }

    /**
     * Three details, none of them incidental. The sequence is resolved through
     * pg_get_serial_sequence() rather than composed as `<table>_<column>_seq`,
     * because that is only the default name and PostgreSQL truncates
     * identifiers at 63 characters. MAX() is aggregated over the table in the
     * same scan rather than in a subquery. And the third setval() argument
     * leaves is_called false on an empty table, so the next value is 1 rather
     * than 2 - which the two-argument form the tree uses today gets wrong.
     */
    public function testResetSequenceOnPostgres()
    {
        $this->assertSame(
            'SELECT setval(pg_get_serial_sequence(\'roles\', \'id\'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "roles";',
            $this->pgsql->resetSequence('roles', 'id')
        );
    }

    /**
     * Every primary key in MISP's schema is `id`, so the call sites read better
     * without it - but the column still has to reach both the sequence lookup
     * and the aggregate.
     */
    public function testResetSequenceDefaultsToTheIdColumn()
    {
        $this->assertSame(
            $this->pgsql->resetSequence('organisations', 'id'),
            $this->pgsql->resetSequence('organisations')
        );
    }
}
