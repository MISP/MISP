<?php

App::uses('ConnectionManager', 'Model');

/**
 * Renders the SQL that differs between MySQL and PostgreSQL only in spelling.
 *
 * Migrations were half the MySQL debt; the raw SQL the application issues at
 * runtime is the other half. Rendering PostgreSQL DDL buys nothing if the
 * application then cannot query what it created, so this class sits alongside
 * the migration grammars and shares their flavour detection - it is the same
 * problem one layer up.
 *
 * ## What belongs here, and what does not
 *
 * MISP already carries two dozen `isMysql()` branches, and most of them exist
 * for no better reason than backticks versus double quotes. Bruteforce::clean()
 * is the pattern in miniature: six lines, two branches, and the only
 * differences are identifier quoting and string quoting. So the rule is that a
 * branch is legitimate only where the two statements are *structurally*
 * different, and even then the branch belongs in a Lib class rather than at the
 * call site - otherwise the next engine means editing seventy places again.
 *
 * Three kinds of difference, three homes:
 *
 * - **Identifier and literal quoting** get no methods here on purpose. Callers
 *   use `$db->name()` and `$db->value()`, which already exist, are already
 *   correct on every driver, and are already used elsewhere in MISP. Reach them
 *   through getDataSource().
 * - **Performance optimisations** - index hints, straight joins, MEMORY
 *   temporaries - are not this class's business either. They are capability
 *   probes: AppModel::checkDbSupport() reads the driver's own $supports array,
 *   so the optimisation is simply not taken on an engine that does not declare
 *   it, and the query still runs.
 * - **Introspection** - `information_schema`, `SHOW INDEX`, `SHOW VARIABLES` -
 *   cannot be translated by spelling at all; PostgreSQL needs genuinely
 *   different queries against `pg_catalog`. That is SchemaInspector's job.
 *
 * What is left, and what this class covers, is the set of constructs where both
 * engines can express the same thing and merely disagree about how to write it.
 *
 * ## Fragments and statements
 *
 * The methods split into two kinds, and the return values say which is which:
 *
 * - **Expression methods** (dateOf, unixTimestamp, fromUnixtime,
 *   formatYearMonth, regexpMatch) return a fragment with no trailing semicolon,
 *   to be embedded in a larger query or in a `fields` array.
 * - **Statement methods** (optimizeTable, upsert, resetSequence) return a
 *   complete statement ending in a semicolon, matching what the grammars
 *   produce. resetSequence returns null where the engine has nothing to do.
 *
 * ## Where the two engines still differ in more than spelling
 *
 * Worth knowing before treating any of this as a pure translation:
 *
 * - fromUnixtime() yields a local `datetime` on MySQL and a `timestamptz` on
 *   PostgreSQL. Wrapped in dateOf() - which is how MISP uses it - the two agree
 *   as long as the session time zone does.
 * - regexpMatch() quotes the pattern through the driver, and the drivers
 *   disagree about backslashes: MySQL's string literals treat `\` as an escape
 *   unless NO_BACKSLASH_ESCAPES is set, while PostgreSQL's standard_conforming_
 *   strings leaves it literal. A pattern with backslashes is not the same
 *   pattern on both engines, and no amount of quoting makes it so.
 * - upsert() needs a unique constraint over the conflict columns on
 *   PostgreSQL, where MySQL will match whichever unique key it likes.
 * - optimizeTable() renders `VACUUM ANALYZE` on PostgreSQL, which cannot run
 *   inside a transaction block.
 */
class SqlDialect
{
    const FLAVOUR_MYSQL = 'mysql';
    const FLAVOUR_PGSQL = 'pgsql';

    /**
     * @var DboSource
     */
    private $db;

    /**
     * @param DboSource|null $db Defaults to the 'default' connection.
     */
    public function __construct($db = null)
    {
        $this->db = $db === null ? ConnectionManager::getDataSource('default') : $db;
    }

    /**
     * The datasource this dialect renders for.
     *
     * Deliberately public: quoting is not exposed as dialect methods, so a
     * caller holding a dialect reaches name() and value() through here.
     *
     * @return DboSource
     */
    public function getDataSource()
    {
        return $this->db;
    }

    /**
     * Which engine this dialect is rendering for.
     *
     * Matches AppModel::isMysql()'s test, so MysqlExtended and the observer
     * variants all count as MySQL.
     *
     * @return string One of the FLAVOUR_* constants.
     */
    public function flavour()
    {
        return ($this->db instanceof Mysql) ? self::FLAVOUR_MYSQL : self::FLAVOUR_PGSQL;
    }

    // ------------------------------------------------------------ expressions

    /**
     * The date part of a datetime expression.
     *
     * Rendered as a cast rather than as `CAST(x AS DATE)` because these
     * fragments end up in CakePHP `fields` arrays, and DboSource's field
     * quoting mangles the bare `DATE` keyword inside a CAST - which is exactly
     * why the hand-written PostgreSQL branches in Log and AuditLog had to drop
     * out of the ORM and build their query as a string.
     *
     * The expression is parenthesised because `::` binds tighter than almost
     * everything, so an unparenthesised compound expression would cast only its
     * last term.
     *
     * @param string $expr An SQL expression, already quoted by the caller.
     * @return string
     */
    public function dateOf($expr)
    {
        if ($this->isMysql()) {
            return sprintf('DATE(%s)', $expr);
        }
        return sprintf('(%s)::date', $expr);
    }

    /**
     * A datetime expression as a Unix timestamp.
     *
     * @param string $expr An SQL expression, already quoted by the caller.
     * @return string
     */
    public function unixTimestamp($expr)
    {
        if ($this->isMysql()) {
            return sprintf('UNIX_TIMESTAMP(%s)', $expr);
        }
        return sprintf('EXTRACT(EPOCH FROM %s)::bigint', $expr);
    }

    /**
     * A Unix timestamp expression as a datetime.
     *
     * @param string $expr An SQL expression, already quoted by the caller.
     * @return string
     */
    public function fromUnixtime($expr)
    {
        if ($this->isMysql()) {
            return sprintf('FROM_UNIXTIME(%s)', $expr);
        }
        return sprintf('to_timestamp(%s)', $expr);
    }

    /**
     * A datetime expression formatted as `YYYY-MM`.
     *
     * The one format string MISP asks for, so it is a named method rather than
     * a general strftime-style translator: the format vocabularies are large,
     * only partly overlapping, and nothing here needs the rest of them.
     *
     * @param string $expr An SQL expression, already quoted by the caller.
     * @return string
     */
    public function formatYearMonth($expr)
    {
        if ($this->isMysql()) {
            return sprintf("DATE_FORMAT(%s, '%%Y-%%m')", $expr);
        }
        return sprintf("to_char(%s, 'YYYY-MM')", $expr);
    }

    /**
     * A regular-expression match.
     *
     * The pattern is a value and is quoted here; the expression is SQL and is
     * not. See the class docblock on backslashes - the quoting is correct on
     * both engines, but a pattern that relies on backslash escapes does not
     * mean the same thing on both.
     *
     * @param string $expr An SQL expression, already quoted by the caller.
     * @param string $pattern The pattern, unquoted.
     * @return string
     */
    public function regexpMatch($expr, $pattern)
    {
        $quoted = $this->db->value($pattern, 'string');
        if ($this->isMysql()) {
            return sprintf('%s REGEXP %s', $expr, $quoted);
        }
        return sprintf('%s ~ %s', $expr, $quoted);
    }

    // ------------------------------------------------------------- statements

    /**
     * Reclaim the space a table's deleted rows still occupy.
     *
     * Advisory on both engines - the table is queryable throughout and the
     * result is identical either way - but not free: MySQL rebuilds the table,
     * and the PostgreSQL rendering cannot run inside a transaction block.
     *
     * @param string $table Physical table name.
     * @return string One statement.
     */
    public function optimizeTable($table)
    {
        if ($this->isMysql()) {
            return sprintf('OPTIMIZE TABLE %s;', $this->db->name($table));
        }
        return sprintf('VACUUM ANALYZE %s;', $this->db->name($table));
    }

    /**
     * Complete an INSERT so that a row colliding with an existing key updates
     * it instead of failing.
     *
     * The conflict columns are required even though MySQL ignores them, in the
     * same spirit as the schema DSL's changeColumn: an author working on the
     * only engine they can run would otherwise omit the one part PostgreSQL
     * cannot infer, and the divergence would not show up until it ran there.
     * They must name a unique constraint or index on PostgreSQL; MySQL matches
     * whichever unique key the row collides with.
     *
     * MySQL's half deliberately uses `VALUES(col)` rather than 8.0.20's row
     * alias: the alias form is what the deprecation notice recommends, but
     * MariaDB does not have it, and MISP supports both.
     *
     * One PostgreSQL parse trap for an `INSERT ... SELECT`: if the SELECT ends
     * in a table reference, `FROM t ON CONFLICT` reads as the start of a join
     * condition and fails to parse. A WHERE or GROUP BY clause between them,
     * or a `WHERE true`, keeps the two apart.
     *
     * @param string $insert A complete INSERT statement, with or without its
     *   trailing semicolon.
     * @param array $conflictColumns The columns whose uniqueness is being
     *   violated.
     * @param array $updateColumns The columns to overwrite with the incoming
     *   row's values.
     * @return string One statement.
     * @throws InvalidArgumentException When either column list is empty.
     */
    public function upsert($insert, array $conflictColumns, array $updateColumns)
    {
        if (empty($conflictColumns)) {
            throw new InvalidArgumentException(
                'An upsert needs the columns it conflicts on. MySQL infers them, PostgreSQL cannot.'
            );
        }
        if (empty($updateColumns)) {
            throw new InvalidArgumentException(
                'An upsert needs at least one column to update. To ignore collisions instead, write the engine-specific statement.'
            );
        }
        $insert = rtrim(rtrim(trim($insert), ';'));
        $assignments = array();
        if ($this->isMysql()) {
            foreach ($updateColumns as $column) {
                $name = $this->db->name($column);
                $assignments[] = sprintf('%s = VALUES(%s)', $name, $name);
            }
            return sprintf('%s ON DUPLICATE KEY UPDATE %s;', $insert, implode(', ', $assignments));
        }
        foreach ($updateColumns as $column) {
            $name = $this->db->name($column);
            $assignments[] = sprintf('%s = EXCLUDED.%s', $name, $name);
        }
        $conflict = array();
        foreach ($conflictColumns as $column) {
            $conflict[] = $this->db->name($column);
        }
        return sprintf(
            '%s ON CONFLICT (%s) DO UPDATE SET %s;',
            $insert,
            implode(', ', $conflict),
            implode(', ', $assignments)
        );
    }

    /**
     * Bring a table's auto-increment counter back in line with its contents,
     * after rows were inserted with the key set by hand.
     *
     * MySQL has nothing to do - it tracks the high-water mark itself - so this
     * returns null there, and a caller runs the statement only when it gets
     * one. That null is the whole point of the method: the same logic is
     * currently open-coded behind an `isMysql()` branch in four places.
     *
     * The sequence is resolved through pg_get_serial_sequence() rather than
     * composed as `<table>_<column>_seq`, which is only the default name:
     * PostgreSQL truncates identifiers at 63 characters, and a sequence can be
     * renamed or attached to a differently named column. The three-argument
     * setval() form is what makes an empty table safe - is_called goes false,
     * so the next value is 1 rather than 2.
     *
     * @param string $table Physical table name.
     * @param string $column The auto-incrementing column.
     * @return string|null One statement, or null when the engine needs none.
     */
    public function resetSequence($table, $column = 'id')
    {
        if ($this->isMysql()) {
            return null;
        }
        $name = $this->db->name($column);
        return sprintf(
            'SELECT setval(pg_get_serial_sequence(%s, %s), COALESCE(MAX(%s), 1), MAX(%s) IS NOT NULL) FROM %s;',
            $this->db->value($table, 'string'),
            $this->db->value($column, 'string'),
            $name,
            $name,
            $this->db->name($table)
        );
    }

    /**
     * @return bool
     */
    private function isMysql()
    {
        return $this->db instanceof Mysql;
    }
}
