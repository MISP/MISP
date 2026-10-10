<?php

/**
 * Turns one flavour-agnostic schema operation into the SQL a given engine wants.
 *
 * A grammar renders; it never executes. SchemaBuilder collects operations and
 * hands them here one at a time, and every method returns an array of complete
 * statements - an array rather than a string because the same operation can be
 * one statement on MySQL and three on PostgreSQL (see PostgresGrammar's
 * changeColumn).
 *
 * ## What is borrowed and what is ours
 *
 * Most of the type work is already done. DboSource::buildColumn() renders a
 * field spec through the driver's own $columns map, so `boolean` becomes
 * tinyint(1) on MySQL and boolean on PostgreSQL with no branching here. Its
 * _buildFieldParameters() pass then reads the driver's $fieldParameters, and
 * because Mysql declares charset/collate/comment/unsigned while Postgres
 * declares none, those hints are emitted on one engine and dropped on the other
 * for free. buildTableParameters() does the same for ENGINE and the table
 * charset. name() and value() handle identifier and literal quoting.
 *
 * What CakePHP has no answer for, and this class therefore owns: RENAME COLUMN,
 * RENAME TABLE, index DDL beyond the create-table clause, positional `after`,
 * prefix-length indexes, FULLTEXT, and the three column types MISP uses that
 * Cake's map is missing.
 *
 * ## The type-map extension
 *
 * Cake's Mysql map has no mediumtext, longtext or varbinary, and the current
 * MISP schema uses all three - so without an extension a migration touching one
 * of those columns simply could not be expressed. Each grammar declares its own
 * additions in $extraColumns and swaps the merged map into the public
 * $db->columns around each buildColumn() call, restoring it in a finally. The
 * merge is strictly additive - a key Cake already defines is never shadowed -
 * so Model::schema() and value() behave identically even mid-swap.
 *
 * ## Dropped hints
 *
 * A hint that one engine cannot express is dropped, not translated. That is
 * safe for `after` (cosmetic column ordering) and for unsigned/collate (storage
 * and comparison details PostgreSQL expresses differently or not at all). It is
 * *not* safe for a prefix length, which changes what the index actually indexes,
 * so anything dropped is recorded in $droppedHints for the caller to log rather
 * than vanishing quietly. FULLTEXT is not dropped at all - it is rejected, with
 * a message pointing at rawSql().
 */
abstract class AbstractGrammar
{
    const FLAVOUR_MYSQL = 'mysql';
    const FLAVOUR_PGSQL = 'pgsql';

    /**
     * @var DboSource
     */
    protected $db;

    /**
     * Type-map additions on top of the driver's own $columns. Strictly additive.
     *
     * @var array
     */
    protected $extraColumns = array();

    /**
     * Column options that are ours, not CakePHP's. Stripped from a spec before
     * it reaches buildColumn(), which would not know what to do with them.
     *
     * @var array
     */
    protected static $ownColumnOptions = array('after');

    /**
     * Human-readable notes about hints this grammar could not express.
     *
     * @var array
     */
    protected $droppedHints = array();

    public function __construct(DboSource $db)
    {
        $this->db = $db;
    }

    /**
     * The grammar for a connection.
     *
     * The MySQL test mirrors AppModel::isMysql(), so MysqlExtended and the
     * observer variants all resolve to MysqlGrammar.
     *
     * @param DboSource $db
     * @return AbstractGrammar
     */
    public static function forDataSource(DboSource $db)
    {
        if ($db instanceof Mysql) {
            App::uses('MysqlGrammar', 'Migration/Grammar');
            return new MysqlGrammar($db);
        }
        App::uses('PostgresGrammar', 'Migration/Grammar');
        return new PostgresGrammar($db);
    }

    /**
     * A grammar for an engine this host cannot connect to.
     *
     * Rendering needs a datasource - for the type map, identifier quoting and
     * literal quoting - but it never needs the socket underneath it. The
     * offline datasources supply the first without opening the second, which is
     * what lets a dry run print both flavours on a host that has only one PDO
     * driver installed. That is every host: MISP requires neither pdo_mysql nor
     * pdo_pgsql, and the PostgreSQL one is essentially never present.
     *
     * @param string $flavour One of the FLAVOUR_* constants.
     * @return AbstractGrammar
     * @throws InvalidArgumentException On a flavour with no grammar behind it.
     */
    public static function offline($flavour)
    {
        if ($flavour === self::FLAVOUR_MYSQL) {
            App::uses('OfflineMysql', 'Migration/Grammar');
            return self::forDataSource(new OfflineMysql());
        }
        if ($flavour === self::FLAVOUR_PGSQL) {
            App::uses('OfflinePostgres', 'Migration/Grammar');
            return self::forDataSource(new OfflinePostgres());
        }
        throw new InvalidArgumentException(sprintf(
            'No grammar for the flavour "%s". Known flavours are: %s.',
            $flavour,
            implode(', ', self::flavours())
        ));
    }

    /**
     * @return array Every flavour a migration is rendered for, in the order a
     *   dry run prints them.
     */
    public static function flavours()
    {
        return array(self::FLAVOUR_MYSQL, self::FLAVOUR_PGSQL);
    }

    /**
     * @return string One of the FLAVOUR_* constants.
     */
    abstract public function flavour();

    /**
     * @return DboSource
     */
    public function getDataSource()
    {
        return $this->db;
    }

    // ---------------------------------------------------------------- schema

    /**
     * @param string $table
     * @param array $columns name => spec, where a spec is an array with at least a 'type'.
     * @param array $options 'indexes', plus any table parameters the engine understands.
     * @return array Statements.
     */
    abstract public function createTable($table, array $columns, array $options = array());

    /**
     * @param string $table
     * @return array Statements.
     */
    public function dropTable($table)
    {
        return array(sprintf('DROP TABLE %s;', $this->name($table)));
    }

    /**
     * @param string $from
     * @param string $to
     * @return array Statements.
     */
    abstract public function renameTable($from, $to);

    // ----------------------------------------------------------------- table

    /**
     * @param string $table
     * @param string $column
     * @param string $type
     * @param array $options
     * @return array Statements.
     */
    abstract public function addColumn($table, $column, $type, array $options = array());

    /**
     * @param string $table
     * @param string $column
     * @param string $type
     * @param array $options Must state 'null' and 'default' - see assertCompleteRedefinition().
     * @return array Statements.
     */
    public function changeColumn($table, $column, $type, array $options = array())
    {
        $this->assertCompleteRedefinition('changeColumn', $table, $column, $options);
        return $this->renderChangeColumn($table, $column, $type, $options);
    }

    /**
     * @param string $table
     * @param string $from
     * @param string $to
     * @param string $type The new column's type. MySQL's CHANGE needs it restated; so does PostgreSQL.
     * @param array $options Must state 'null' and 'default' - see assertCompleteRedefinition().
     * @return array Statements.
     */
    public function renameColumn($table, $from, $to, $type, array $options = array())
    {
        $this->assertCompleteRedefinition('renameColumn', $table, $to, $options);
        return $this->renderRenameColumn($table, $from, $to, $type, $options);
    }

    /**
     * @return array Statements.
     */
    abstract protected function renderChangeColumn($table, $column, $type, array $options);

    /**
     * @return array Statements.
     */
    abstract protected function renderRenameColumn($table, $from, $to, $type, array $options);

    /**
     * @param string $table
     * @param string $column
     * @return array Statements.
     */
    public function dropColumn($table, $column)
    {
        return array(sprintf(
            'ALTER TABLE %s DROP COLUMN %s;',
            $this->name($table),
            $this->name($column)
        ));
    }

    /**
     * Drop a table's primary key constraint. The columns stay; only the
     * constraint goes, so that another can take its place - the way a table
     * keyed on a natural column gets an id.
     *
     * @param string $table
     * @return array Statements.
     */
    abstract public function dropPrimaryKey($table);

    /**
     * @param string $table
     * @param string|array $columns
     * @param array $options 'unique', 'name', 'length', 'fulltext'.
     * @return array Statements.
     */
    abstract public function addIndex($table, $columns, array $options = array());

    /**
     * @param string $table
     * @param string|array $columnsOrName The column set, or the index's own name.
     * @return array Statements.
     */
    abstract public function dropIndex($table, $columnsOrName);

    /**
     * The physical name this grammar gives an index.
     *
     * @param string $table
     * @param string|array $columns
     * @param array $options
     * @return string
     */
    abstract public function indexName($table, $columns, array $options = array());

    // --------------------------------------------------------------- helpers

    /**
     * Identifier quoting, straight off the driver.
     *
     * @param string $identifier
     * @return string
     */
    public function name($identifier)
    {
        return $this->db->name($identifier);
    }

    /**
     * Type-aware literal quoting, straight off the driver.
     *
     * @param mixed $data
     * @param string|null $type
     * @return string
     */
    public function value($data, $type = null)
    {
        return $this->db->value($data, $type);
    }

    /**
     * Hints this grammar could not express, since the last time they were taken.
     *
     * @return array
     */
    public function takeDroppedHints()
    {
        $dropped = $this->droppedHints;
        $this->droppedHints = array();
        return $dropped;
    }

    /**
     * Render a full column definition - name, type, modifiers - via the driver.
     *
     * @param array $spec Must carry 'name' and 'type'.
     * @return string
     * @throws InvalidArgumentException On a missing or unrenderable type.
     */
    protected function buildColumn(array $spec)
    {
        $spec = $this->normaliseColumn($spec);
        $this->assertRenderable($spec);

        $original = $this->db->columns;
        $this->db->columns = $this->mergedColumns();
        try {
            $sql = $this->db->buildColumn($this->stripOwnOptions($spec));
        } finally {
            $this->db->columns = $original;
        }

        if ($sql === null) {
            throw new InvalidArgumentException(sprintf(
                'Could not render column "%s" of type "%s" for %s.',
                $spec['name'],
                $spec['type'],
                $this->flavour()
            ));
        }
        return $sql;
    }

    /**
     * " PRIMARY KEY" when a column added on its own is the table's key, else "".
     *
     * createTable() states the key as a table constraint after the columns;
     * an ADD of a single column has no such place, and MySQL refuses an
     * AUTO_INCREMENT column that is not made a key in the same statement, so
     * the constraint rides on the column. Both engines accept it there.
     *
     * @param array $spec
     * @return string
     */
    protected function primaryKeyClause(array $spec)
    {
        $spec = $this->normaliseColumn($spec);
        return (isset($spec['key']) && $spec['key'] === 'primary') ? ' PRIMARY KEY' : '';
    }

    /**
     * Render just the type - "varchar(40)", "int(11)" - with no name and no
     * modifiers. PostgreSQL's ALTER COLUMN ... TYPE needs it in isolation.
     *
     * @param array $spec
     * @return string
     */
    protected function renderType(array $spec)
    {
        $spec = $this->normaliseColumn($spec);
        $this->assertRenderable($spec);

        $real = $this->mergedColumns();
        $real = $real[$spec['type']];
        $out = $real['name'];

        $length = null;
        foreach (array('length', 'limit') as $key) {
            if (isset($spec[$key])) {
                $length = $spec[$key];
                break;
            }
        }
        if ($length === null) {
            foreach (array('length', 'limit') as $key) {
                if (isset($real[$key])) {
                    $length = $real[$key];
                    break;
                }
            }
        }
        if ($length !== null) {
            $out .= '(' . $length . ')';
        }
        return $out;
    }

    /**
     * Fold the DSL's own spellings into what buildColumn() expects.
     *
     * Only one so far: `primary_key`. Cake's map entry for it holds the trailing
     * modifier alone ("NOT NULL AUTO_INCREMENT" / "serial NOT NULL"), never a
     * type - passing it through verbatim would emit `id` NOT NULL AUTO_INCREMENT
     * with no type at all. The driver expects an integer column flagged
     * primary instead, which renders as int(11) NOT NULL AUTO_INCREMENT on MySQL
     * and serial NOT NULL on PostgreSQL.
     *
     * @param array $spec
     * @return array
     */
    protected function normaliseColumn(array $spec)
    {
        if (isset($spec['type']) && $spec['type'] === 'primary_key') {
            $spec['type'] = 'integer';
            $spec['key'] = 'primary';
        }
        return $spec;
    }

    /**
     * Redefining a column means redefining all of it.
     *
     * MySQL's MODIFY and CHANGE replace the column's entire definition: a
     * nullability or default that is not restated is dropped. PostgreSQL's ALTER
     * COLUMN ... TYPE changes only the type and leaves both alone. So the same
     * migration, written without saying what it wants, gives a nullable
     * defaultless column on one engine and an untouched one on the other - a
     * divergence that shows up months later on whichever engine the author was
     * not looking at.
     *
     * Rather than pick a winner and emulate it (which would mean reading the
     * live schema mid-render), the DSL requires the caller to say. 'null' and
     * 'default' must both be present; 'default' => null is the explicit way to
     * say the column has none.
     *
     * This is a deliberate tightening of the PRD's section 6.3 signature, where
     * both options were optional.
     *
     * @param string $operation
     * @param string $table
     * @param string $column
     * @param array $options
     * @return void
     * @throws InvalidArgumentException
     */
    protected function assertCompleteRedefinition($operation, $table, $column, array $options)
    {
        $missing = array();
        foreach (array('null', 'default') as $option) {
            if (!array_key_exists($option, $options)) {
                $missing[] = $option;
            }
        }
        if (empty($missing)) {
            return;
        }
        throw new InvalidArgumentException(sprintf(
            '%s(%s.%s) must state %s. MySQL rewrites the whole column definition and drops whatever is left unsaid, while PostgreSQL leaves it in place - so an unstated option means the two engines end up with different columns. Pass "default" => null if the column has no default.',
            $operation,
            $table,
            $column,
            implode(' and ', $missing)
        ));
    }

    /**
     * @param array $spec
     * @return void
     * @throws InvalidArgumentException
     */
    protected function assertRenderable(array $spec)
    {
        if (empty($spec['name'])) {
            throw new InvalidArgumentException('A column spec needs a name.');
        }
        if (empty($spec['type'])) {
            throw new InvalidArgumentException(sprintf(
                'Column "%s" has no type.',
                $spec['name']
            ));
        }
        if (strpos($spec['type'], 'enum') === 0) {
            throw new InvalidArgumentException(sprintf(
                'Column "%s": enum is MySQL-only and has no portable rendering. Declare it with rawSql() instead.',
                $spec['name']
            ));
        }
        $known = $this->mergedColumns();
        if (!isset($known[$spec['type']])) {
            throw new InvalidArgumentException(sprintf(
                'Column "%s": %s has no rendering for type "%s". Use one of: %s - or rawSql() for anything engine-specific.',
                $spec['name'],
                $this->flavour(),
                $spec['type'],
                implode(', ', array_keys($known))
            ));
        }
    }

    /**
     * The type map buildColumn() and renderType() render against: the driver's
     * own $columns plus this grammar's additions.
     *
     * Additive by construction - array_merge puts the driver's keys last, so a
     * type Cake already defines can never be redefined out from under
     * Model::schema() while the map is swapped in. A grammar that needs to
     * *correct* a driver entry rather than add to it overrides this method and
     * says why (PostgresGrammar does, for length modifiers Cake emits that
     * PostgreSQL does not accept).
     *
     * @return array
     */
    protected function mergedColumns()
    {
        return array_merge($this->extraColumns, $this->db->columns);
    }

    /**
     * @param array $spec
     * @return array
     */
    protected function stripOwnOptions(array $spec)
    {
        foreach (static::$ownColumnOptions as $option) {
            unset($spec[$option]);
        }
        return $spec;
    }

    /**
     * Normalise a createTable() column map into full specs, and pick out the
     * primary key - declared either as the `primary_key` type or as an ordinary
     * type with `key => primary`.
     *
     * @param array $columns
     * @return array array($specs, $primaryKey)
     */
    protected function partitionColumns(array $columns)
    {
        $specs = array();
        $primaryKey = null;
        foreach ($columns as $name => $spec) {
            if (is_string($spec)) {
                $spec = array('type' => $spec);
            }
            $spec['name'] = $name;
            if (
                (isset($spec['type']) && $spec['type'] === 'primary_key') ||
                (isset($spec['key']) && $spec['key'] === 'primary')
            ) {
                $primaryKey = $name;
            }
            $specs[$name] = $spec;
        }
        return array($specs, $primaryKey);
    }

    /**
     * Unpack one entry of createTable()'s `indexes` map.
     *
     * The map is keyed by index name, and the simple case lets that key double
     * as the column: `'uuid' => array('unique' => true)`. A composite index
     * keeps the key as its name and states its columns in the options:
     * `'lookup' => array('column' => array('a', 'b'))`.
     *
     * @param string $key
     * @param array|null $options
     * @return array array($columns, $options)
     */
    protected function normaliseIndexDeclaration($key, $options)
    {
        $options = is_array($options) ? $options : array();
        $columns = isset($options['column']) ? $options['column'] : $key;
        if (!isset($options['name'])) {
            $options['name'] = $key;
        }
        return array($columns, $options);
    }

    /**
     * @param string|array $columns
     * @return array
     */
    protected function columnList($columns)
    {
        return array_values((array)$columns);
    }

    /**
     * @param string $note
     * @return void
     */
    protected function noteDroppedHint($note)
    {
        $this->droppedHints[] = $note;
    }
}
