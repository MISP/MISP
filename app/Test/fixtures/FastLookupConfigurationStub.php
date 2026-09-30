<?php
/** Loaded only inside isolated tests; never replaces other suites' Configure. */
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = [];
        public static function read($key) { return self::$values[$key] ?? null; }
        public static function write($key, $value) { self::$values[$key] = $value; }
        public static function delete($key) { unset(self::$values[$key]); }
        public static function clear() { self::$values = []; }
    }
}
if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}

if (!class_exists('FastLookupPrefixesChangedException', false) && class_exists('FastLookupIndexUnavailableException', false)) {
    class FastLookupPrefixesChangedException extends FastLookupIndexUnavailableException {}
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static $warnings = [];
        public static function warning($message) { self::$warnings[] = $message; }
    }
}

class FastLookupTestStatement
{
    private $rows;
    private $offset = 0;
    public $closed = false;
    public function __construct(array $rows) { $this->rows = $rows; }
    public function fetch($mode) { return $this->rows[$this->offset++] ?? false; }
    public function closeCursor() { $this->closed = true; }
}

class FastLookupTestDatasource
{
    public $config = ['host' => 'db', 'database' => 'misp', 'password' => 'secret'];
    public $queries = [];
    public $responses = [];
    public $version = '10.11.6-MariaDB';
    public function name($name) { return '`' . str_replace('.', '`.`', $name) . '`'; }
    public function value($value, $type = null) { return "'" . str_replace("'", "''", $value) . "'"; }
    public function fullTableName($model) { return $this->name($model->useTable); }
    public function conditions($conditions, $quote, $where, $model)
    {
        return '`Event`.`org_id` = 7 AND (`Attribute`.`object_id` = 0 OR `Object`.`distribution` = 5)';
    }
    public function getConnection() { return $this; }
    public function getAttribute($attribute) { return $this->version; }
    /** Case-folding per-byte weights "\x00" . strtoupper(byte); a space weighs like the pad "\x00 ". */
    public static function asciiWeightTable(): array
    {
        $table = [];
        for ($n = 0; $n < 128; ++$n) {
            $table[chr($n)] = "\x00" . strtoupper(chr($n));
        }
        return $table;
    }

    /** A wide weights row: value cells, the ASCII table and its probe weight, then pad cells. */
    public static function weightRow(array $valueCells, array $padCells = ["\x00 "]): array
    {
        $table = self::asciiWeightTable();
        return array_merge($valueCells, array_values($table), [strtr(rtrim(FastLookupValueTool::ASCII_PROBE, ' '), $table)], $padCells);
    }

    public function rawQuery($sql)
    {
        $this->queries[] = $sql;
        if (!$this->responses) {
            throw new RuntimeException('Unexpected SQL query.');
        }
        return new FastLookupTestStatement(array_shift($this->responses));
    }
}

class FastLookupTestAttribute
{
    public $useTable = 'attributes';
    public $Event;
    public $Object;
    public $db;
    public $users = [];
    public $typeDefinitions;
    public $columns = [
        'value1' => ['charset' => 'utf8mb3', 'collate' => 'utf8mb3_unicode_ci'],
        'value2' => ['charset' => 'utf8mb3', 'collate' => 'utf8mb3_unicode_ci'],
    ];
    public function __construct()
    {
        $this->db = new FastLookupTestDatasource();
        $this->Event = (object)['useTable' => 'events'];
        $this->Object = (object)['useTable' => 'objects'];
        $this->typeDefinitions = array_fill_keys([
            'domain', 'domain|ip', 'hostname', 'hostname|port', 'ip-src', 'ip-dst',
            'ip-src|port', 'ip-dst|port', 'md5', 'sha1', 'sha256', 'sha512',
            'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha512',
            'malware-sample', 'text', 'url', 'port',
        ], []);
    }
    public function getDataSource() { return $this->db; }
    public function schema($field) { return $this->columns[$field]; }
    public function buildConditions($user)
    {
        $this->users[] = $user;
        return ['Event.org_id' => 7];
    }
}

class FastLookupTestFilter
{
    /** The filter's reply; null answers "absent" for every queried position, like the real filter. */
    public $hits = null;
    public $reads = [];
    public $prefixes = ['version' => '', 'lengths' => null];
    public $prefixReads = 0;
    /** Answers to successive prefixLengths() calls; $prefixes once exhausted. */
    public $prefixSequence = [];
    /** The next candidates() calls with a prefix version that report a prefix-version change. */
    public $changes = 0;
    /** Once the prefix-version changes are used up, candidates() reports a full filter. */
    public $full = false;
    public function prefixLengths($generation)
    {
        ++$this->prefixReads;
        return $this->prefixSequence ? array_shift($this->prefixSequence) : $this->prefixes;
    }
    public function candidates($generation, array $tokens, $maximumIds = 100000, $prefixVersion = null)
    {
        $this->reads[] = [$generation, $tokens, $maximumIds, $prefixVersion];
        if ($prefixVersion !== null && $this->changes-- > 0) {
            throw new FastLookupPrefixesChangedException('changed');
        }
        if ($this->full) {
            throw new FastLookupIndexFullException($generation);
        }
        if ($this->hits === null) {
            return array_map(function () { return ['exact' => false, 'ip_range' => [], 'domain' => []]; }, $tokens);
        }
        return $this->hits;
    }
}

class FastLookupTestManager
{
    public $snapshot;
    public $current = true;
    public $index;
    public $reads = 0;
    public function __construct()
    {
        $this->index = new FastLookupTestFilter();
        $this->snapshot = ['status' => 'ready', 'generation' => 'generation-one', 'revision' => 'revision-one'];
    }
    public function status($metrics = false) { ++$this->reads; return $this->snapshot; }
    public function filter() { return $this->index; }
    public function isCurrent(array $snapshot) { return $this->current; }
}
