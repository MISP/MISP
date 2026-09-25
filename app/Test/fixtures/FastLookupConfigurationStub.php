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

class FastLookupTestIndex
{
    public $hits = [];
    public $reads = [];
    public function candidates($generation, array $tokens, $maximumIds = 100000)
    {
        $this->reads[] = [$generation, $tokens, $maximumIds];
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
        $this->index = new FastLookupTestIndex();
        $this->snapshot = ['status' => 'ready', 'generation' => 'generation-one', 'revision' => 'revision-one'];
    }
    public function status($metrics = false) { ++$this->reads; return $this->snapshot; }
    public function index() { return $this->index; }
    public function isCurrent(array $snapshot) { return $this->current; }
}
