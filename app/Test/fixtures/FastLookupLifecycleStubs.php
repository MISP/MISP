<?php
if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}
class Configure
{
    public static $values = ['MISP.fast_lookup_enabled' => true];
    public static function read($name) { return self::$values[$name] ?? null; }
}
class FastLookupConfig
{
    public static $fingerprint = 'scope-one';
    public static function scope($attribute = null) { return ['attribute_types' => ['domain'], 'published_only' => true, 'max_values' => 10000, 'matching' => ['exact', 'ip_cidr', 'parent_domain']]; }
    public static function namespaceFor($attribute) { return 'test-database'; }
    public static function fingerprint($attribute) { return self::$fingerprint; }
}
class FastLookupValueTool
{
    public function __construct($attribute) {}
    public function prepareAttributes(array $rows) { return $rows; }
}
class FastLookupLifecycleAttribute
{
    public $db;
    public $alias = 'Attribute';
    public $Event;
    public $useTable = 'attributes';
    public function __construct() { $this->db = new FastLookupLifecycleConnection(); $this->Event = (object)['useTable' => 'events']; }
    public function getDataSource() { return $this->db; }
    public function log($message, $level) {}
}
class FastLookupLifecycleStatement
{
    private $db;
    private $sql;
    private $rows;
    public function __construct($db, $sql) { $this->db = $db; $this->sql = $sql; }
    public function execute($args = []) { $this->rows = $this->db->execute($this->sql, $args); return true; }
    public function fetch($mode = null) { return array_shift($this->rows) ?: false; }
    public function fetchAll($mode = null) { return $this->rows; }
    public function fetchColumn() { $row = $this->fetch(); return $row ? reset($row) : false; }
    public function closeCursor() {}
}
class FastLookupLifecycleConnection
{
    public $settings = [];
    public $events = [];
    public $attributes = [];
    public $config = ['datasource' => 'Database/Mysql', 'prefix' => ''];
    private $snapshot;
    public function getConnection() { return $this; }
    public function fullTableName($model) { return is_string($model) ? $model : $model->useTable; }
    public function name($name) { return $name; }
    public function getAttribute($attribute) { return 'mysql'; }
    public function inTransaction() { return $this->snapshot !== null; }
    public function beginTransaction() { if ($this->inTransaction()) { throw new LogicException('Nested transaction'); } $this->snapshot = $this->settings; return true; }
    public function commit() { $this->snapshot = null; return true; }
    public function rollBack() { $this->settings = $this->snapshot; $this->snapshot = null; return true; }
    public function prepare($sql) { return new FastLookupLifecycleStatement($this, $sql); }
    public function execute($sql, $args)
    {
        if (strpos($sql, 'admin_settings') !== false) {
            if (strpos($sql, 'INSERT') === 0) {
                if (strpos($sql, 'DO NOTHING') === false && strpos($sql, 'setting = setting') === false || !isset($this->settings[$args[0]])) {
                    $this->settings[$args[0]] = $args[1];
                }
                return [];
            }
            if (strpos($sql, 'UPDATE') === 0) { $this->settings[$args[1]] = $args[0]; return []; }
            if (strpos($sql, 'DELETE') === 0) {
                if (count($args) === 1 || ($this->settings[$args[0]] ?? null) === $args[1]) { unset($this->settings[$args[0]]); }
                return [];
            }
            if (strpos($sql, ' LIKE ') !== false) {
                $rows = [];
                foreach ($this->settings as $key => $value) {
                    if (strpos($key, rtrim($args[0], '%')) === 0) { $rows[] = ['setting' => $key, 'value' => $value]; }
                }
                if (strpos($sql, 'COUNT(') !== false) { return [['count' => count($rows)]]; }
                if (preg_match('/LIMIT (\d+)/', $sql, $match)) { $rows = array_slice($rows, 0, (int)$match[1]); }
                return $rows;
            }
            $key = strpos($sql, 'WHERE id = ?') !== false ? 'fastLookupIndex:state:v2' : $args[0];
            return isset($this->settings[$key]) ? [strpos($sql, 'SELECT id ') === 0 ? ['id' => 1] : ['value' => $this->settings[$key]]] : [];
        }
        if (strpos($sql, 'FROM events') !== false) {
            $publishedOnly = strpos($sql, 'published = TRUE') !== false;
            $events = array_filter($this->events, function ($published) use ($publishedOnly) { return !$publishedOnly || $published; });
            if (strpos($sql, 'COUNT(') !== false) { return [['total' => count($events), 'high_water' => $events ? max(array_keys($events)) : '0']]; }
            if (strpos($sql, 'WHERE id = ?') !== false) { return array_key_exists($args[0], $events) ? [['published' => $events[$args[0]]]] : []; }
            $rows = [];
            foreach ($events as $id => $published) { if ($id > $args[0] && $id <= $args[1]) { $rows[] = ['id' => (string)$id]; } }
            usort($rows, function ($a, $b) { return (int)$a['id'] <=> (int)$b['id']; });
            preg_match('/LIMIT (\d+)/', $sql, $match);
            return array_slice($rows, 0, (int)$match[1]);
        }
        if (strpos($sql, 'FROM attributes') !== false) {
            $rows = array_filter($this->attributes, function ($row) use ($args) { return $row['event_id'] === $args[0] && (int)$row['id'] > (int)$args[1] && !$row['deleted'] && in_array($row['type'], array_slice($args, 2), true); });
            return array_values(array_slice($rows, 0, 500));
        }
        throw new LogicException('Unexpected SQL: ' . $sql);
    }
}
class FastLookupLifecycleIndex
{
    public $meta = [];
    public $events = [];
    public $available = true;
    public $failNextWrite = false;
    public $failInitialise = false;
    public $afterWrite;
    public function metadata() { if (!$this->available || !$this->meta) { throw new RuntimeException('Redis unavailable'); } return $this->meta; }
    public function initialise($generation, $fingerprint, $progress) {
        if (($this->meta['generation'] ?? null) === $generation) { throw new InvalidArgumentException('Generation must be new.'); }
        $this->events = [];
        $this->meta = ['generation' => $generation, 'fingerprint' => $fingerprint, 'revision' => '0', 'ready' => false, 'progress' => $progress];
        if ($this->failInitialise) { $this->failInitialise = false; throw new RuntimeException('Interrupted initialisation'); }
    }
    public $afterCheckpoint;
    public function checkpoint($generation, $revision, $progress, $ready) { $this->metadata(); $this->meta = array_merge($this->meta, compact('generation', 'revision', 'progress', 'ready')); if ($this->afterCheckpoint) { ($this->afterCheckpoint)(); } }
    public function beginEvent($generation, $eventId) { $this->events[$eventId] = []; }
    public function addAttributes($generation, $eventId, $rows) { if ($this->failNextWrite) { $this->failNextWrite = false; throw new RuntimeException('Interrupted write'); } $this->events[$eventId] = array_merge($this->events[$eventId], $rows); }
    public function endEvent($generation, $eventId) { if ($this->afterWrite) { ($this->afterWrite)(); } }
    public function removeEvent($generation, $eventId) { unset($this->events[$eventId]); }
    public function statistics($generation) { return ['types' => [], 'shared_memory_bytes' => 0]; }
}
