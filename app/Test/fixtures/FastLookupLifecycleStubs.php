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
    public static function scope($attribute = null) { return ['attribute_types' => ['domain'], 'published_only' => true, 'max_values' => 10000, 'matching' => ['exact', 'ip_cidr', 'parent_domain'], 'false_positive_rate' => 0.001]; }
    public static function namespaceFor($attribute) { return 'test-database'; }
    public static function fingerprint($attribute) { return self::$fingerprint; }
}
class FastLookupValueTool
{
    public function __construct($attribute) {}
    public function scanColumns($alias) { return "$alias.id AS id, $alias.event_id AS event_id, $alias.type AS type, $alias.value1 AS value1, $alias.value2 AS value2"; }
    public function prepareScannedAttributes(array $rows) { return $rows; }
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
    /** Another process holds the worker lock. */
    public $workerLockBusy = false;
    public $workerLocks = 0;
    /** Per rebuild-scan query: whether a transaction or the worker lock was held. */
    public $scans = [];
    /** Per dirty-event refresh query: whether a transaction was open. */
    public $refreshes = [];
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
        if (strpos($sql, 'GET_LOCK(') !== false) {
            if ($this->workerLockBusy) { return [['acquired' => 0]]; }
            ++$this->workerLocks;
            return [['acquired' => 1]];
        }
        if (strpos($sql, 'RELEASE_LOCK(') !== false) {
            --$this->workerLocks;
            return [['released' => 1]];
        }
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
            $key = strpos($sql, 'WHERE id = ?') !== false ? 'fastLookupIndex:state:v3' : $args[0];
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
        if (strpos($sql, 'MAX(id)') !== false) {
            $ids = array_map('intval', array_column($this->attributes, 'id'));
            return [['high_water' => $ids ? (string)max($ids) : null]];
        }
        if (strpos($sql, 'GROUP BY type') !== false) {
            $counts = [];
            foreach ($this->attributes as $row) {
                if (in_array($row['type'], $args, true)) { $counts[$row['type']] = ($counts[$row['type']] ?? 0) + 1; }
            }
            $rows = [];
            foreach ($counts as $type => $count) { $rows[] = ['type' => $type, 'attributes' => $count]; }
            return $rows;
        }
        if (strpos($sql, 'FROM attributes') !== false) {
            preg_match('/LIMIT (\d+)/', $sql, $match);
            if (strpos($sql, 'a.event_id = ?') !== false) {
                $this->refreshes[] = ['transaction' => $this->inTransaction()];
                [$eventId, $after] = $args;
                $types = array_slice($args, 2);
                $keep = function ($row) use ($eventId, $after, $types) { return $row['event_id'] === $eventId && (int)$row['id'] > (int)$after; };
            } else {
                $this->scans[] = ['transaction' => $this->inTransaction(), 'worker_lock' => $this->workerLocks > 0];
                [$after, $highWater] = $args;
                $types = array_slice($args, 2);
                $published = strpos($sql, 'e.published = TRUE') !== false;
                $keep = function ($row) use ($after, $highWater, $published) {
                    return (int)$row['id'] > (int)$after && (int)$row['id'] <= (int)$highWater
                        && array_key_exists($row['event_id'], $this->events) && (!$published || $this->events[$row['event_id']]);
                };
            }
            $rows = array_values(array_filter($this->attributes, function ($row) use ($keep, $types) {
                return $keep($row) && !$row['deleted'] && in_array($row['type'], $types, true);
            }));
            usort($rows, function ($a, $b) { return (int)$a['id'] <=> (int)$b['id']; });
            return array_slice($rows, 0, (int)$match[1]);
        }
        throw new LogicException('Unexpected SQL: ' . $sql);
    }
}
class FastLookupLifecycleFilter
{
    const MIN_CAPACITY = 1000000;
    public $meta = [];
    /** generation => ['rows' => [attribute id => row], 'info' => generation state] */
    public $generations = [];
    public $available = true;
    public $moduleAvailable = true;
    public $failNextWrite = false;
    public $failReserve = false;
    public $afterWrite;
    public $afterCheckpoint;
    /** Runs after activate() has swapped the generations, like its old-key cleanup. */
    public $afterActivate;
    /** reserve() arguments in call order. */
    public $reserved = [];
    public function moduleAvailable() { return $this->moduleAvailable; }
    public function metadata()
    {
        if (!$this->available || !$this->meta) { throw new RuntimeException('Redis unavailable'); }
        $meta = $this->meta;
        $meta['generations'] = [];
        if ($meta['live'] !== null) {
            if (!isset($this->generations[$meta['live']])) { throw new RuntimeException('Missing generation'); }
            $meta['generations'][$meta['live']] = $this->generations[$meta['live']]['info'];
        }
        // Like the real filter: a missing building generation is omitted.
        if ($meta['building'] !== null && isset($this->generations[$meta['building']])) {
            $meta['generations'][$meta['building']] = $this->generations[$meta['building']]['info'];
        }
        return $meta;
    }
    public function reserve($generation, $fingerprint, $capacity, $rate, $rangeEntries)
    {
        $this->reserved[] = compact('generation', 'fingerprint', 'capacity', 'rate', 'rangeEntries');
        if ($this->failReserve) { $this->failReserve = false; throw new RuntimeException('Interrupted reservation'); }
        if ($this->meta) {
            // Like the real filter: unusable metadata cannot be served, so reserve() starts a clean namespace.
            try { $this->metadata(); } catch (RuntimeException $e) { if (!$this->available) { throw $e; } $this->meta = []; $this->generations = []; }
        }
        if (!$this->meta) {
            $this->meta = ['live' => null, 'building' => null, 'fingerprint' => null, 'building_fingerprint' => null, 'revision' => '0', 'ready' => false];
        }
        if ($this->meta['live'] === $generation || isset($this->generations[$generation])) { throw new InvalidArgumentException('Generation must be new.'); }
        foreach (array_keys($this->generations) as $old) {
            if ($old !== $this->meta['live']) { unset($this->generations[$old]); }
        }
        $this->generations[$generation] = ['rows' => [], 'info' => ['capacity' => $capacity, 'rate' => $rate, 'inserted' => 0, 'stale' => 0, 'buckets' => 1, 'cursor' => '0']];
        $this->meta['building'] = $generation;
        $this->meta['building_fingerprint'] = $fingerprint;
    }
    public function add($generation, array $prepared)
    {
        $this->writable($generation);
        if ($this->failNextWrite) { $this->failNextWrite = false; throw new RuntimeException('Interrupted write'); }
        foreach ($prepared as $row) {
            if (!isset($this->generations[$generation]['rows'][$row['id']])) { ++$this->generations[$generation]['info']['inserted']; }
            $this->generations[$generation]['rows'][$row['id']] = $row;
        }
        if ($this->afterWrite) { ($this->afterWrite)(); }
    }
    public function markStale($generation, $count) { $this->writable($generation); $this->generations[$generation]['info']['stale'] += $count; }
    public function setCursor($generation, $cursor) { $this->writable($generation); $this->generations[$generation]['info']['cursor'] = $cursor; }
    public function checkpoint($revision, $ready)
    {
        $this->metadata();
        $this->meta['revision'] = $revision;
        $this->meta['ready'] = $ready;
        if ($this->afterCheckpoint) { ($this->afterCheckpoint)(); }
    }
    public function activate($generation, $fingerprint)
    {
        $this->writable($generation);
        if ($this->meta['building'] !== $generation) { throw new RuntimeException('Generation changed'); }
        $this->generations = [$generation => $this->generations[$generation]];
        $this->meta = array_merge($this->meta, ['live' => $generation, 'fingerprint' => $fingerprint, 'building' => null, 'building_fingerprint' => null, 'ready' => false]);
        if ($this->afterActivate) { ($this->afterActivate)(); }
    }
    public function statistics($generation)
    {
        return $this->metadata()['generations'][$generation] + ['filter_bytes' => 0, 'posting_bytes' => 0, 'shared_memory_bytes' => 0];
    }
    /** Attribute IDs the live generation lets through. */
    public function liveIds()
    {
        $ids = array_map('strval', array_keys($this->generations[$this->meta['live'] ?? ''] ['rows'] ?? []));
        sort($ids);
        return $ids;
    }
    private function writable($generation)
    {
        $this->metadata();
        if ($generation !== $this->meta['live'] && $generation !== $this->meta['building']) { throw new RuntimeException('Generation changed'); }
    }
}
