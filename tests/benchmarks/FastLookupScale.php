<?php
/**
 * Scale benchmark for the persistent fast lookup index. Disposable services only.
 *
 * Loads N synthetic attributes per type into homogeneous events (one type per
 * event range), backfills the index one type per batch, and reports per type:
 * build time, Redis memory growth, memory by key class and encoding, and lookup
 * throughput for 10,000-value requests (hits, misses and expansion matches).
 *
 * Usage: php FastLookupScale.php CAKE_DIR MYSQL_SOCKET REDIS_SOCKET
 * Environment: FL_PER_TYPE (default 1000), FL_PER_EVENT (100), FL_TYPES
 * (comma list, default FastLookupConfig::DEFAULT_TYPES), FL_DUPLICATES (0.1),
 * FL_LOOKUP (10000), FL_OUT (JSON report path).
 */
if ($argc !== 4) {
    fwrite(STDERR, "Usage: php FastLookupScale.php CAKE_DIR DISPOSABLE_MYSQL_SOCKET DISPOSABLE_REDIS_SOCKET\n");
    exit(2);
}
define('DS', DIRECTORY_SEPARATOR);
define('CAKE', rtrim($argv[1], '/') . '/');
define('ROOT', dirname(__DIR__, 2));
define('APP', ROOT . '/app/');
define('APP_DIR', 'app');
define('APPLIBS', APP . 'Lib/');
define('CORE_PATH', dirname(rtrim(CAKE, '/')) . '/');
define('CAKE_CORE_INCLUDE_PATH', dirname(rtrim(CAKE, '/')));
define('TMP', sys_get_temp_dir() . '/');
define('CACHE', TMP);
define('CONFIG', TMP . 'fastlookup-scale-' . bin2hex(random_bytes(8)) . '/');
error_reporting(E_ALL & ~E_DEPRECATED);
mkdir(CONFIG);
file_put_contents(CONFIG . 'database.php', '<?php class DATABASE_CONFIG {}');
register_shutdown_function(function () {
    unlink(CONFIG . 'database.php');
    rmdir(CONFIG);
});
require CAKE . 'basics.php';
require CAKE . 'Core/App.php';
require CAKE . 'Error/exceptions.php';
spl_autoload_register(['App', 'load']);
App::uses('Configure', 'Core');
App::uses('Cache', 'Cache');
App::uses('CakeObject', 'Core');
Configure::write('Cache.disable', true);
Configure::write('debug', 0);
Configure::write('MISP.redis_host', $argv[3]);
Configure::write('MISP.redis_database', 12);
App::build(['Model' => [APP . 'Model/'], 'Model/Behavior' => [APP . 'Model/Behavior/'],
    'Model/Datasource/Database' => [APP . 'Model/Datasource/Database/'],
    'Tools' => [APPLIBS . 'Tools/'], 'Migration' => [APPLIBS . 'Migration/']], App::PREPEND);
App::uses('MispAttribute', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('RedisTool', 'Tools');
App::uses('FastLookupConfig', 'Tools');
App::uses('FastLookupIndexManager', 'Tools');
App::uses('FastLookupIndex', 'Tools');
App::uses('FastLookupValueTool', 'Tools');
App::uses('AttributeFastLookupTool', 'Tools');

class FastLookupScaleAttribute extends MispAttribute
{
    public $actsAs = ['Containable'];
    public $belongsTo = [];
    public $hasMany = [];

    protected function _mergeVars($properties, $class, $normalize = true)
    {
        parent::_mergeVars(array_values(array_diff($properties, ['actsAs'])), $class, $normalize);
    }

    public function __construct()
    {
        AppModel::__construct(false, 'attributes', 'default');
        $this->SharingGroup = new class {
            public function authorizedIds($user) { return $user['fixture_sgids']; }
        };
        $this->Event = new Model(['name' => 'Event', 'table' => 'events']);
        $this->Object = new Model(['name' => 'Object', 'table' => 'objects']);
        $this->bindModel(['belongsTo' => [
            'Event' => ['className' => 'Model', 'foreignKey' => 'event_id'],
            'Object' => ['className' => 'Model', 'foreignKey' => 'object_id'],
        ]], false);
    }
}

$perType = (int)(getenv('FL_PER_TYPE') ?: 1000);
$perEvent = (int)(getenv('FL_PER_EVENT') ?: 100);
$types = getenv('FL_TYPES') ? explode(',', getenv('FL_TYPES')) : FastLookupConfig::DEFAULT_TYPES;
$duplicates = (float)(getenv('FL_DUPLICATES') === false ? 0.1 : getenv('FL_DUPLICATES'));
$lookupSize = (int)(getenv('FL_LOOKUP') ?: 10000);
$eventsPerType = intdiv($perType + $perEvent - 1, $perEvent);
if ($eventsPerType > 1000) {
    fwrite(STDERR, "FL_PER_TYPE / FL_PER_EVENT must be at most 1000 events per type.\n");
    exit(2);
}
Configure::write('MISP.fast_lookup_attribute_types', implode(',', $types));
Configure::write('MISP.fast_lookup_published_only', true);
Configure::write('MISP.fast_lookup_max_values', max($lookupSize, 10000));

$pdo = new PDO('mysql:unix_socket=' . $argv[2], 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$database = 'fastlookup_scale_' . bin2hex(random_bytes(6));
$pdo->exec('CREATE DATABASE `' . $database . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
register_shutdown_function(function () use ($pdo, $database) {
    $pdo->exec('DROP DATABASE `' . $database . '`');
});
$pdo->exec('USE `' . $database . '`');
$pdo->exec('SET NAMES utf8mb4');
$schema = json_decode(file_get_contents(ROOT . '/db_schema.json'), true)['schema'];
foreach (['attributes', 'events', 'objects'] as $table) {
    $columns = [];
    foreach ($schema[$table] as $column) {
        $columns[] = '`' . $column['column_name'] . '` ' . $column['column_type'] .
            ($table === 'attributes' && in_array($column['column_name'], ['value1', 'value2'], true)
                ? ' CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci' : '') .
            ($column['column_name'] === 'id' ? ' NOT NULL AUTO_INCREMENT PRIMARY KEY' : ' NULL');
    }
    $pdo->exec('CREATE TABLE `' . $table . '` (' . implode(',', $columns) . ') ENGINE=InnoDB');
}
$pdo->exec('CREATE TABLE admin_settings (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, setting VARCHAR(255) NOT NULL UNIQUE, value TEXT NOT NULL) ENGINE=InnoDB');
ConnectionManager::create('default', ['datasource' => 'Database/MysqlExtended', 'unix_socket' => $argv[2],
    'login' => 'root', 'password' => '', 'database' => $database,
    'prefix' => '', 'encoding' => 'utf8mb4', 'persistent' => false]);
$redis = RedisTool::init();
$model = new FastLookupScaleAttribute();
$namespace = 'misp:fast_lookup:v3:' . hash('sha256', FastLookupConfig::namespaceFor($model)) . ':';
register_shutdown_function(function () use ($redis, $namespace) {
    $cursor = null;
    do {
        $keys = $redis->scan($cursor, $namespace . '*', 1000);
        if ($keys) { $redis->del($keys); }
    } while ($cursor !== 0);
});

/** Deterministic synthetic values: [value1, value2] plus lookup forms. */
function syntheticValue(string $type, int $typeIndex, int $i): array
{
    $h = hash('sha512', $type . ':' . $i);
    $ipv4 = function (int $n) use ($typeIndex) { return (10 + $typeIndex) . '.' . (($n >> 16) & 255) . '.' . (($n >> 8) & 255) . '.' . ($n & 255); };
    $ip = function (int $n) use ($ipv4, $typeIndex) {
        if ($n % 50 === 7) { return sprintf('2001:db8:%x::%x', $typeIndex, $n); } // 2% IPv6
        if ($n % 50 === 13) { return (10 + $typeIndex) . '.' . (($n >> 8) & 255) . '.' . ($n & 255) . '.0/24'; } // 2% CIDR
        return $ipv4($n);
    };
    $ports = [443, 443, 443, 80, 80, 8080, 53, 22, 8443, 4444];
    $port = ($i % 10 === 9) ? (1024 + $i % 60000) : $ports[$i % 10];
    $domain = 'd' . $i . '-' . substr($h, 0, 6) . '.example' . ($i % 7) . '.test';
    $host = 'h' . substr($h, 6, 6) . '.d' . intdiv($i, 4) . '.example' . ($i % 7) . '.test';
    $filename = 'file' . ($i % 5000) . '.exe';
    switch ($type) {
        case 'md5': return [substr($h, 0, 32), ''];
        case 'sha1': return [substr($h, 0, 40), ''];
        case 'sha256': return [substr($h, 0, 64), ''];
        case 'sha512': return [$h, ''];
        case 'filename|md5': case 'malware-sample': return [$filename, substr($h, 0, 32)];
        case 'filename|sha1': return [$filename, substr($h, 0, 40)];
        case 'filename|sha256': return [$filename, substr($h, 0, 64)];
        case 'filename|sha512': return [$filename, $h];
        case 'ip-src': case 'ip-dst': return [$ip($i), ''];
        case 'ip-src|port': case 'ip-dst|port': return [$ip($i), (string)$port];
        case 'domain': return [$domain, ''];
        case 'hostname': return [$host, ''];
        case 'domain|ip': return [$domain, $ip($i)];
        case 'hostname|port': return [$host, (string)$port];
    }
    // Other exact types (url, email, ...): a unique 40-80 byte string.
    return [$type . '-' . substr($h, 0, 20 + $i % 40) . '@example.test', ''];
}

/** Values a log would contain for this attribute: [hit, expansion-hit or null]. */
function lookupForms(string $type, array $value): array
{
    [$v1, $v2] = $value;
    $ipSide = in_array($type, ['domain|ip'], true) ? $v2 : $v1;
    if (in_array($type, ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'domain|ip'], true) && strpos($ipSide, '/') !== false) {
        return [null, substr($ipSide, 0, strrpos($ipSide, '.')) . '.77'];
    }
    switch ($type) {
        case 'filename|md5': case 'filename|sha1': case 'filename|sha256': case 'filename|sha512': case 'malware-sample':
            return [$v2, null];
        case 'domain': return [$v1, 'www.' . $v1];
        case 'domain|ip': return [$v1, 'mail.' . $v1];
    }
    return [$v1, null];
}

function redisUsed($redis): int { return (int)$redis->info('memory')['used_memory']; }

$typeIndex = array_flip(array_values($types));
$eventId = 0; $attributeId = 0;
$loaded = []; $loadStart = microtime(true);
$pdo->exec('SET unique_checks = 0');
foreach ($types as $type) {
    $k = $typeIndex[$type];
    $events = [];
    for ($e = 0; $e < $eventsPerType; ++$e) {
        $events[] = sprintf('(%d, 1, 1, 3, 0, 1, %s, %s, 1)', ++$eventId, $pdo->quote('scale ' . $type), $pdo->quote(sprintf('%08x-0000-4000-8000-%012x', $eventId, $eventId)));
    }
    $pdo->exec('INSERT INTO events (id, org_id, orgc_id, distribution, sharing_group_id, published, info, uuid, timestamp) VALUES ' . implode(',', $events));
    $firstEvent = $eventId - $eventsPerType + 1;
    $rows = [];
    $samples = [];
    for ($i = 0; $i < $perType; ++$i) {
        // A share of values repeats an earlier value in another event.
        $source = ($i > $perEvent && ($i * 7919) % 1000 < $duplicates * 1000) ? ($i * 31) % $i : $i;
        $value = syntheticValue($type, $k, $source);
        $event = $firstEvent + intdiv($i, $perEvent);
        $rows[] = sprintf("(%d, %d, 0, %s, 'Network activity', %s, %s, 1, 1, 5, 0, 0)",
            ++$attributeId, $event, $pdo->quote($type), $pdo->quote($value[0]), $pdo->quote($value[1]));
        // Sample evenly, plus every CIDR (i % 50 === 13) so expansion lookups exist.
        if ($i % max(1, intdiv($perType, $lookupSize)) === 0 || $source % 50 === 13) { $samples[] = $value; }
        if (count($rows) === 5000) {
            $pdo->exec('INSERT INTO attributes (id, event_id, object_id, type, category, value1, value2, to_ids, timestamp, distribution, sharing_group_id, deleted) VALUES ' . implode(',', $rows));
            $rows = [];
        }
    }
    if ($rows) {
        $pdo->exec('INSERT INTO attributes (id, event_id, object_id, type, category, value1, value2, to_ids, timestamp, distribution, sharing_group_id, deleted) VALUES ' . implode(',', $rows));
    }
    $loaded[$type] = ['first_event' => $firstEvent, 'samples' => $samples];
}
$pdo->exec('CREATE INDEX value1 ON attributes (value1(255))');
$pdo->exec('CREATE INDEX value2 ON attributes (value2(255))');
$pdo->exec('CREATE INDEX event_id ON attributes (event_id)');
$pdo->exec('CREATE INDEX deleted ON attributes (deleted)');
$loadSeconds = microtime(true) - $loadStart;
fwrite(STDERR, sprintf("loaded %d attributes in %.1f s\n", $attributeId, $loadSeconds));

// Backfill: the first batch initialises; each following batch is one type.
$manager = new FastLookupIndexManager($model);
$baseline = redisUsed($redis);
$start = microtime(true);
$status = $manager->startRebuild();
$afterInit = redisUsed($redis);
$report = ['parameters' => compact('perType', 'perEvent', 'duplicates', 'lookupSize', 'eventsPerType') + ['types' => $types],
    'load_seconds' => round($loadSeconds, 1), 'redis_baseline_bytes' => $baseline,
    'init' => ['seconds' => round(microtime(true) - $start, 2), 'bytes' => $afterInit - $baseline], 'types' => []];
$previous = $afterInit;
foreach ($types as $type) {
    $t = microtime(true);
    $status = $manager->runBatch($eventsPerType);
    if (in_array($status['status'], ['error', 'unavailable'], true)) {
        throw new RuntimeException('Backfill failed on ' . $type . ': ' . json_encode($status));
    }
    $used = redisUsed($redis);
    $seconds = microtime(true) - $t;
    $report['types'][$type] = [
        'build_seconds' => round($seconds, 2),
        'build_attributes_per_second' => (int)round($perType / $seconds),
        'redis_bytes' => $used - $previous,
        'redis_bytes_per_attribute' => round(($used - $previous) / $perType, 1),
    ];
    $previous = $used;
    fwrite(STDERR, sprintf("%-16s %6.1f s  %7.1f B/attribute\n", $type, $seconds, ($used - $baseline) / max(1, $perType * count($report['types']))));
}
for ($i = 0; $i < 5 && $status['status'] !== 'ready'; ++$i) { $status = $manager->runBatch(1000); }
if ($status['status'] !== 'ready') { throw new RuntimeException('Backfill did not finish: ' . json_encode($status)); }
$report['build_seconds_total'] = round(microtime(true) - $start, 1);
$report['redis_bytes_total'] = redisUsed($redis) - $baseline;
$report['redis_bytes_per_attribute'] = round($report['redis_bytes_total'] / ($perType * count($types)), 1);

// Memory and encoding by key class, from the live Redis keys.
$classes = [];
$typeHash = [];
foreach ($types as $type) { $typeHash[hash('sha256', $type)] = $type; }
$cursor = null;
do {
    $keys = $redis->scan($cursor, $namespace . '*', 1000) ?: [];
    foreach ($keys as $key) {
        $rest = substr($key, strlen($namespace));
        if (preg_match('/^g:[^:]+:t:([0-9a-f]{64}):(b:\d+|owners|events|r:\d+)$/', $rest, $m)) {
            $class = $m[2][0] === 'b' ? 'postings' : ($m[2][0] === 'r' ? 'reverse_manifests' : $m[2]);
            $type = $typeHash[$m[1]] ?? '?';
        } else {
            $class = 'global'; $type = '*';
        }
        $bytes = (int)$redis->rawCommand('MEMORY', 'USAGE', $key, 'SAMPLES', '0');
        $encoding = $redis->object('encoding', $key);
        $fields = (int)$redis->hLen($key);
        foreach ([$class, $class . '@' . $type] as $bucket) {
            $classes[$bucket]['keys'] = ($classes[$bucket]['keys'] ?? 0) + 1;
            $classes[$bucket]['bytes'] = ($classes[$bucket]['bytes'] ?? 0) + $bytes;
            $classes[$bucket]['fields'] = ($classes[$bucket]['fields'] ?? 0) + $fields;
            $classes[$bucket]['encodings'][$encoding] = ($classes[$bucket]['encodings'][$encoding] ?? 0) + 1;
        }
    }
} while ($cursor !== 0);
ksort($classes);
$report['key_classes'] = $classes;
$t = microtime(true);
$report['statistics'] = $manager->status(true)['statistics'] ?? null;
$report['statistics_seconds'] = round(microtime(true) - $t, 2);

// Lookups: 10,000-value requests per type through the full model path, and the
// Redis candidate phase alone for the same values.
$user = ['org_id' => 1, 'fixture_sgids' => [], 'Role' => ['perm_site_admin' => false, 'perm_sync' => false]];
$valueTool = new FastLookupValueTool($model);
$index = $manager->index();
$generation = $manager->status()['generation'];
$lookup = function (array $values) use ($user) {
    $t = microtime(true);
    $response = (new FastLookupScaleAttribute())->fastLookup($user, ['value' => $values]);
    if (($response['status'] ?? null) !== 'ready') { throw new RuntimeException('Lookup not ready: ' . json_encode($response)); }
    return [microtime(true) - $t, count((array)$response['results'])];
};
$candidatePhase = function (array $values) use ($valueTool, $index, $generation, $types) {
    $tokenSeconds = 0; $candidateSeconds = 0;
    foreach (array_chunk($values, AttributeFastLookupTool::BATCH_SIZE, true) as $batch) {
        $t = microtime(true);
        $tokens = $valueTool->queryTokens($batch, $types);
        $tokenSeconds += microtime(true) - $t;
        $t = microtime(true);
        $index->candidates($generation, $tokens);
        $candidateSeconds += microtime(true) - $t;
    }
    return [$tokenSeconds, $candidateSeconds];
};
foreach ($types as $type) {
    $hits = []; $expansions = [];
    foreach ($loaded[$type]['samples'] as $value) {
        [$hit, $expansion] = lookupForms($type, $value);
        if ($hit !== null) { $hits[] = $hit; }
        if ($expansion !== null) { $expansions[] = $expansion; }
    }
    $hits = array_slice(array_values(array_unique($hits)), 0, $lookupSize);
    $misses = [];
    for ($i = 0; count($misses) < $lookupSize; ++$i) {
        $miss = lookupForms($type, syntheticValue($type, 90, 900000000 + $i))[0] ?? null;
        if ($miss !== null) { $misses[] = $miss; }
    }
    $results = [];
    foreach (['hits' => $hits, 'misses' => $misses, 'expansions' => array_slice(array_values(array_unique($expansions)), 0, $lookupSize)] as $label => $values) {
        if (!$values) { continue; }
        [$seconds, $matched] = $lookup($values);
        [$tokenSeconds, $candidateSeconds] = $candidatePhase($values);
        $results[$label] = [
            'values' => count($values), 'matched' => $matched,
            'seconds' => round($seconds, 3), 'values_per_second' => (int)round(count($values) / $seconds),
            'redis_candidate_seconds' => round($tokenSeconds + $candidateSeconds, 3),
            'tokenize_seconds' => round($tokenSeconds, 3),
            'candidates_seconds' => round($candidateSeconds, 3),
        ];
    }
    $report['types'][$type]['lookups'] = $results;
    fwrite(STDERR, sprintf("lookup %-16s hits %.2f s misses %.2f s\n", $type, $results['hits']['seconds'] ?? -1, $results['misses']['seconds']));
}
$report['versions'] = ['php' => PHP_VERSION, 'mariadb' => $pdo->query('SELECT VERSION()')->fetchColumn(),
    'redis' => $redis->info('server')['redis_version'],
    'hash_max_listpack' => $redis->config('GET', 'hash-max-listpack-*')];
$json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (getenv('FL_OUT')) { file_put_contents(getenv('FL_OUT'), $json); }
echo $json, "\n";
