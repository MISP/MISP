<?php
/**
 * Real CakePHP/MysqlExtended/MariaDB/Redis integration, not a production runner.
 * Prefer FastLookupIntegration.sh: it supplies disposable socket-only services.
 * Creates and drops a unique database; uses Redis DB 13 on the supplied service.
 * The supplied Redis service MUST be disposable (tests deliberately flush it).
 */
if ($argc !== 4) {
    fwrite(STDERR, "Usage: php FastLookupIntegration.php CAKE_DIR DISPOSABLE_MYSQL_SOCKET DISPOSABLE_REDIS_SOCKET\n");
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
define('CONFIG', TMP . 'fastlookup-config-' . bin2hex(random_bytes(8)) . '/');
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
Configure::write('debug', 2);
Configure::write('MISP.unpublishedprivate', true);
Configure::write('MISP.redis_host', $argv[3]);
Configure::write('MISP.redis_database', 13);
App::build(['Model' => [APP . 'Model/'], 'Model/Behavior' => [APP . 'Model/Behavior/'],
    'Model/Datasource/Database' => [APP . 'Model/Datasource/Database/'],
    'Tools' => [APPLIBS . 'Tools/'], 'Migration' => [APPLIBS . 'Migration/']], App::PREPEND);
App::uses('MispAttribute', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('RedisTool', 'Tools');
App::uses('FastLookupCache', 'Tools');
App::uses('AttributeFastLookupTool', 'Tools');

class FastLookupIntegrationAttribute extends MispAttribute
{
    public $actsAs = ['Containable'];
    public $belongsTo = [];
    public $hasMany = [];

    protected function _mergeVars($properties, $class, $normalize = true)
    {
        // Avoid unrelated workflows/logging; keep real Model, SQL and ACLs.
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

$pdo = new PDO('mysql:unix_socket=' . $argv[2], 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$database = 'fastlookup_' . bin2hex(random_bytes(8));
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
$pdo->exec('CREATE INDEX value1 ON attributes (value1(255))');
$pdo->exec('CREATE INDEX value2 ON attributes (value2(255))');
$pdo->exec('CREATE INDEX event_id ON attributes (event_id)');
$pdo->exec('CREATE INDEX deleted ON attributes (deleted)');
ConnectionManager::create('default', ['datasource' => 'Database/MysqlExtended', 'unix_socket' => $argv[2],
    'login' => 'root', 'password' => '', 'database' => $database,
    'prefix' => '', 'encoding' => 'utf8mb4', 'persistent' => false]);
$db = ConnectionManager::getDataSource('default');
$redis = RedisTool::init();
$redis->flushDB();
$checks = 0;
$queryMeasurements = [];

function same($expected, $actual, $label)
{
    global $checks;
    if ($expected !== $actual) {
        throw new RuntimeException($label . "\nExpected " . var_export($expected, true) . "\nActual " . var_export($actual, true));
    }
    ++$checks;
}

function insertRow($table, array $row)
{
    global $pdo;
    $pdo->prepare('INSERT INTO `' . $table . '` (`' . implode('`,`', array_keys($row)) .
        '`) VALUES (' . implode(',', array_fill(0, count($row), '?')) . ')')->execute(array_values($row));
    return (string)$pdo->lastInsertId();
}

function addAttribute($value, $event = 2, array $overrides = [])
{
    return insertRow('attributes', $overrides + [
        'event_id' => $event, 'distribution' => 5, 'sharing_group_id' => 0,
        'object_id' => 0, 'deleted' => 0, 'type' => 'domain',
        'category' => 'Network activity', 'value1' => $value, 'value2' => '',
        'to_ids' => 0, 'timestamp' => 1,
    ]);
}

function lookup(array $user, array $values, $maxAge = 60, $cache = null)
{
    // One instance per simulated request, as in the HTTP application.
    $model = new FastLookupIntegrationAttribute();
    return $cache === null ? $model->fastLookup($user, ['value' => $values, 'maxAge' => $maxAge]) :
        (new AttributeFastLookupTool($model, $cache))->lookup($user, ['value' => $values, 'maxAge' => $maxAge]);
}

function jsonSame(array $expected, $actual, $label)
{
    same(true, $actual instanceof stdClass, $label . ' JSON object');
    same(json_encode((object)$expected), json_encode($actual), $label);
}

function lookupQueries()
{
    global $db;
    return array_values(array_filter($db->getLog(false, true)['log'], function ($entry) {
        return stripos($entry['query'], 'input_index') !== false;
    }));
}

function onlyKey()
{
    global $redis;
    $keys = $redis->keys('misp:fast_lookup:*');
    same(1, count($keys), 'one cache entry');
    return $keys[0];
}

foreach ([1 => [1, 0, 0, 0], 2 => [2, 3, 0, 1], 3 => [2, 0, 0, 1],
    4 => [2, 4, 7, 1], 5 => [2, 4, 8, 1], 6 => [2, 3, 0, 0],
    7 => [2, 1, 0, 1], 8 => [2, 2, 0, 1], 9 => [2, 3, 0, 1], 10 => [2, 3, 0, 1],
    9001 => [2, 3, 0, 1]] as $id => $acl) {
    insertRow('events', ['id' => $id, 'org_id' => $acl[0], 'orgc_id' => $acl[0],
        'distribution' => $acl[1], 'sharing_group_id' => $acl[2], 'published' => $acl[3],
        'info' => 'event-' . $id, 'uuid' => 'event-' . $id, 'timestamp' => 1]);
}
foreach ([1 => [0, 0], 2 => [4, 7], 3 => [4, 8], 4 => [5, 0], 5 => [3, 0]] as $id => $acl) {
    insertRow('objects', ['id' => $id, 'distribution' => $acl[0], 'sharing_group_id' => $acl[1], 'event_id' => 2]);
}
foreach (range(1, 8) as $id) {
    addAttribute('event-' . $id, $id);
}
$attributeMatrix = [
    'attribute-private' => ['distribution' => 0],
    'attribute-community' => ['distribution' => 1],
    'attribute-connected' => ['distribution' => 2],
    'attribute-all' => ['distribution' => 3],
    'attribute-sg7' => ['distribution' => 4, 'sharing_group_id' => 7],
    'attribute-sg8' => ['distribution' => 4, 'sharing_group_id' => 8],
    'object-private' => ['object_id' => 1],
    'object-sg7' => ['object_id' => 2],
    'object-sg8' => ['object_id' => 3],
    'object-inherit' => ['object_id' => 4],
    'object-public' => ['object_id' => 5],
    'deleted' => ['deleted' => 1],
];
foreach ($attributeMatrix as $value => $row) {
    addAttribute($value, 2, $row);
}
addAttribute('no-event', 9999);
addAttribute('component', 2, ['value2' => '443']);
addAttribute('shared', 2, ['value2' => 'shared']);
addAttribute('shared', 2);
addAttribute('shared', 4);
addAttribute('shared', 8);
addAttribute('numeric-sort', 10);
addAttribute('numeric-sort', 2);
addAttribute('CAFÉ ', 2);
foreach (['literal%_', '!negation', 'left&&right', "quote'\\tail", '123', '2001:db8::1'] as $value) {
    addAttribute($value, 2);
}
$user = ['org_id' => 1, 'fixture_sgids' => [7], 'Role' => ['perm_site_admin' => false, 'perm_sync' => false]];
$admin = ['org_id' => 1, 'fixture_sgids' => [], 'Role' => ['perm_site_admin' => true, 'perm_sync' => false]];
$sync = array_replace_recursive($user, ['Role' => ['perm_sync' => true]]);
$orgAdmin = array_replace_recursive($user, ['Role' => ['perm_admin' => true]]);
$publisher = array_replace_recursive($user, ['Role' => ['perm_publish' => true]]);
$readOnly = array_replace_recursive($user, ['Role' => ['perm_add' => false, 'perm_modify' => false]]);
$owner = array_replace($user, ['org_id' => 2, 'fixture_sgids' => []]);
$stranger = array_replace($user, ['org_id' => 3, 'fixture_sgids' => []]);
$values = array_merge(array_map(function ($id) { return 'event-' . $id; }, range(1, 8)),
    array_keys($attributeMatrix), ['no-event', 'component', '443', 'component|443', 'shared',
    'numeric-sort', 'cafe', 'CAFÉ ', 'literal%_', '!negation', 'left&&right', "quote'\\tail", '123',
    '2001:0DB8:0000:0000:0000:0000:0000:0001', 'missing', 'absent-😀', 'shared']);
$common = ['component' => ['2'], '443' => ['2'], 'shared' => ['2', '4', '8'],
    'numeric-sort' => ['2', '10'], 'cafe' => ['2'], 'CAFÉ ' => ['2'], 'literal%_' => ['2'], '!negation' => ['2'],
    'left&&right' => ['2'], "quote'\\tail" => ['2'], '123' => ['2'],
    '2001:0DB8:0000:0000:0000:0000:0000:0001' => ['2']];
$visibleMatrix = ['event-1' => ['1'], 'event-2' => ['2'], 'event-4' => ['4'],
    'event-7' => ['7'], 'event-8' => ['8'], 'attribute-community' => ['2'],
    'attribute-connected' => ['2'], 'attribute-all' => ['2'], 'attribute-sg7' => ['2'],
    'object-sg7' => ['2'], 'object-inherit' => ['2'], 'object-public' => ['2']];
jsonSame($visibleMatrix + $common, lookup($user, $values, 0), 'literal values, full ACL matrix, numeric key, SQL collation and IPv6');
jsonSame([], lookup($user, [], 0), 'empty input');
jsonSame([], lookup($user, ['missing'], 0), 'empty output');

foreach (['user' => $user, 'site-admin' => $admin, 'sync' => $sync, 'org-admin' => $orgAdmin,
    'publisher' => $publisher, 'read-only' => $readOnly, 'event-owner' => $owner,
    'unrelated-org' => $stranger] as $role => $actor) {
    $redis->flushDB();
    $fresh = lookup($actor, $values, 0);
    $db->getLog(false, true);
    $cold = lookup($actor, $values);
    $coldQueries = lookupQueries();
    $warm = lookup($actor, $values);
    $warmQueries = lookupQueries();
    same(json_encode($fresh), json_encode($cold), "$role cold/fresh parity");
    same(json_encode($fresh), json_encode($warm), "$role warm/fresh parity");
    same(2, count($coldQueries), "$role cold discovery + live ACL query");
    same(1, count($warmQueries), "$role warm live ACL query only");
    foreach ($warmQueries as $entry) {
        same(true, stripos($entry['query'], 'event_id') !== false, "$role warm query returns event IDs");
        same(true, preg_match('/(?:`?Attribute`?\.)?`?id`?\s+IN\s*\(/i', $entry['query']) === 1,
            "$role warm query constrained by candidate attribute IDs");
    }
    $queryMeasurements[$role] = ['cold' => count($coldQueries), 'warm' => count($warmQueries)];
}
jsonSame(['event-3' => ['3'], 'event-6' => ['6']], lookup($admin, ['event-3', 'event-6']), 'admin bypasses visibility but not deletion');
jsonSame([], lookup($admin, ['deleted', 'no-event']), 'admin excludes deleted rows and missing events');
jsonSame([], lookup($sync, ['event-3', 'event-6']), 'sync role does not bypass attribute ACL');
jsonSame(['event-3' => ['3'], 'event-6' => ['6']], lookup($owner, ['event-3', 'event-6']), 'owner sees own private and unpublished');
jsonSame([], lookup($stranger, ['event-1', 'event-4']), 'unrelated org cannot reuse privileged cache results');
Configure::write('MISP.unpublishedprivate', false);
jsonSame(['event-6' => ['6']], lookup($user, ['event-6']), 'unpublishedprivate disabled follows standard visibility');
Configure::write('MISP.unpublishedprivate', true);

// Prime, mutate in SQL, then reuse the same candidate cache across requests.
$mutations = [
    'deleted-now' => ['UPDATE attributes SET deleted=1 WHERE id=?', []],
    'value1-changed' => ["UPDATE attributes SET value1='replaced' WHERE id=?", []],
    'attribute-private-now' => ['UPDATE attributes SET distribution=0 WHERE id=?', []],
    'attribute-sg-removed' => ['UPDATE attributes SET distribution=4,sharing_group_id=8 WHERE id=?', []],
    'object-private-now' => ['UPDATE objects SET distribution=0 WHERE id=5', ['object_id' => 5]],
];
foreach ($mutations as $value => $case) {
    $id = addAttribute($value, 2, $case[1]);
    jsonSame([$value => ['2']], lookup($user, [$value]), "$value initially visible");
    $pdo->prepare($case[0])->execute(strpos($case[0], '?') === false ? [] : [$id]);
    jsonSame([], lookup($user, [$value]), "$value immediately removed on warm lookup");
}
$secondId = addAttribute('unrelated-first', 2, ['value2' => 'value2-changed']);
lookup($user, ['value2-changed']);
$pdo->exec("UPDATE attributes SET value2='replaced' WHERE id=" . $secondId);
jsonSame([], lookup($user, ['value2-changed']), 'value2 changes immediately removed');
lookup($user, ['event-4']);
$noMembership = array_replace($user, ['fixture_sgids' => []]);
jsonSame([], lookup($noMembership, ['event-4']), 'sharing-group membership revoked between requests');
addAttribute('event-revoked', 9);
lookup($user, ['event-revoked']);
$pdo->exec('UPDATE events SET distribution=0 WHERE id=9');
jsonSame([], lookup($user, ['event-revoked']), 'event distribution revoked immediately');
$pdo->exec('UPDATE events SET distribution=3,published=0 WHERE id=9');
jsonSame([], lookup($user, ['event-revoked']), 'event unpublished immediately');
$pdo->exec('UPDATE events SET published=1 WHERE id=9');
jsonSame(['event-revoked' => ['9']], lookup($user, ['event-revoked']), 'existing cached candidate visible after event republish');
$pdo->exec('DELETE FROM events WHERE id=9');
jsonSame([], lookup($admin, ['event-revoked']), 'event deleted immediately even for admin');

// Both positive and negative candidate membership may lag; bypass is fresh.
foreach ([false, true] as $positive) {
    $redis->flushDB();
    $value = $positive ? 'positive-new-match' : 'negative-new-match';
    if ($positive) {
        addAttribute($value, 2);
    }
    $before = $positive ? [$value => ['2']] : [];
    jsonSame($before, lookup($user, [$value]), "$value prime");
    $key = onlyKey();
    $ttl = $redis->pttl($key);
    same(true, $ttl > 0 && $ttl <= 60000, "$value TTL bounded to 60 seconds");
    $payload = $redis->get($key);
    usleep(120000);
    jsonSame($before, lookup($user, [$value]), "$value cache hit");
    same(true, $redis->pttl($key) < $ttl, "$value hit does not refresh TTL");
    same($payload, $redis->get($key), "$value hit does not refresh discovery time");
    addAttribute($value, 8);
    jsonSame($before, lookup($user, [$value]), "$value new match can be stale");
    $after = [$value => $positive ? ['2', '8'] : ['8']];
    jsonSame($after, lookup($user, [$value], 0), "$value bypass sees new match");
    same($payload, $redis->get($key), "$value bypass leaves cache untouched");
    $redis->pExpire($key, 50);
    usleep(80000);
    jsonSame($after, lookup($user, [$value]), "$value real Redis expiry refreshes candidates");
}
$redis->flushDB();
lookup($user, ['max-age-new']);
addAttribute('max-age-new', 2);
usleep(1100000);
jsonSame(['max-age-new' => ['2']], lookup($user, ['max-age-new'], 1), 'maxAge narrows permitted candidate staleness');

// Actual corrupted Redis payload and a disconnected phpredis connection.
$redis->flushDB();
lookup($user, ['shared']);
$redis->setex(onlyKey(), 60, '{broken-json');
jsonSame(['shared' => ['2', '4', '8']], lookup($user, ['shared']), 'corrupt Redis payload falls back to SQL');
$failedRedis = new Redis();
$failedRedis->connect($argv[3]);
$failedRedis->close();
$failedCache = new FastLookupCache('integration-failed-redis', $failedRedis);
jsonSame(['shared' => ['2', '4', '8']], lookup($user, ['shared'], 60, $failedCache), 'disconnected real Redis falls back to SQL');

// A migrated utf8mb4 component can store supplementary characters even when
// its companion column still uses utf8mb3. Ignore only impossible branches.
$redis->flushDB();
$emoji = 'stored-😀';
jsonSame([], lookup($user, [$emoji]), 'utf8mb3 cannot contain four-byte IOC');
$pdo->exec('ALTER TABLE attributes MODIFY value2 TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL');
$db->cacheSources = false; // Read the changed schema, not Cake's old description.
$emojiId = addAttribute('emoji-carrier', 2, ['value2' => $emoji]);
foreach ([0, 60, 60] as $maxAge) {
    jsonSame([$emoji => ['2']], lookup($user, [$emoji], $maxAge), 'mixed-charset schema retains utf8mb4 component match');
}
$pdo->exec('DELETE FROM attributes WHERE id=' . $emojiId);
$pdo->exec('ALTER TABLE attributes MODIFY value2 TEXT CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NULL');
$db->cacheSources = true;

// Multiple SQL batches and positive/negative cache hits retain all requested keys.
$batchValues = [];
$batchExpected = [];
for ($i = 0; $i < 205; ++$i) {
    $value = 'batch-' . $i;
    $batchValues[] = $value;
    if ($i % 2 === 0) {
        addAttribute($value, 2);
        $batchExpected[$value] = ['2'];
    }
}
jsonSame($batchExpected, lookup($user, $batchValues), '205 values cross discovery and live SQL batches');
jsonSame($batchExpected, lookup($user, $batchValues), '205 values warm parity');

function insertRepeated($value, $count, $distinctEvents = false)
{
    global $pdo;
    for ($done = 0; $done < $count; $done += 1000) {
        $size = min(1000, $count - $done);
        $rows = [];
        $events = [];
        for ($i = 0; $i < $size; ++$i) {
            $event = $distinctEvents ? 10000 + $done + $i : 2;
            $rows[] = '(' . $event . ',5,0,0,0,' . $pdo->quote($value) . ",'')";
            if ($distinctEvents) {
                $events[] = '(' . $event . ',2,2,3,0,1)';
            }
        }
        if ($events) {
            $pdo->exec('INSERT INTO events (id,org_id,orgc_id,distribution,sharing_group_id,published) VALUES ' . implode(',', $events));
        }
        $pdo->exec('INSERT INTO attributes (event_id,distribution,sharing_group_id,object_id,deleted,value1,value2) VALUES ' . implode(',', $rows));
    }
}

// Exceed cache capacity without dropping the event from the final candidate.
$redis->flushDB();
insertRepeated('over-cache-cap', 10000);
addAttribute('over-cache-cap', 9001);
jsonSame(['over-cache-cap' => ['2', '9001']], lookup($user, ['over-cache-cap']), 'all matches returned beyond 10000-candidate cache cap');
same([], $redis->keys('misp:fast_lookup:*'), 'oversized candidate set not cached');
jsonSame(['over-cache-cap' => ['2', '9001']], lookup($user, ['over-cache-cap']), 'oversized repeated request remains complete');

// Resource limits fail explicitly and never publish partial cache entries.
insertRepeated('over-row-cap', 100001, true);
foreach ([0, 60] as $maxAge) {
    $redis->flushDB();
    try {
        lookup($user, ['over-row-cap'], $maxAge);
        throw new RuntimeException('Expected resource-cap OverflowException');
    } catch (OverflowException $e) {
        ++$checks;
    }
    same([], $redis->keys('misp:fast_lookup:*'), 'overflow never writes a truncated cache');
}
$redis->flushDB();
try {
    lookup($user, array_merge(array_slice($batchValues, 0, 100), ['over-row-cap']));
    throw new RuntimeException('Expected cross-batch resource-cap OverflowException');
} catch (OverflowException $e) {
    ++$checks;
}
same([], $redis->keys('misp:fast_lookup:*'), 'later-batch overflow never publishes earlier partial cache entries');

// Representative timings include model creation and real SQL/Redis, exclude
// HTTP/auth/startup. Indexed background rows remain present in all scenarios.
function benchmark($label, array $actor, callable $valuesForIteration, $maxAge, $iterations = 40)
{
    global $db;
    $times = [];
    $queries = 0;
    for ($i = 0; $i < $iterations; ++$i) {
        $db->getLog(false, true);
        $started = hrtime(true);
        lookup($actor, $valuesForIteration($i), $maxAge);
        $times[] = (hrtime(true) - $started) / 1e6;
        $queries += count(lookupQueries());
    }
    sort($times);
    return ['scenario' => $label, 'iterations' => $iterations,
        'median_ms' => round($times[(int)floor(count($times) / 2)], 3),
        'p95_ms' => round($times[(int)ceil(count($times) * .95) - 1], 3),
        'lookup_sql_per_request' => $queries / $iterations];
}
$redis->flushDB();
$repeatValues = array_slice($batchValues, 0, 100);
lookup($user, $repeatValues);
$benchmarks = [];
$benchmarks[] = benchmark('repeat-100-warm', $user, function () use ($repeatValues) { return $repeatValues; }, 60);
$benchmarks[] = benchmark('repeat-100-fresh', $user, function () use ($repeatValues) { return $repeatValues; }, 0);
$newMisses = function ($i) {
    return array_map(function ($j) use ($i) { return 'new-miss-' . $i . '-' . $j; }, range(0, 99));
};
$redis->flushDB();
$benchmarks[] = benchmark('new-misses-100-cache-enabled', $user, $newMisses, 60);
$benchmarks[] = benchmark('new-misses-100-fresh', $user, $newMisses, 0);
$repeatMisses = $newMisses(0);
lookup($user, $repeatMisses);
$benchmarks[] = benchmark('repeat-misses-100-warm', $user, function () use ($repeatMisses) { return $repeatMisses; }, 60);
$report = ['checks' => $checks, 'versions' => ['php' => PHP_VERSION,
    'mariadb' => $pdo->query('SELECT VERSION()')->fetchColumn(), 'redis' => $redis->info('server')['redis_version']],
    'fixture_attribute_rows' => (int)$pdo->query('SELECT COUNT(*) FROM attributes')->fetchColumn(),
    'collation' => 'utf8mb3_unicode_ci (value1/value2, matching INSTALL/MYSQL.sql)', 'query_counts' => $queryMeasurements, 'benchmarks' => $benchmarks,
    'limitations' => ['Direct model invocation, not HTTP authentication/rate limiting.',
        'Sharing-group membership is supplied by fixture; standard buildConditions and database joins execute.',
        'Synthetic indexed local data, no concurrent load or production throughput claims.',
        'Expiry is exercised by shortening a real Redis TTL; the initial TTL is asserted <=60s.']];
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
