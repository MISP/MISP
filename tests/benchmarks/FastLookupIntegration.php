<?php
/**
 * Real CakePHP/MysqlExtended/MariaDB/Redis integration, not a production runner.
 * Prefer FastLookupIntegration.sh: it supplies disposable socket-only services.
 * Creates and drops a unique database; uses a unique namespace in Redis DB 12.
 * The supplied services must be disposable; no global Redis flush is used.
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


$pdo->exec('CREATE TABLE admin_settings (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, setting VARCHAR(255) NOT NULL UNIQUE, value TEXT NOT NULL) ENGINE=InnoDB');
$checks = 0;
$queryMeasurements = [];
$benchmarks = [];
$model = new FastLookupIntegrationAttribute();
$namespace = 'misp:fast_lookup:v2:' . hash('sha256', FastLookupConfig::namespaceFor($model)) . ':';
register_shutdown_function(function () use ($redis, $namespace) {
    // Only this test's namespace, including generations left by failed assertions.
    $cursor = null;
    do {
        $keys = $redis->scan($cursor, $namespace . '*', 1000);
        if ($keys) { $redis->del($keys); }
    } while ($cursor !== 0);
});

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
    $pdo->prepare('INSERT INTO `' . $table . '` (`' . implode('`,`', array_keys($row)) . '`) VALUES (' . implode(',', array_fill(0, count($row), '?')) . ')')->execute(array_values($row));
    return (string)$pdo->lastInsertId();
}

function addAttribute($value, $event = 2, array $overrides = [])
{
    return insertRow('attributes', $overrides + [
        'event_id' => $event, 'distribution' => 5, 'sharing_group_id' => 0,
        'object_id' => 0, 'deleted' => 0, 'type' => 'domain', 'category' => 'Network activity',
        'value1' => $value, 'value2' => '', 'to_ids' => 0, 'timestamp' => 1,
    ]);
}

function lookup(array $user, array $values)
{
    return (new FastLookupIntegrationAttribute())->fastLookup($user, ['value' => $values]);
}

function eventIds(array $response)
{
    same('ready', $response['status'], 'lookup ready');
    same(true, isset($response['scope']['attribute_types']), 'lookup scope');
    same(true, $response['results'] instanceof stdClass, 'results JSON object');
    $result = new stdClass();
    foreach ($response['results'] as $value => $entry) { $result->{$value} = $entry['event_ids']; }
    return $result;
}

function jsonSame(array $expected, array $actual, $label)
{
    same(json_encode((object)$expected), json_encode(eventIds($actual)), $label);
}

function manager()
{
    return new FastLookupIndexManager(new FastLookupIntegrationAttribute());
}

function rebuild()
{
    $manager = manager();
    $status = $manager->startRebuild();
    for ($i = 0; $i < 100 && $status['status'] !== 'ready'; ++$i) {
        if (in_array($status['status'], ['error', 'unavailable'], true)) {
            throw new RuntimeException('Rebuild failed: ' . json_encode($status));
        }
        $status = $manager->runBatch(3);
    }
    same('ready', $status['status'], 'complete backfill');
    return $status;
}

function changed($eventId)
{
    FastLookupIndexManager::recordChange(new FastLookupIntegrationAttribute(), (string)$eventId);
}

function drain()
{
    $manager = manager();
    for ($i = 0; $i < 100; ++$i) {
        $status = $manager->processPending(25);
        if ($status['status'] === 'ready') { return $status; }
        if (in_array($status['status'], ['error', 'unavailable'], true)) {
            throw new RuntimeException('Pending refresh failed: ' . json_encode($status));
        }
    }
    throw new RuntimeException('Pending refresh did not finish.');
}

function lookupQueries()
{
    global $db;
    return array_values(array_filter($db->getLog(false, true)['log'], function ($entry) {
        return stripos($entry['query'], 'input_index') !== false;
    }));
}

foreach ([1 => [1, 0, 0, 0], 2 => [2, 3, 0, 1], 3 => [2, 0, 0, 1],
    4 => [2, 4, 7, 1], 5 => [2, 4, 8, 1], 6 => [2, 3, 0, 0],
    7 => [2, 1, 0, 1], 8 => [2, 2, 0, 1], 9 => [2, 3, 0, 1], 10 => [2, 3, 0, 1]] as $id => $acl) {
    insertRow('events', ['id' => $id, 'org_id' => $acl[0], 'orgc_id' => $acl[0],
        'distribution' => $acl[1], 'sharing_group_id' => $acl[2], 'published' => $acl[3],
        'info' => 'event-' . $id, 'uuid' => 'event-' . $id, 'timestamp' => 1]);
}
foreach ([1 => [0, 0], 2 => [4, 7], 3 => [4, 8], 4 => [5, 0], 5 => [3, 0]] as $id => $acl) {
    insertRow('objects', ['id' => $id, 'distribution' => $acl[0], 'sharing_group_id' => $acl[1], 'event_id' => 2]);
}
foreach (range(1, 8) as $id) { addAttribute('event-' . $id, $id); }
$attributeMatrix = [
    'attribute-private' => ['distribution' => 0], 'attribute-community' => ['distribution' => 1],
    'attribute-connected' => ['distribution' => 2], 'attribute-all' => ['distribution' => 3],
    'attribute-sg7' => ['distribution' => 4, 'sharing_group_id' => 7],
    'attribute-sg8' => ['distribution' => 4, 'sharing_group_id' => 8],
    'object-private' => ['object_id' => 1], 'object-sg7' => ['object_id' => 2],
    'object-sg8' => ['object_id' => 3], 'object-inherit' => ['object_id' => 4],
    'object-public' => ['object_id' => 5], 'deleted' => ['deleted' => 1],
];
foreach ($attributeMatrix as $value => $row) { addAttribute($value, 2, $row); }
addAttribute('no-event', 9999);
addAttribute('component', 2, ['type' => 'hostname|port', 'value2' => '443']);
addAttribute('shared', 2, ['value2' => 'shared']);
foreach ([2, 4, 8] as $event) { addAttribute('shared', $event); }
foreach ([2, 10] as $event) { addAttribute('numeric-sort', $event); }
addAttribute('CAFÉ ', 2);
addAttribute("nbsp\u{00a0}", 2);
addAttribute('excluded-text', 2, ['type' => 'text']);
foreach (['literal%_', '!negation', 'left&&right', "quote'\\tail", '123', '2001:db8::1'] as $value) { addAttribute($value, 2); }
$user = ['org_id' => 1, 'fixture_sgids' => [7], 'Role' => ['perm_site_admin' => false, 'perm_sync' => false]];
$admin = ['org_id' => 1, 'fixture_sgids' => [], 'Role' => ['perm_site_admin' => true, 'perm_sync' => false]];
$sync = array_replace_recursive($user, ['Role' => ['perm_sync' => true]]);
$orgAdmin = array_replace_recursive($user, ['Role' => ['perm_admin' => true]]);
$publisher = array_replace_recursive($user, ['Role' => ['perm_publish' => true]]);
$readOnly = array_replace_recursive($user, ['Role' => ['perm_add' => false, 'perm_modify' => false]]);
$owner = array_replace($user, ['org_id' => 2, 'fixture_sgids' => []]);
$stranger = array_replace($user, ['org_id' => 3, 'fixture_sgids' => []]);

$unavailable = lookup($user, ['shared']);
same('unavailable', $unavailable['status'], 'index unavailable before first backfill');
same(false, isset($unavailable['results']), 'unbuilt index never returns results');
$build = manager();
same('warming', $build->startRebuild()['status'], 'rebuild starts warming');
same('warming', $build->runBatch(1)['status'], 'incomplete event scan remains warming');
same(false, isset(lookup($user, ['shared'])['results']), 'incomplete backfill gates IOC results');
while (($status = $build->runBatch(3))['status'] === 'warming') {}
same('ready', $status['status'], 'initial backfill ready');

$values = array_merge(array_map(function ($id) { return 'event-' . $id; }, range(1, 8)), array_keys($attributeMatrix),
    ['no-event', 'component', '443', 'component|443', 'shared', 'numeric-sort', 'cafe', 'CAFÉ ', 'nbsp', 'literal%_',
     '!negation', 'left&&right', "quote'\\tail", '123', '2001:0DB8:0000:0000:0000:0000:0000:0001', 'excluded-text', 'missing', 'absent-😀', 'shared']);
$common = ['component' => ['2'], '443' => ['2'], 'shared' => ['2', '4', '8'], 'numeric-sort' => ['2', '10'],
    'cafe' => ['2'], 'CAFÉ ' => ['2'], 'nbsp' => ['2'], 'literal%_' => ['2'], '!negation' => ['2'],
    'left&&right' => ['2'], "quote'\\tail" => ['2'], '123' => ['2'], '2001:0DB8:0000:0000:0000:0000:0000:0001' => ['2']];
$visibleMatrix = ['event-2' => ['2'], 'event-4' => ['4'], 'event-7' => ['7'], 'event-8' => ['8'],
    'attribute-community' => ['2'], 'attribute-connected' => ['2'], 'attribute-all' => ['2'], 'attribute-sg7' => ['2'],
    'object-sg7' => ['2'], 'object-inherit' => ['2'], 'object-public' => ['2']];
jsonSame($visibleMatrix + $common, lookup($user, $values), 'literal components, ACL matrix, SQL collation, publication and type scope');
jsonSame([], lookup($user, []), 'ready empty input');
jsonSame([], lookup($user, ['missing']), 'ready negative result');
foreach (['user' => $user, 'site-admin' => $admin, 'sync' => $sync, 'org-admin' => $orgAdmin,
    'publisher' => $publisher, 'read-only' => $readOnly, 'owner' => $owner, 'stranger' => $stranger] as $role => $actor) {
    $first = lookup($actor, $values);
    $db->getLog(false, true);
    $second = lookup($actor, $values);
    same(json_encode($first), json_encode($second), "$role repeated lookup parity");
    $queries = lookupQueries();
    $live = array_values(array_filter($queries, function ($q) { return strpos($q['query'], 'event_id') !== false; }));
    same(1, count($live), "$role one candidate-constrained exact SQL query");
    same(true, preg_match('/`Attribute`\.`id` IN \(/', $live[0]['query']) === 1, "$role exact SQL constrained by Redis candidates");
    $queryMeasurements[$role] = count($queries);
}
jsonSame(['event-3' => ['3']], lookup($admin, ['event-3', 'event-6']), 'site admin still restricted to publication scope');
jsonSame(['event-3' => ['3']], lookup($owner, ['event-3', 'event-6']), 'owner still restricted to publication scope');
jsonSame([], lookup($sync, ['event-3', 'event-6']), 'sync role retains ACL');
jsonSame([], lookup($admin, ['deleted', 'no-event', 'excluded-text']), 'admin retains deletion/event/type scope');
jsonSame([], lookup(array_replace($user, ['fixture_sgids' => []]), ['event-4']), 'live sharing-group membership revocation');

$missingIps = array_map(function ($i) { return '198.18.' . intdiv($i, 256) . '.' . ($i % 256); }, range(0, 9999));
$started = hrtime(true);
jsonSame([], lookup($user, $missingIps), '10000 distinct IPv4 misses accepted');
$benchmarks[] = ['scenario' => '10000 distinct IPv4 misses', 'elapsed_ms' => round((hrtime(true) - $started) / 1e6, 3)];

// New membership is gated by a durable dirty row, then refreshed persistently.
addAttribute('new.example.org', 2);
changed(2);
same('updating', lookup($user, ['new.example.org'])['status'], 'dirty event gates results');
drain();
jsonSame(['new.example.org' => ['2']], lookup($user, ['new.example.org']), 'new member appears after refresh');

// Candidate authorization always follows current SQL, even if a write bypasses
// callbacks. Normal application mutations additionally create the dirty marker.
$mutations = [
    'deleted-now' => ['UPDATE attributes SET deleted=1 WHERE id=?', []],
    'value1-changed' => ["UPDATE attributes SET value1='replaced' WHERE id=?", []],
    'attribute-private-now' => ['UPDATE attributes SET distribution=0 WHERE id=?', []],
    'attribute-sg-removed' => ['UPDATE attributes SET distribution=4,sharing_group_id=8 WHERE id=?', []],
    'object-private-now' => ['UPDATE objects SET distribution=0 WHERE id=5', ['object_id' => 5]],
];
foreach ($mutations as $value => $case) {
    $id = addAttribute($value, 2, $case[1]); changed(2); drain();
    jsonSame([$value => ['2']], lookup($user, [$value]), "$value initially visible");
    $pdo->prepare($case[0])->execute(strpos($case[0], '?') === false ? [] : [$id]);
    jsonSame([], lookup($user, [$value]), "$value excluded by current SQL");
}
$secondId = addAttribute('unrelated-first', 2, ['value2' => 'value2-changed']); changed(2); drain();
$pdo->exec("UPDATE attributes SET value2='replaced' WHERE id=" . $secondId);
jsonSame([], lookup($user, ['value2-changed']), 'changed second component excluded');
addAttribute('event-revoked', 9); changed(9); drain();
$pdo->exec('UPDATE events SET distribution=0 WHERE id=9');
jsonSame([], lookup($user, ['event-revoked']), 'event distribution revoked immediately');
$pdo->exec('UPDATE events SET distribution=3,published=0 WHERE id=9');
jsonSame([], lookup($admin, ['event-revoked']), 'unpublished excluded even for admin');
changed(9); drain();
$pdo->exec('UPDATE events SET published=1 WHERE id=9'); changed(9); drain();
jsonSame(['event-revoked' => ['9']], lookup($user, ['event-revoked']), 'republish refresh restores membership');
$pdo->exec('DELETE FROM events WHERE id=9'); changed(9); drain();
jsonSame([], lookup($admin, ['event-revoked']), 'event removal removes membership');

// Both IP versions, non-network host bits, overlapping CIDRs and label parents.
foreach ([['192.0.2.199/24', 2], ['192.0.2.1/25', 8], ['0.0.0.0/0', 4],
    ['2001:db8:abcd::1234/48', 2], ['2001:db8::1/32', 8], ['::/0', 4]] as list($range, $event)) {
    addAttribute($range, $event, ['type' => 'ip-src']); changed($event);
}
addAttribute('example.org', 2, ['type' => 'domain']);
addAttribute('b.example.org', 8, ['type' => 'domain|ip', 'value2' => '198.51.100.1']);
addAttribute('example.org', 10, ['type' => 'hostname']);
foreach ([2, 8, 10] as $event) { changed($event); }
drain();
$expanded = lookup($user, ['192.0.2.42', '2001:db8:abcd::9', 'a.b.example.org', 'badexample.org']);
same(['2', '4', '8'], $expanded['results']->{'192.0.2.42'}['event_ids'], 'overlapping IPv4 event IDs');
same(['2'], $expanded['results']->{'192.0.2.42'}['ip_ranges']->{'192.0.2.199/24'}, 'IPv4 original CIDR value retained');
same(['2', '4', '8'], $expanded['results']->{'2001:db8:abcd::9'}['event_ids'], 'overlapping IPv6 event IDs');
same(['2', '8'], $expanded['results']->{'a.b.example.org'}['event_ids'], 'domain parents exclude hostname-only attribute');
same(['2'], $expanded['results']->{'a.b.example.org'}['domains']->{'example.org'}, 'domain parent mapping');
same(false, isset($expanded['results']->{'badexample.org'}), 'parent domains respect label boundaries');

$tenThousand = array_map(function ($i) { return hash('sha512', (string)$i); }, range(1, 10000));
$started = hrtime(true);
jsonSame([], lookup($user, $tenThousand), '10000 SHA512 input values accepted');
$benchmarks[] = ['scenario' => '10000 distinct SHA512 misses', 'elapsed_ms' => round((hrtime(true) - $started) / 1e6, 3)];
$mixed = array_merge(array_slice($missingIps, 0, 5000), array_map(function ($i) { return 'host-' . $i . '.b.example.org'; }, range(0, 4999)));
$started = hrtime(true);
$mixedResult = lookup($user, $mixed);
same('ready', $mixedResult['status'], '10000 mixed containment lookups ready');
same(10000, count(get_object_vars($mixedResult['results'])), '10000 mixed containment lookups complete');
$benchmarks[] = ['scenario' => '5000 IPv4 range matches and 5000 domain-parent matches', 'elapsed_ms' => round((hrtime(true) - $started) / 1e6, 3)];
try { lookup($user, array_merge($tenThousand, ['extra'])); throw new RuntimeException('Missing count rejection'); }
catch (InvalidArgumentException $e) { ++$checks; }
try { $model->fastLookup($user, ['value' => ['shared'], 'maxAge' => 0]); throw new RuntimeException('Missing maxAge rejection'); }
catch (InvalidArgumentException $e) { ++$checks; }
Configure::write('MISP.fast_lookup_max_values', 1);
same('ready', manager()->status()['status'], 'request limit change does not invalidate membership');
try { lookup($user, ['one', 'two']); throw new RuntimeException('Missing configured count rejection'); }
catch (InvalidArgumentException $e) { ++$checks; }
Configure::delete('MISP.fast_lookup_max_values');

$metrics = manager()->status(true)['statistics'];
same(count(FastLookupConfig::scope($model)['attribute_types']), count($metrics['types']), 'statistics include every configured type');
same(true, $metrics['shared_memory_bytes'] > 0, 'shared Redis allocation measured');
$domainMetrics = array_values(array_filter($metrics['types'], function ($row) { return $row['type'] === 'domain'; }))[0];
same(true, $domainMetrics['entries'] > 0 && $domainMetrics['attributes'] > 0 && $domainMetrics['memory_bytes'] > 0, 'domain counts and actual allocation measured');
$cursor = null; $redisKeys = [];
do { $keys = $redis->scan($cursor, $namespace . '*', 1000); if ($keys) { $redisKeys = array_merge($redisKeys, $keys); } } while ($cursor !== 0);
foreach ($redisKeys as $key) {
    same(-1, $redis->ttl($key), 'persistent index key has no TTL');
    same(false, strpos($key, 'example.org') !== false, 'keys contain no plaintext IOC');
}

// Config changes require a fresh backfill, including widening publication scope.
Configure::write('MISP.fast_lookup_published_only', false);
same('unavailable', lookup($user, ['shared'])['status'], 'publication scope mismatch gates results');
rebuild();
jsonSame(['event-1' => ['1'], 'event-6' => ['6']], lookup($admin, ['event-1', 'event-6']), 'all-event scope includes unpublished');
jsonSame(['event-6' => ['6']], lookup($owner, ['event-6']), 'owner can see unpublished within all-event scope');
Configure::write('MISP.unpublishedprivate', false);
jsonSame(['event-6' => ['6']], lookup($user, ['event-6']), 'standard unpublished visibility configuration retained');
Configure::write('MISP.unpublishedprivate', true);
Configure::write('MISP.fast_lookup_attribute_types', 'domain');
same('unavailable', lookup($user, ['shared'])['status'], 'attribute type scope mismatch gates results');
rebuild();
jsonSame([], lookup($user, ['192.0.2.42']), 'type scope excludes network ranges');

// Empty-weight query must preserve SQL's matching of normally empty value2.
$ignorable = "\u{200b}";
$ignorableResult = lookup($user, [$ignorable]);
same(true, isset($ignorableResult['results']->{$ignorable}), 'ignorable-weight input uses exact SQL fallback');

// Rollbacks retain both model data and the durable dirty marker atomically.
$connection = $db->getConnection();
$connection->beginTransaction();
$connection->exec("UPDATE attributes SET value1='rolled-back' WHERE value1='shared'");
changed(2);
same(true, $connection->inTransaction(), 'dirty tracking does not commit caller transaction');
$connection->rollBack();
same('ready', manager()->status()['status'], 'rolled-back dirty marker is not pending');
jsonSame(['shared' => ['2', '4', '8']], lookup($user, ['shared']), 'rollback preserves original lookup values');

// A restored older Redis checkpoint and missing buckets must never be a miss.
$metaKey = $namespace . 'meta';
$metaKeys = $redis->keys($namespace . '*meta*');
same(1, count($metaKeys), 'one index metadata key');
$metaKey = $metaKeys[0];
$revision = $redis->hGet($metaKey, 'revision');
$redis->hSet($metaKey, 'revision', 'old-backup');
same('unavailable', lookup($user, ['shared'])['status'], 'restored stale Redis checkpoint gates results');
$redis->hSet($metaKey, 'revision', $revision);
same('ready', manager()->status()['status'], 'matching checkpoint restored');
$cursor = null; $bucket = null;
do {
    $keys = $redis->scan($cursor, $namespace . '*', 1000);
    foreach ($keys ?: [] as $key) {
        if ($key !== $metaKey && $redis->type($key) === Redis::REDIS_HASH && $redis->hExists($key, '!')) { $bucket = $key; break 2; }
    }
} while ($cursor !== 0);
same(true, is_string($bucket), 'a sentinel-protected index bucket exists');
$redis->del($bucket);
$missing = lookup($user, ['shared']);
same(false, $missing['status'] === 'ready', 'missing bucket refuses result completeness');
same(false, isset($missing['results']), 'missing bucket never returns partial results');

// Flush the test's deferred callback before database cleanup occurs at shutdown.
FastLookupIndexManager::dispatchPending();
$report = ['checks' => $checks, 'versions' => ['php' => PHP_VERSION,
    'mariadb' => $pdo->query('SELECT VERSION()')->fetchColumn(), 'redis' => $redis->info('server')['redis_version']],
    'fixture_attribute_rows' => (int)$pdo->query('SELECT COUNT(*) FROM attributes')->fetchColumn(),
    'default_max_values' => 10000, 'query_counts' => $queryMeasurements, 'benchmarks' => $benchmarks, 'statistics' => $metrics,
    'limitations' => ['Direct model invocation, not HTTP authentication/rate limiting.',
        'Sharing-group membership is supplied by fixture; standard buildConditions and database joins execute.',
        'Mutations use explicit durable recordChange calls; hook routing is covered by lifecycle tests.',
        'Synthetic local data, no production throughput claims.']];
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
