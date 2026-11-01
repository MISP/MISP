<?php
/**
 * Focused integration test: real Cake Model/Containable/Mysql and MariaDB SQL.
 * Run against a disposable server (a unique test database is created and removed):
 * php RestSearchSqlIntegration.php /path/to/cakephp/lib/Cake /path/to/mysql.sock
 * Framework startup, sharing-group membership and unrelated enrichments are
 * isolated; SQL generation, ACLs, hydration, virtual fields and afterFind run.
 */
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
define('CONFIG', TMP . 'restsearch-sql-config/');
error_reporting(E_ALL & ~E_DEPRECATED);
@mkdir(CONFIG);
file_put_contents(CONFIG . 'database.php', '<?php class DATABASE_CONFIG {}');
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
App::build(['Model' => [APP . 'Model/'], 'Model/Behavior' => [APP . 'Model/Behavior/'],
    'Model/Datasource/Database' => [APP . 'Model/Datasource/Database/'],
    'Tools' => [APPLIBS . 'Tools/'], 'Migration' => [APPLIBS . 'Migration/']], App::PREPEND);
App::uses('MispAttribute', 'Model');
App::uses('Correlation', 'Model');
App::uses('ConnectionManager', 'Model');

trait RestSearchSqlModelSetup
{
    protected function _mergeVars($properties, $class, $normalize = true)
    {
        // Only Containable is needed; logging/analyst/workflow integrations are
        // outside this fixture. Keep real Cake find methods and callbacks.
        parent::_mergeVars(array_values(array_diff($properties, ['actsAs'])), $class, $normalize);
    }
}

class RestSearchSqlIntegrationAttribute extends MispAttribute
{
    use RestSearchSqlModelSetup;
    public $actsAs = ['Containable'];
    public $belongsTo = [];
    public $hasMany = [];
    public function __construct()
    {
        AppModel::__construct(false, 'attributes', 'default');
        $this->SharingGroup = new class {
            public function authorizedIds($user) { return [7]; }
        };
        $this->Event = new Model(['name' => 'Event', 'table' => 'events']);
        $this->AttributeTag = new Model(['name' => 'AttributeTag', 'table' => 'attribute_tags']);
        $this->AttributeTag->Tag = new Model(['name' => 'Tag', 'table' => 'tags']);
        $this->Event->EventTag = new Model(['name' => 'EventTag', 'table' => 'event_tags']);
        $this->Event->EventTag->Behaviors->load('Containable');
        $this->Event->EventTag->Tag = $this->AttributeTag->Tag;
        $this->Event->EventTag->bindModel(['belongsTo' => ['Tag' => ['className' => 'Model', 'foreignKey' => 'tag_id']]], false);
        $this->bindModel(['belongsTo' => ['Event' => ['className' => 'Model', 'foreignKey' => 'event_id']],
            'hasMany' => ['AttributeTag' => ['className' => 'Model', 'foreignKey' => 'attribute_id']]], false);
        $this->Event->ThreatLevel = new class {
            public function find($type, $query) { return []; }
        };
        $this->Event->Org = new class {
            public function find($type, $query) { return ['Org' => ['id' => 1, 'name' => 'Fixture', 'uuid' => 'fixture']]; }
        };
    }
}

class RestSearchSqlIntegrationCorrelation extends Correlation
{
    use RestSearchSqlModelSetup;
    public $actsAs = ['Containable'];
    public $belongsTo = [];
    private $testEngine;
    public function __construct($engine, $attribute)
    {
        $this->testEngine = $engine;
        $table = $engine === 'Default' ? 'default_correlations' : 'no_acl_correlations';
        AppModel::__construct(['name' => 'Correlation', 'alias' => 'Correlation', 'table' => $table]);
        $this->Attribute = $attribute;
        $this->Behaviors->load($engine . 'Correlation', ['deadlockAvoidance' => false]);
    }
    public function getCorrelationModelName() { return $this->testEngine; }
}

$pdo = new PDO('mysql:unix_socket=' . $argv[2], 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$database = 'restsearch_sql_' . bin2hex(random_bytes(8));
$pdo->exec('CREATE DATABASE `' . $database . '`');
register_shutdown_function(function () use ($pdo, $database) {
    $pdo->exec('DROP DATABASE `' . $database . '`');
});
$pdo->exec('USE `' . $database . '`');
$schema = json_decode(file_get_contents(ROOT . '/db_schema.json'), true)['schema'];
foreach (['attributes', 'events', 'objects', 'attribute_tags', 'event_tags', 'tags', 'default_correlations', 'no_acl_correlations'] as $table) {
    $columns = [];
    foreach ($schema[$table] as $column) {
        // Allow omitted unrelated fields in narrow synthetic records.
        $columns[] = '`' . $column['column_name'] . '` ' . $column['column_type'] .
            ($column['column_name'] === 'id' ? ' NOT NULL AUTO_INCREMENT PRIMARY KEY' : ' NULL');
    }
    $pdo->exec('CREATE TABLE `' . $table . '` (' . implode(',', $columns) . ')');
}
$pdo->exec('CREATE INDEX deleted ON attributes (deleted)');
function insertRow($table, $row)
{
    global $pdo;
    $pdo->prepare('INSERT INTO `' . $table . '` (`' . implode('`,`', array_keys($row)) .
        '`) VALUES (' . implode(',', array_fill(0, count($row), '?')) . ')')->execute(array_values($row));
}
ConnectionManager::create('default', ['datasource' => 'Database/MysqlExtended', 'unix_socket' => $argv[2],
    'login' => 'root', 'password' => '', 'database' => $database,
    'prefix' => '', 'encoding' => 'utf8mb4', 'persistent' => false]);
$events = [];
foreach ([1 => [1, 0, 0, 0], 2 => [2, 3, 0, 1], 3 => [2, 0, 0, 1],
    4 => [2, 4, 7, 1], 5 => [2, 4, 8, 1], 6 => [2, 3, 0, 0]] as $id => $acl) {
    $events[$id] = ['id' => $id, 'org_id' => $acl[0], 'orgc_id' => $acl[0],
        'distribution' => $acl[1], 'sharing_group_id' => $acl[2], 'published' => $acl[3],
        'info' => 'event-' . $id, 'uuid' => 'event-' . $id, 'threat_level_id' => 1,
        'analysis' => 0, 'date' => '2026-09-23', 'timestamp' => 1];
    insertRow('events', $events[$id]);
}
insertRow('objects', ['id' => 1, 'distribution' => 0, 'sharing_group_id' => 0]);
insertRow('objects', ['id' => 2, 'distribution' => 4, 'sharing_group_id' => 7]);
$attributes = [];
foreach ([1 => [1, 0, 0, 0, 0], 2 => [2, 5, 0, 0, 0], 3 => [3, 5, 0, 0, 0],
    4 => [4, 4, 7, 0, 0], 5 => [5, 5, 0, 0, 0], 6 => [6, 5, 0, 0, 0],
    7 => [2, 0, 0, 0, 0], 8 => [2, 4, 8, 0, 0], 9 => [2, 5, 0, 1, 0],
    10 => [2, 5, 0, 2, 0], 11 => [2, 5, 0, 0, 1], 12 => [2, 5, 0, 0, 0]] as $id => $acl) {
    $attributes[$id] = ['id' => $id, 'event_id' => $acl[0], 'distribution' => $acl[1],
        'sharing_group_id' => $acl[2], 'object_id' => $acl[3], 'deleted' => $acl[4],
        'type' => 'domain', 'category' => 'Network activity', 'value1' => 'example-' . $id . '.org',
        'value2' => $id === 12 ? '443' : '', 'to_ids' => 1, 'timestamp' => 1];
    insertRow('attributes', $attributes[$id]);
}
$checks = 0;
function same($expected, $actual, $label)
{
    global $checks;
    if ($expected !== $actual) {
        throw new RuntimeException($label . "\nExpected " . var_export($expected, true) . "\nActual " . var_export($actual, true));
    }
    $checks++;
}
$user = ['org_id' => 1, 'Role' => ['perm_site_admin' => false, 'perm_sync' => false]];
$admin = ['org_id' => 1, 'Role' => ['perm_site_admin' => true, 'perm_sync' => true]];
$attribute = new RestSearchSqlIntegrationAttribute();
$requirements = ['fields' => ['Attribute.type', 'Attribute.value'], 'attributeTags' => false,
    'organisations' => false, 'threatLevels' => false];
$options = ['flatten' => true, 'order' => 'Attribute.id ASC', 'limit' => 100,
    'exportRequirements' => $requirements];
$rows = $attribute->fetchAttributes($user, $options);
same([1, 2, 4, 10, 12], array_map('intval', Hash::extract($rows, '{n}.Attribute.id')), 'ACL projection ids');
same('example-12.org|443', end($rows)['Attribute']['value'], 'virtual composite value');
same(false, isset($rows[0]['Attribute']['comment']), 'projection excludes unneeded columns');
foreach ([$user, $admin] as $actor) {
    foreach ([[], ['deleted' => 'only'], ['deleted' => true], ['flatten' => false],
        ['conditions' => ['Event.id' => 2]], ['conditions' => ['Object.distribution' => 4]]] as $case) {
        $query = array_replace($options, $case);
        $hydrated = $attribute->fetchAttributes($actor, $query);
        $count = $attribute->fetchAttributes($actor, $query + ['countOnly' => true]);
        same(count($hydrated), $count, 'SQL count equals hydration ' . json_encode($case));
    }
}
$legacy = $attribute->fetchAttributes($user, array_diff_key($options, ['exportRequirements' => true]));
same(Hash::extract($rows, '{n}.Attribute.id'), Hash::extract($legacy, '{n}.Attribute.id'), 'full-row/projection ids');
same(true, array_key_exists('comment', $legacy[0]['Attribute']), 'default full row preserved');

foreach ([1 => 1, 2 => 0] as $tagId => $exportable) {
    insertRow('tags', ['id' => $tagId, 'name' => 'tag-' . $tagId, 'exportable' => $exportable]);
    insertRow('attribute_tags', ['attribute_id' => 1, 'event_id' => 1, 'tag_id' => $tagId, 'local' => 0]);
    insertRow('event_tags', ['event_id' => 2, 'tag_id' => $tagId, 'local' => 0]);
}
$tagged = $attribute->fetchAttributes($user, array_diff_key($options, ['exportRequirements' => true]));
same(['tag-1'], Hash::extract($tagged[0]['AttributeTag'], '{n}.Tag.name'), 'exportable attribute tags hydrated');
$taggedAll = $attribute->fetchAttributes($user, array_diff_key($options, ['exportRequirements' => true]) + ['includeAllTags' => true]);
same(['tag-1', 'tag-2'], Hash::extract($taggedAll[0]['AttributeTag'], '{n}.Tag.name'), 'includeAllTags attribute hydration');
$db = ConnectionManager::getDataSource('default');
foreach ([false, true] as $allTags) {
    $db->getLog(false, true);
    $withEventTags = $attribute->fetchAttributes($user, $options + ['includeEventTags' => true, 'includeAllTags' => $allTags]);
    $tagQueries = array_filter($db->getLog(false, true)['log'], function ($entry) use ($database) {
        return strpos($entry['query'], 'FROM `' . $database . '`.`event_tags`') !== false;
    });
    same(1, count($tagQueries), 'one event-tag SQL query for multiple events');
    foreach ($withEventTags as $row) {
        $expectedTags = $row['Attribute']['event_id'] == 2 ? ($allTags ? ['tag-1', 'tag-2'] : ['tag-1']) : [];
        same($expectedTags, Hash::extract($row['EventTag'], '{n}.Tag.name'), 'inherited tag exportability and empty events');
        foreach ($row['EventTag'] as $tag) {
            same(true, $tag['Tag']['inherited'], 'inherited event tag flag');
        }
    }
}

// Scan progress must reflect SQL rows, including pages entirely discarded by
// PHP warning-list filtering. This is the metadata consumed by cursor export.
$attribute->Warninglist = new class {
    public function filterWarninglistAttribute($row) { return false; }
};
$cursor = 0;
$scanned = [];
do {
    $scanOptions = array_replace($options, ['limit' => 2, 'enforceWarninglist' => true,
        'conditions' => ['Attribute.id >' => $cursor]]);
    $count = false;
    $skipped = 0;
    $scan = null;
    $filtered = $attribute->fetchAttributes($user, $scanOptions, $count, false, $skipped, $scan);
    same([], $filtered, 'all SQL rows can be filtered by PHP');
    same($scan['count'], $skipped, 'raw scan count retained across PHP filtering');
    if ($scan['last_id'] !== null) {
        $cursor = (int)$scan['last_id'];
        $scanned[] = $cursor;
    }
} while ($scan['count'] === 2);
same([2, 10, 12], $scanned, 'keyset SQL boundary progresses across filtered pages');

class Allowedlist extends Model
{
    public $useTable = false;
    public function removeAllowedlistedFromArray($rows, $isAttributeArray)
    {
        return array_values(array_filter($rows, function ($row) {
            return $row['Attribute']['id'] != 2;
        }));
    }
}
$iterate = new ReflectionMethod(MispAttribute::class, '__iteratedFetch');
$iterate->setAccessible(true);
$exporter = new class {
    public function separator($params) { return ','; }
    public function handler($row, $params) { return (string)$row['Attribute']['id']; }
};
foreach ([
    [0, 3, false, '1,4', 3, 4, true],
    [4, 3, false, '10,12', 2, 12, false],
    [0, 3, true, '', 3, 4, true],
] as $case) {
    [$after, $limit, $filterAll, $output, $rawCount, $next, $more] = $case;
    $params = array_replace($options, ['conditions' => [], 'after_id' => $after,
        'limit' => $limit, 'enforceWarninglist' => $filterAll]);
    $file = new TmpFileTool();
    $skipped = 0;
    $pagination = null;
    $args = [$user, $params, false, $file, $exporter, [], 2, &$skipped, &$pagination];
    same($rawCount, $iterate->invokeArgs($attribute, $args), 'cursor SQL rows bounded across role-sized chunks');
    same($output, $file->intoString(), 'cursor output after allowedlist and warning-list exclusions');
    same(['next_cursor' => $next, 'has_more' => $more], $pagination, 'cursor continuation tracks raw SQL');
}

// Both edge directions, duplicates, same-event exclusion, private and SG ACLs.
foreach ([[1, 2], [1, 3], [4, 1], [1, 5], [1, 7], [1, 8], [1, 9], [10, 1],
    [1, 12], [1, 12], [2, 4], [2, 12], [3, 4]] as $edge) {
    $row = [];
    foreach (['' => $edge[0], '1_' => $edge[1]] as $prefix => $id) {
        $a = $attributes[$id];
        $e = $events[$a['event_id']];
        foreach (['attribute_id' => $id, 'event_id' => $a['event_id'], 'object_id' => $a['object_id'],
            'org_id' => $e['org_id'], 'distribution' => $a['distribution'],
            'sharing_group_id' => $a['sharing_group_id'], 'event_distribution' => $e['distribution'],
            'event_sharing_group_id' => $e['sharing_group_id'],
            'object_distribution' => $a['object_id'] === 2 ? 4 : 0,
            'object_sharing_group_id' => $a['object_id'] === 2 ? 7 : 0] as $field => $value) {
            $row[$prefix . $field] = $value;
        }
    }
    insertRow('default_correlations', $row);
    insertRow('no_acl_correlations', array_intersect_key($row, array_flip(['attribute_id', 'event_id', '1_attribute_id', '1_event_id'])));
}
$sources = [$attributes[1], $attributes[2], $attributes[4], $attributes[5]];
foreach (['Default', 'NoAcl'] as $engine) {
    $correlation = new RestSearchSqlIntegrationCorrelation($engine, $attribute);
    foreach ([$user, $admin] as $actor) {
        foreach ([false, true] as $eventData) {
            foreach ([['id', 'event_id', 'value'], ['event_id', 'value'], ['value'], []] as $fields) {
                $expected = [];
                foreach ($sources as $source) {
                    $expected[$source['id']] = $correlation->getRelatedAttributes($actor, [7], $source, $fields, $eventData);
                }
                $db->getLog(false, true);
                $actual = $correlation->getRelatedAttributesBatch($actor, [7], $sources, $fields, $eventData);
                same($expected, $actual, "$engine correlation parity eventData=$eventData fields=" . json_encode($fields));
                same(3, count($db->getLog(false, true)['log']), "$engine two edge queries plus one hydration query");
            }
        }
    }
}

echo "PASS: $checks real Cake/MariaDB assertions; MariaDB " . $pdo->query('SELECT VERSION()')->fetchColumn() . "\n";
