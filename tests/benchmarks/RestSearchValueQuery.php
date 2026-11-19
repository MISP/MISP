<?php
/**
 * Render the real fetchAttributes query without a MISP installation.
 * Usage: php RestSearchValueQuery.php /path/to/cakephp/lib/Cake < case.json
 * Only collaborators that would access the database are substituted. Filtering,
 * ACL construction and SQL rendering use the application's production classes.
 */
define('DS', DIRECTORY_SEPARATOR);
define('CAKE', rtrim($argv[1], '/') . '/');
define('APP', dirname(__DIR__, 2) . '/app/');
define('APPLIBS', APP . 'Lib/');
error_reporting(E_ALL & ~E_DEPRECATED);

class App
{
    public static function uses($class, $package) {}
}
class Configure
{
    public static function read($key)
    {
        return $key === 'MISP.unpublishedprivate';
    }
    public static function check($key) { return false; }
}
require CAKE . 'basics.php';
require CAKE . 'Core/CakeObject.php';
require CAKE . 'Event/CakeEventListener.php';
require CAKE . 'Model/Model.php';
require CAKE . 'Utility/Hash.php';
require CAKE . 'Utility/Inflector.php';
require CAKE . 'Model/Datasource/DataSource.php';
require CAKE . 'Model/Datasource/DboSource.php';
require CAKE . 'Model/Datasource/Database/Mysql.php';
require APPLIBS . 'Migration/LegacyMigrationsTrait.php';
require APP . 'Model/AppModel.php';
require APP . 'Model/MispAttribute.php';
require APP . 'Model/Datasource/Database/MysqlExtended.php';
require APPLIBS . 'Migration/Grammar/OfflineConnection.php';
require APPLIBS . 'Migration/Grammar/OfflineMysql.php';

class RestSearchBenchmarkAttribute extends MispAttribute
{
    public $captured;
    private $legacyDeletedIndex;
    public function __construct($legacyDeletedIndex)
    {
        $this->legacyDeletedIndex = $legacyDeletedIndex;
        $this->SharingGroup = new class {
            public function authorizedIds($user) { return [1]; }
        };
        $this->Event = (object)['ThreatLevel' => new class {
            public function find($type, $options) { return []; }
        }];
    }
    public function find($type = 'first', $query = [])
    {
        $this->captured = $query;
        return [];
    }
    public function getSchemaInspector()
    {
        return new class($this->legacyDeletedIndex) {
            private $present;
            public function __construct($present) { $this->present = $present; }
            public function hasNamedIndex($table, $index) { return $this->present; }
        };
    }
    public function getColumnType($column)
    {
        return preg_match('/(?:id|distribution|deleted|published|to_ids)$/',
            $column) ? 'integer' : 'string';
    }
}

$case = json_decode(stream_get_contents(STDIN), true, 512,
    JSON_THROW_ON_ERROR);
$model = new RestSearchBenchmarkAttribute(!empty($case['legacy_deleted_index']));
$filter = ['OR' => $case['values']];
$conditions = $model->generic_add_filter([], $filter,
    ['Attribute.value1', 'Attribute.value2']);
$valueConditions = $conditions;
foreach ($case['conditions'] ?? [] as $condition) {
    $conditions['AND'][] = $condition;
}
$user = ['org_id' => 1, 'Role' => [
    'perm_site_admin' => !empty($case['admin']), 'perm_sync' => false,
]];
$model->fetchAttributes($user, [
    'conditions' => $conditions, 'flatten' => true,
    'limit' => $case['limit'] ?? 500, 'order' => 'Attribute.id ASC',
]);
$query = $model->captured;
$db = new OfflineMysql();
$db->config['database'] = 'misp_restsearch_test';
$query['table'] = '`attributes`';
$query['alias'] = 'Attribute';
$query['fields'][] = $model->virtualFields['value'] . ' AS Attribute__value';

// Remove only the exact-value predicate, retaining every other filter and ACL.
$unionQuery = $query;
foreach ($unionQuery['conditions']['AND'] as &$clause) {
    if (isset($clause['AND'])) {
        $clause['AND'] = array_values(array_filter($clause['AND'],
            function ($condition) use ($valueConditions) {
                return $condition !== $valueConditions['AND'][0];
            }));
    }
}
unset($clause);
$quoted = implode(', ', array_map(function ($value) use ($db) {
    return $db->value($value, 'string');
}, $case['values']));
$unionQuery['joins'][] = [
    'type' => 'INNER', 'alias' => 'ValueMatch',
    'table' => '(SELECT id FROM attributes WHERE value1 IN (' . $quoted .
        ') UNION SELECT id FROM attributes WHERE value2 IN (' . $quoted . '))',
    'conditions' => ['ValueMatch.id = Attribute.id'],
];
$output = [];
foreach (['or' => $query, 'union' => $unionQuery] as $name => $params) {
    $output[$name] = $db->buildStatement($params, $model);
    $params['fields'] = ['Attribute.id'];
    $output[$name . '_ids'] = $db->buildStatement($params, $model);
}
echo json_encode($output, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
