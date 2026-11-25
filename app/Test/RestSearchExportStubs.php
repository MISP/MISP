<?php
// Database boundaries are recorded; the real fetch/filter/export pipeline runs.
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}
if (!class_exists('AppModel', false)) {
    #[AllowDynamicProperties]
    class AppModel
    {
        public function __isset($name) { return false; }
    }
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        public static $values = [];
        public static function read($key) { return self::$values[$key] ?? null; }
        public static function check($key) { return isset(self::$values[$key]); }
    }
}
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $models = [];
        public static function init($name) { return self::$models[$name]; }
    }
}
require_once __DIR__ . '/../Model/MispAttribute.php';
require_once __DIR__ . '/../Model/Allowedlist.php';
require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
foreach (['Text', 'Cache', 'Hashes', 'Count', 'Json'] as $export) {
    require_once __DIR__ . '/../Lib/Export/' . $export . 'Export.php';
}

#[AllowDynamicProperties]
class RestSearchExportLookup
{
    public $queries = [];
    public function find($type, $params) {
        $this->queries[] = [$type, $params];
        return $type === 'first' ? ['Org' => ['id' => 1]] : [];
    }
    public function authorizedIds($user) { return [7]; }
    public function hasNamedIndex($table, $index) { return false; }
    public function harvestSubqueryElements($filters) { return []; }
    public function addFiltersFromSubqueryElements($filters, $elements, $user) { return $filters; }
    public function addFiltersFromUserSettings($user, $filters) { return $filters; }
}

class RestSearchExportAttribute extends MispAttribute
{
    public $queries = [];
    public $tagCalls = 0;
    public $rows = [];
    public $Event;
    public $SharingGroup;
    public $Allowedlist;
    public function __construct() {
        $this->SharingGroup = new RestSearchExportLookup();
        $this->Event = new RestSearchExportLookup();
        $this->Event->Org = new RestSearchExportLookup();
        $this->Event->ThreatLevel = new RestSearchExportLookup();
        $this->rows = [[
            'Attribute' => ['id' => 12, 'event_id' => 3, 'type' => 'filename|md5',
                'value' => 'file|abc', 'comment' => 'large comment'],
            'Event' => ['id' => 3, 'org_id' => 1, 'orgc_id' => 1,
                'threat_level_id' => 1, 'uuid' => 'event-uuid'],
        ]];
    }
    public function getSchemaInspector() { return new RestSearchExportLookup(); }
    public function find($type, $params = []) {
        $this->queries[] = [$type, $params];
        if ($type === 'count') { return count($this->rows); }
        $rows = $this->rows;
        if (!in_array('Attribute.*', $params['fields'], true)) {
            foreach ($rows as &$row) {
                $projected = [];
                foreach ($params['fields'] as $field) {
                    [$model, $name] = explode('.', $field, 2);
                    if (isset($row[$model][$name])) {
                        $projected[$model][$name] = $row[$model][$name];
                    }
                }
                $row = $projected;
            }
        }
        return $rows;
    }
    public function attachTagsToAttributes(array &$attributes, array $options) {
        $this->tagCalls++;
    }
    public function bindModel($associations, $reset = true) {}
    public function findOrder($order, $model, $allowed) { return $order; }
    public function convert_to_memory_limit_to_mb($limit) { return 128; }
    public function buildFilterConditions(array $user, array &$filters, $params = false) {
        return ['Attribute.type' => 'filename|md5', 'Event.published' => 1];
    }
}
