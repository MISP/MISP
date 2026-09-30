<?php
/**
 * Stubs and doubles for AttributeRestSearchCursorTest.
 *
 * Loaded only from the test's setUp(), which runs in a separate process: the
 * unguarded App/Configure/Component stubs here would otherwise collide with
 * the stubs other files under app/Test/ declare in the shared PHPUnit process.
 */


class App { public static function uses($class, $package) {} }
#[AllowDynamicProperties]
class AppModel {}
class Component {}
class Inflector { public static function tableize($name) { return strtolower($name) . "s"; } }
#[AllowDynamicProperties]
class Controller {}
class Configure {
    public static function read($key) { return false; }
    public static function check($key) { return false; }
}
class BadRequestException extends Exception {}
class ClassRegistry {
    public static $allowedIds = [];
    public static function init($name) {
        if ($name === 'Allowedlist') { return new CursorAllowedlist(); }
        throw new Exception($name);
    }
}
class CursorAllowedlist {
    public function removeAllowedlistedFromArray($rows, $unused) {
        return array_filter($rows, function ($row) {
            return !in_array($row['Attribute']['id'], ClassRegistry::$allowedIds);
        });
    }
}
class CursorEvent {
    public $ThreatLevel;
    public $Org;
    public function __construct() {
        $this->ThreatLevel = new CursorDependency();
        $this->Org = new CursorDependency();
    }
    public function harvestSubqueryElements($filters) { return []; }
    public function addFiltersFromSubqueryElements($filters, $elements, $user) { return $filters; }
    public function addFiltersFromUserSettings($user, $filters) { return $filters; }
}
class CursorDependency {
    public function authorizedIds($user) { return []; }
    public function hasNamedIndex($table, $index) { return false; }
    public function find($type, $params) {
        return $type === 'first' ? ['Org' => ['id' => 1]] : [];
    }
    public function filterWarninglistAttribute($attribute) {
        return $attribute['id'] > 4;
    }
}
require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Model/MispAttribute.php';
require_once __DIR__ . '/../Controller/Component/RestSearchComponent.php';
require_once __DIR__ . '/../Controller/AppController.php';
require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
foreach (['Json', 'Text', 'Cache', 'Hashes', 'Count'] as $name) {
    require_once __DIR__ . '/../Lib/Export/' . $name . 'Export.php';
}
class CursorRequest {
    public $params = ['named' => []];
    public $data;
    public function is($type) { return $type === 'post'; }
}
class CursorAuth {
    public function user() { return ['Role' => ['perm_sync' => false]]; }
}
class CursorUser {
    public $roleLimit = 0;
    public function getUserRestLimit($user, $controller) { return $this->roleLimit; }
}
class CursorResponse {
    public function viewData($file, $type, $false, $true, $name, $headers) {
        return ['body' => $file->intoString(), 'headers' => $headers];
    }
}
class CursorController extends AppController {
    public $filters;
    public $modelClass = 'MispAttribute';
    public function __construct($filters) {
        $this->filters = $filters;
        $this->MispAttribute = new CursorSqlAttribute(range(1, 6));
        $this->request = new CursorRequest();
        $this->request->data = $filters;
        $this->RestSearch = new RestSearchComponent();
        $this->Auth = new CursorAuth();
        $this->User = new CursorUser();
        $this->RestResponse = new CursorResponse();
    }
    protected function _closeSession($saveSession = false) { return $this->Auth->user(); }
}


class CursorSqlAttribute extends MispAttribute {
    public $queries = [];
    public $ids = [];
    public $filterConditions = [];
    public function __construct($ids) {
        $this->ids = $ids;
        $this->SharingGroup = new CursorDependency();
        $this->Warninglist = new CursorDependency();
        $this->Event = new CursorEvent();
    }
    public function buildFilterConditions(array $user, array &$params, $skipBuildConditions = false) { return $this->filterConditions; }
    protected function convert_to_memory_limit_to_mb($value) { return 1; }
    public function buildConditions($user) { return ['Event.org_id' => 1]; }
    public function getSchemaInspector() { return new CursorDependency(); }
    public function findOrder($order, $model, $fields) { return $order; }
    public function find($type, $params) {
        $this->queries[] = $params;
        if (count($this->queries) > 15) { throw new Exception('Loop stalled'); }
        $after = 0;
        array_walk_recursive($params['conditions'], function ($value, $key) use (&$after) {
            if ($key === 'Attribute.id >') { $after = max($after, $value); }
        });
        $ids = array_values(array_filter($this->ids, function ($id) use ($after) {
            return $id > $after;
        }));
        $ids = array_slice($ids, $params['offset'] ?? 0, $params['limit']);
        return array_map(function ($id) {
            return [
                'Attribute' => ['id' => $id, 'event_id' => 1, 'value' => 'v' . $id, 'type' => 'md5'],
                'Event' => ['org_id' => 1, 'orgc_id' => 1, 'threat_level_id' => 1],
            ];
        }, $ids);
    }
}
class CursorExport {
    public function separator($params) { return ','; }
    public function handler($row, $params) { return (string) $row['Attribute']['id']; }
}
