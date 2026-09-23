<?php
/**
 * Stubs, production classes and doubles for AttributeBatchRelationsTest.
 *
 * Loaded only from that test's setUp(), which runs in a separate process:
 * the bare Model/AppModel stubs here would otherwise collide with the
 * stubs other files under app/Test/ declare in the shared PHPUnit process.
 */

if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}
if (!class_exists('Model', false)) {
    #[AllowDynamicProperties]
    class Model {}
}
if (!class_exists('AppModel', false)) {
    class AppModel extends Model {}
}
if (!class_exists('ModelBehavior', false)) {
    class ModelBehavior {}
}
if (!class_exists('Configure', false)) {
    class Configure { public static function read($key) { return null; } }
}
require_once __DIR__ . '/../Model/Correlation.php';
require_once __DIR__ . '/../Model/MispAttribute.php';
if (file_exists(__DIR__ . '/../Model/Behavior/RelatedAttributeBatchTrait.php')) {
    require_once __DIR__ . '/../Model/Behavior/RelatedAttributeBatchTrait.php';
}
require_once __DIR__ . '/../Model/Behavior/DefaultCorrelationBehavior.php';
require_once __DIR__ . '/../Model/Behavior/NoAclCorrelationBehavior.php';
require_once __DIR__ . '/../Model/Behavior/OnDemandCorrelationBehavior.php';

/** Replaces only database I/O, including the selected fields and conditions. */
class BatchRelationRows extends Model
{
    public $rows = [];
    public $queries = [];
    public $visibleIds = [];
    public function fetchAttributesSimple($user, $query)
    {
        $query['conditions']['Attribute.id'] = array_values(array_intersect(
            $query['conditions']['Attribute.id'], $this->visibleIds
        ));
        return $this->find('all', $query);
    }
    public function find($type, $query)
    {
        $this->queries[] = $query;
        $rows = array_values(array_filter($this->rows, function ($row) use ($query) {
            foreach ($query['conditions'] as $field => $expected) {
                $different = substr($field, -3) === ' !=';
                $field = str_replace(' !=', '', $field);
                list($alias, $name) = explode('.', $field);
                $actual = $row[$alias][$name];
                $matches = is_array($expected)
                    ? in_array($actual, $expected) : $actual == $expected;
                if ($different ? $matches : !$matches) {
                    return false;
                }
            }
            return true;
        }));
        foreach ($rows as &$row) {
            if (!empty($query['fields'])) {
                $alias = isset($row['Correlation']) ? 'Correlation' : 'Attribute';
                $fields = array_map(function ($field) use ($alias) {
                    return str_replace($alias . '.', '', $field);
                }, $query['fields']);
                $row[$alias] = array_intersect_key($row[$alias], array_flip($fields));
            }
            if (empty($query['contain']['Event'])) {
                unset($row['Event']);
            }
        }
        if ($type === 'column') {
            $field = $query['fields'][0];
            return array_column(array_column($rows, 'Correlation'), $field);
        }
        return $rows;
    }
}

class BatchTestCorrelation extends Correlation
{
    public $backend;
    public $storage;
    public $engineName = 'Default';
    public function __construct() {}
    public function getCorrelationModelName() { return $this->engineName; }
    public function find($type, $query) { return $this->storage->find($type, $query); }
    public function __call($method, $args)
    {
        return $this->backend->$method($this, ...$args);
    }
}
