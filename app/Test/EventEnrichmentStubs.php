<?php
/** Framework stubs for EventEnrichmentTest; loaded only in its isolated processes. */
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel {}
}
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = [];

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new class {
                    public $responses = [];

                    public function find($type, $options = [])
                    {
                        return array_shift($this->responses) ?: [];
                    }
                };
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = [];
        }
    }
}
require_once __DIR__ . '/../Model/Event.php';
require_once __DIR__ . '/../Model/MispAttribute.php';

class EnrichmentTestEvent extends Event
{
    public $Attribute;
    public $Module;
}

class EnrichmentTestAttribute extends MispAttribute
{
    public $Event;
    public $Module;
    public $attribute;
    public $saved = [];

    public function __construct() {}

    public function fetchAttributes(array $user, array $options = [], &$result_count = false, $real_count = false, &$skipped_item_count = false, &$last_read_id = 0)
    {
        return [['Attribute' => $this->attribute]];
    }

    public function create($data = [], $filterKey = false) {}

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->saved[] = $data;
        return true;
    }
}
