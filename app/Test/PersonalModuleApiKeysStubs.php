<?php
/** Loaded only inside the isolated PersonalModuleApiKeysTest processes. */
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
        public static function import($type, $name) {}
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel {}
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = [];
        public static function read($name) { return self::$values[$name] ?? null; }
        public static function write($name, $value) { self::$values[$name] = $value; }
        public static function check($name) { return isset(self::$values[$name]); }
        public static function reset() { self::$values = []; }
    }
}
if (!class_exists('MethodNotAllowedException', false)) {
    class MethodNotAllowedException extends RuntimeException {}
}
if (!function_exists('__')) {
    function __($text, ...$args) { return $args ? vsprintf($text, $args) : $text; }
}
require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
require_once __DIR__ . '/../Lib/Tools/BetterSecurity.php';
require_once __DIR__ . '/../Lib/Tools/EncryptedValue.php';
require_once __DIR__ . '/../Model/Module.php';
require_once __DIR__ . '/../Model/UserSetting.php';

if (!class_exists('Model', false)) {
    class Model {}
}
if (!class_exists('ModelBehavior', false)) {
    class ModelBehavior {}
}
if (!class_exists('LogableBehavior', false)) {
    class LogableBehavior extends ModelBehavior
    {
        public $settings = [];
        public $schema = [];
        public $old = [];
    }
}
// 3.0's audit behaviour reads the value columns through AttributeValue
if (!class_exists('AttributeValue', false)) {
    require_once __DIR__ . '/../Model/AttributeValue.php';
}
require_once __DIR__ . '/../Model/Behavior/AuditLogBehavior.php';
require_once __DIR__ . '/../Plugin/SysLogLogable/Model/Behavior/SysLogLogableBehavior.php';

class PersonalKeysLogModel extends Model
{
    public $alias = 'UserSetting';
    public $name = 'UserSetting';
    public $primaryKey = 'id';
    public $id = 1;
    public $data;
    public function schema($field = false)
    {
        return ['id' => ['type' => 'integer'], 'setting' => ['type' => 'string'], 'value' => ['type' => 'text']];
    }
}

class PersonalKeysLegacyLogger extends SysLogLogableBehavior
{
    public $captured;
    public function prepare($old)
    {
        $this->settings['UserSetting'] = ['enabled' => true, 'ignore' => [], 'change' => 'full', 'foreignKey' => 'model_id'];
        $this->schema = ['change' => true];
        $this->old = $old;
    }
    public function _saveLog(&$Model, $logData, $title = null) { $this->captured = $logData; }
}

class PersonalKeysTestModule extends Module
{
    public $settings = [];
    public $credentials = [];
    public $lookups = [];
    public $listings = [];

    protected function moduleConfigSetting($name) { return $this->settings[$name] ?? null; }
    protected function personalModuleApiKeys($userId)
    {
        $this->lookups[] = $userId;
        return $this->credentials[$userId] ?? [];
    }
    public function getModules($family = 'Enrichment', $throwException = false) { return $this->listings; }
}

class PersonalKeysTestSetting extends UserSetting
{
    public $data = [];
    public $rows = [];
    public $queries = [];
    public $User;
    public $saved;
    public $updates = [];

    public function find($type, $options = [])
    {
        $this->queries[] = $options;
        if ($type === 'all') {
            return array_values($this->rows);
        }
        return $this->rows[$options['conditions']['UserSetting.user_id']] ?? [];
    }

    public function getDataSource()
    {
        return new class {
            public function value($value, $type) { return $value; }
        };
    }

    public function updateAll($fields, $conditions = true)
    {
        $this->updates[] = $fields;
        foreach ($this->rows as &$row) {
            if ($row['UserSetting']['id'] == $conditions['UserSetting.id']) {
                $row['UserSetting']['value'] = $fields['UserSetting.value'];
            }
        }
        return true;
    }

    public function setSettingInternal($userId, $setting, $value)
    {
        $this->saved = compact('userId', 'setting', 'value');
        return true;
    }
}


// These entry points must load against the same isolated framework stubs.
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = [];
        public static function init($name) { return self::$instances[$name]; }
    }
}
if (!class_exists('AppShell', false)) {
    class AppShell {}
}
require_once __DIR__ . '/../Model/MispAttribute.php';
require_once __DIR__ . '/../Console/Command/AdminShell.php';

class PersonalKeysEnrichmentModule extends PersonalKeysTestModule
{
    public $requests = [];

    public function queryModuleServer(array $postData, $hover = false, $moduleFamily = 'Enrichment', $throwException = false, $triggerData = [], $skipTrigger = false)
    {
        $this->requests[] = $postData;
        return [];
    }
}

class PersonalKeysTestAttribute extends MispAttribute
{
    public $Event;
    public $Module;

    public function __construct() {}

    public function fetchAttributes(array $user, array $options = [], &$result_count = false, $real_count = false, &$skipped_item_count = false, &$last_read_id = 0)
    {
        return [['Attribute' => [
            'id' => 42, 'event_id' => 7, 'object_id' => 0,
            'uuid' => 'd1849030-b2b9-43d0-a30a-a1433bb4ba3a',
            'type' => 'sha256', 'value' => str_repeat('a', 64),
        ]]];
    }
}

class PersonalKeysTestAdminShell extends AdminShell
{
    public $params = [];
    public $Server;

    public function out($message) {}
    public function error($message, $details = null) { throw new RuntimeException($message); }
}

class PersonalKeysRotationContext
{
    public $steps = [];
    public function begin() { $this->steps[] = 'begin'; }
    public function commit() { $this->steps[] = 'commit'; }
    public function rollback() { $this->steps[] = 'rollback'; }
}

class PersonalKeysRotationServer
{
    private $context;
    public function __construct($context) { $this->context = $context; }
    public function getDataSource() { return $this->context; }
    public function reencryptAuthKeys($old, $new) { $this->context->steps[] = 'server'; }
    public function serverSettingsSaveValue($name, $value, $skipHooks = false)
    {
        $this->context->steps[] = 'save-key';
        Configure::write($name, $value);
        return true;
    }
}

class PersonalKeysRotationParticipant
{
    private $context;
    private $name;
    public function __construct($context, $name) { $this->context = $context; $this->name = $name; }
    public function reencrypt($old, $new) { $this->context->steps[] = $this->name; }
    public function reencryptAuthKeys($old, $new) { $this->reencrypt($old, $new); }
}

class PersonalKeysRotationSetting extends PersonalKeysTestSetting
{
    public $context;
    public $failUpdate = false;

    public function updateAll($fields, $conditions = true)
    {
        $this->context->steps[] = 'personal';
        return !$this->failUpdate && parent::updateAll($fields, $conditions);
    }
}
