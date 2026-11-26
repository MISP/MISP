<?php
/**
 * The audit log files an edit under the event the stored row belongs to, not
 * under an event_id the save carried but did not write.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

class AuditLogEventIdAppModelStub
{
}

class AuditLogEventIdRecorder
{
    public $rows = [];

    public function insert(array $row)
    {
        $this->rows[] = $row;
    }
}

class AuditLogBehaviorEventIdTest extends TestCase
{
    /** @var AuditLogEventIdRecorder */
    private $log;

    /**
     * Stubs are declared at run time, and only when no other test file has
     * declared fuller ones while the suite loaded.
     */
    private static function load()
    {
        if (!class_exists('App', false)) {
            eval('class App { public static function uses($class, $package = null) {} }');
        }
        if (!class_exists('Model', false)) {
            eval('class Model { public $alias; public $name; public $primaryKey = "id"; public $id = null; public $data = []; }');
        }
        if (!class_exists('ModelBehavior', false)) {
            eval('class ModelBehavior {}');
        }
        if (!class_exists('AppModel', false)) {
            class_alias('AuditLogEventIdAppModelStub', 'AppModel');
        }
        if (!class_exists('AuditLog', false)) {
            require_once __DIR__ . '/../Model/AuditLog.php';
        }
        require_once __DIR__ . '/../Model/Behavior/AuditLogBehavior.php';
    }

    private function behavior()
    {
        self::load();
        $class = new ReflectionClass('AuditLogBehavior');
        $behavior = $class->newInstanceWithoutConstructor();
        $this->log = new AuditLogEventIdRecorder();
        foreach (['enabled' => true, 'AuditLog' => $this->log] as $name => $value) {
            $property = $class->getProperty($name);
            $property->setAccessible(true);
            $property->setValue($behavior, $value);
        }
        return $behavior;
    }

    private function attributeModel(array $stored, array $data)
    {
        $model = new class extends Model {
            public $alias = 'Attribute';
            public $name = 'MispAttribute';
            public $primaryKey = 'id';
            public $id = null;
            public $data = [];
            public $stored = [];

            public function __construct()
            {
            }

            public function schema($field = false)
            {
                return [
                    'id' => ['type' => 'integer'],
                    'event_id' => ['type' => 'integer'],
                    'object_id' => ['type' => 'integer'],
                    'value1' => ['type' => 'string'],
                    'comment' => ['type' => 'string'],
                    'deleted' => ['type' => 'boolean'],
                ];
            }

            public function find($type = 'first', $query = [])
            {
                if (empty($this->stored)) {
                    return [];
                }
                $row = $this->stored;
                if (!empty($query['fields'])) {
                    $row = array_intersect_key($row, array_flip($query['fields']));
                }
                return [$this->alias => $row];
            }
        };
        $model->stored = $stored;
        $model->data = ['Attribute' => $data];
        $model->id = $data['id'] ?? null;
        return $model;
    }

    private function save($behavior, $model, $created, array $options)
    {
        $this->assertTrue($behavior->beforeSave($model, $options));
        $behavior->afterSave($model, $created, $options);
        $this->assertCount(1, $this->log->rows);
        return $this->log->rows[0];
    }

    public function testEditLoggedUnderStoredEventNotCarriedOne()
    {
        $behavior = $this->behavior();
        $model = $this->attributeModel(
            ['id' => 838, 'event_id' => 5, 'object_id' => 0, 'value1' => 'victim', 'comment' => '', 'deleted' => 0],
            ['id' => 838, 'event_id' => 99, 'value1' => 'overwritten', 'deleted' => 1]
        );
        $row = $this->save($behavior, $model, false, ['fieldList' => ['value1', 'comment', 'deleted']]);
        $this->assertSame(5, $row['event_id']);
        $this->assertSame(['victim', 'overwritten'], $row['change']['value1']);
    }

    public function testEditWithoutFieldListLoggedUnderStoredEvent()
    {
        $behavior = $this->behavior();
        $model = $this->attributeModel(
            ['id' => 838, 'event_id' => 5, 'object_id' => 0, 'value1' => 'victim', 'comment' => '', 'deleted' => 0],
            ['id' => 838, 'event_id' => 99, 'value1' => 'overwritten']
        );
        $row = $this->save($behavior, $model, false, ['fieldList' => []]);
        $this->assertSame(5, $row['event_id']);
    }

    public function testEditCarryingNoEventIdStillLogged()
    {
        $behavior = $this->behavior();
        $model = $this->attributeModel(
            ['id' => 838, 'event_id' => 5, 'object_id' => 0, 'value1' => 'old', 'comment' => '', 'deleted' => 0],
            ['id' => 838, 'value1' => 'new']
        );
        $row = $this->save($behavior, $model, false, ['fieldList' => ['value1']]);
        $this->assertSame(5, $row['event_id']);
    }

    public function testCreateLoggedUnderItsOwnEvent()
    {
        $behavior = $this->behavior();
        $model = $this->attributeModel([], ['event_id' => 7, 'value1' => 'new']);
        $row = $this->save($behavior, $model, true, ['fieldList' => []]);
        $this->assertSame(7, $row['event_id']);
    }
}
