<?php
/**
 * Value::observedFrom()/observedAt(): the date chain every *when*
 * aggregate reads, with and without an attribute creation column.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database. The framework
 * classes the model touches are stubbed, each guarded so that a full-suite
 * run sharing one process keeps whichever stub loaded first.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            return self::$instances[$name];
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

require_once __DIR__ . '/../Model/Value.php';

use PHPUnit\Framework\TestCase;

/** An attribute model whose schema holds one optional creation column. */
class ObservedChainFakeAttribute
{
    public $alias = 'Attribute';
    public $schemaCalls = 0;
    private $type;

    public function __construct($type)
    {
        $this->type = $type;
    }

    public function schema($field = false)
    {
        $this->schemaCalls++;
        if ($field !== 'creation_datetime' || $this->type === null) {
            return null;
        }
        return array('type' => $this->type, 'null' => true);
    }
}

class ValueObservedChainTest extends TestCase
{
    /** The chains as they read before the creation column existed. */
    const LEGACY_AT = 'COALESCE('
        . 'FLOOR(Attribute.last_seen / 1000000),'
        . ' FLOOR(Attribute.first_seen / 1000000),'
        . ' Attribute.timestamp)';

    const LEGACY_FROM = 'COALESCE('
        . 'FLOOR(Attribute.first_seen / 1000000),'
        . ' FLOOR(Attribute.last_seen / 1000000),'
        . ' Attribute.timestamp)';

    private function valueWith($type, &$fake = null)
    {
        $fake = new ObservedChainFakeAttribute($type);
        ClassRegistry::$instances['MispAttribute'] = $fake;
        return new Value();
    }

    protected function tearDown(): void
    {
        unset(ClassRegistry::$instances['MispAttribute']);
    }

    public function testWithoutTheColumnTheChainsAreUnchanged()
    {
        $value = $this->valueWith(null);
        $this->assertSame(self::LEGACY_FROM, $value->observedFrom());
        $this->assertSame(self::LEGACY_AT, $value->observedAt());
    }

    public function creationTypes()
    {
        return array(
            'datetime' => array(
                'datetime',
                'UNIX_TIMESTAMP(Attribute.creation_datetime)',
            ),
            'timestamp' => array(
                'timestamp',
                'UNIX_TIMESTAMP(Attribute.creation_datetime)',
            ),
            'microseconds' => array(
                'biginteger',
                'FLOOR(Attribute.creation_datetime / 1000000)',
            ),
            'seconds' => array(
                'integer',
                'Attribute.creation_datetime',
            ),
        );
    }

    /**
     * @dataProvider creationTypes
     */
    public function testTheColumnSitsBetweenTheSeenDatesAndTheRowWrite(
        $type,
        $expression
    ) {
        $value = $this->valueWith($type);
        $this->assertSame(
            'COALESCE(FLOOR(Attribute.first_seen / 1000000),'
                . ' FLOOR(Attribute.last_seen / 1000000), '
                . $expression . ', Attribute.timestamp)',
            $value->observedFrom()
        );
        $this->assertSame(
            'COALESCE(FLOOR(Attribute.last_seen / 1000000),'
                . ' FLOOR(Attribute.first_seen / 1000000), '
                . $expression . ', Attribute.timestamp)',
            $value->observedAt()
        );
    }

    public function testTheSchemaIsAskedOnce()
    {
        $value = $this->valueWith('datetime', $fake);
        $value->observedFrom();
        $value->observedAt();
        $value->observedFrom();
        $this->assertSame(1, $fake->schemaCalls);
    }
}
