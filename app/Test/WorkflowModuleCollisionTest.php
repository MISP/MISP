<?php
/**
 * Workflow: a misp-modules service module can never replace a built-in workflow module.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB. The private loader of the service
 * modules runs for real through reflection, on a Workflow built without its constructor.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new stdClass();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}
if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static function __callStatic($name, $args)
        {
        }
    }
}
if (!class_exists('Inflector', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Inflector.php';
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}

require_once __DIR__ . '/../Model/Workflow.php';

class WorkflowModuleCollisionTest extends TestCase
{
    private function load(array $configs, array $reservedIDs = [])
    {
        $workflow = (new ReflectionClass('Workflow'))->newInstanceWithoutConstructor();
        $method = new ReflectionMethod('Workflow', '__getClassForMispModule');
        $method->setAccessible(true);
        return $method->invoke($workflow, $configs, $reservedIDs);
    }

    private function config($name)
    {
        return ['name' => $name, 'meta' => ['description' => 'service module']];
    }

    public function testServiceModuleDoesNotReplaceBuiltInWithSameId()
    {
        $classes = $this->load([$this->config('webhook'), $this->config('other')], ['webhook', 'distribution-if']);
        $this->assertSame(['other'], array_keys($classes));
    }

    public function testCollisionIsDetectedOnTheUnderscoredId()
    {
        $classes = $this->load([$this->config('PushEvent')], ['push_event']);
        $this->assertSame([], $classes);
    }

    public function testNonCollidingServiceModulesAreKept()
    {
        $classes = $this->load([$this->config('first'), $this->config('second')], ['webhook']);
        $this->assertSame(['first', 'second'], array_keys($classes));
    }

    public function testNoServiceModuleYieldsAnArray()
    {
        $this->assertSame([], $this->load([]));
    }
}
