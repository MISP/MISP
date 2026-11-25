<?php
/**
 * Event::handleModuleResult() unit tests.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no DB — the convention used by the
 * other tests under app/Test/ (see CollectionCaptureTest). handleModuleResult()
 * only reaches out to ClassRegistry::init('Warninglist') and ComplexTypeTool,
 * so the framework classes it touches are stubbed here before Event.php is
 * loaded, and the warninglist is a counting double.
 *
 * Regression covered: the TLD and security vendor domain lists used to be
 * fetched inside the loop over the module results (two warninglist fetches per
 * result carrying a freetext type), and the freetext post-processing re-walked
 * the whole accumulator, overwriting the comment of every previously processed
 * result with the comment of the one being handled.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

// -------- framework stubs (must exist BEFORE Event.php loads) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }
    }
}

// NB: ClassRegistry is also stubbed by CollectionCaptureTest and
// PewPewMapWidgetTest. All of them guard with class_exists() and keep the same
// contract — a public static $instances array that init() consults first — so a
// shared-process run works whichever file loads first. We only ever
// pre-register our own double into $instances.
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
    #[\AllowDynamicProperties]
    class AppModel
    {
        public $alias = 'Event';
        public $id = false;
        public $data = array();

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

/** Counts how often each of the two warninglist lists is fetched. */
class EventModuleResultFakeWarninglist
{
    public $tldFetches = 0;
    public $securityVendorDomainFetches = 0;

    public function fetchTLDLists()
    {
        $this->tldFetches++;
        return array('com', 'net');
    }

    public function fetchSecurityVendorDomains()
    {
        $this->securityVendorDomainFetches++;
        return array('virustotal.com');
    }
}

require_once __DIR__ . '/../Lib/Tools/ComplexTypeTool.php';

// Event.php carries a few pre-existing "optional parameter declared before
// required parameter" deprecations; they are not what this test is about.
$eventErrorReporting = error_reporting();
error_reporting($eventErrorReporting & ~E_DEPRECATED);
require_once __DIR__ . '/../Model/Event.php';
error_reporting($eventErrorReporting);

/**
 * $Warninglist is declared here so that handleModuleResult()'s assignment is
 * not a dynamic property on the stubbed AppModel above.
 */
class TestableEvent extends Event
{
    public $Warninglist;
}

class EventHandleModuleResultTest extends TestCase
{
    /** @var EventModuleResultFakeWarninglist */
    private $warninglist;

    protected function setUp(): void
    {
        $this->warninglist = new EventModuleResultFakeWarninglist();
        ClassRegistry::$instances['Warninglist'] = $this->warninglist;
    }

    protected function tearDown(): void
    {
        unset(ClassRegistry::$instances['Warninglist']);
    }

    /** Four module results, each with its own freetext value and comment. */
    private function freetextModuleResult()
    {
        $results = array();
        for ($i = 0; $i < 4; $i++) {
            $results[] = array(
                'types' => array('freetext'),
                'values' => array('1.2.3.' . $i),
                'comment' => 'comment' . $i
            );
        }
        return array('results' => $results);
    }

    public function testWarninglistListsAreFetchedOncePerCall()
    {
        $event = new TestableEvent();
        $event->handleModuleResult($this->freetextModuleResult(), 99);
        $this->assertSame(1, $this->warninglist->tldFetches);
        $this->assertSame(1, $this->warninglist->securityVendorDomainFetches);
    }

    public function testEveryFreetextResultKeepsItsOwnComment()
    {
        $event = new TestableEvent();
        $resultArray = $event->handleModuleResult($this->freetextModuleResult(), 99);
        $comments = array();
        foreach ($resultArray as $attribute) {
            $this->assertSame(99, $attribute['event_id']);
            $comments[$attribute['value']] = $attribute['comment'];
        }
        $this->assertSame(
            array(
                '1.2.3.0' => 'comment0',
                '1.2.3.1' => 'comment1',
                '1.2.3.2' => 'comment2',
                '1.2.3.3' => 'comment3'
            ),
            $comments
        );
    }

    public function testWarninglistIsNotFetchedWithoutFreetext()
    {
        $event = new TestableEvent();
        $event->handleModuleResult(
            array('results' => array(array('types' => array('ip-src'), 'values' => array('1.2.3.4')))),
            99
        );
        $this->assertSame(0, $this->warninglist->tldFetches);
        $this->assertSame(0, $this->warninglist->securityVendorDomainFetches);
    }
}
