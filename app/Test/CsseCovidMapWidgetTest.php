<?php
/**
 * CsseCovidMapWidget country-code regression test.
 *
 * Pure PHPUnit per the MISP test convention (no CakePHP bootstrap, no
 * DB): the framework classes the widget touches are stubbed here
 * before it is loaded, and the Event model is a hand-rolled double
 * pre-registered into the ClassRegistry stub.
 *
 * The widget used to carry its own copy of the country-name to ISO
 * code mapping, which had drifted away from
 * WidgetToolkit::getCountryCodeMapping(). These tests pin the widget
 * to the toolkit so the two cannot diverge again.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

// ---- Framework class stubs --------------------------------------

if (!class_exists('App')) {
    class App
    {
        public static function uses($class = null, $package = null)
        {
            // no-op: WidgetToolkit is required directly below.
        }
    }
}

// NB: Inflector is also stubbed by WidgetCacheTest, which only needs
// underscore(). Both files guard with class_exists(), so in a
// full-suite run whichever loads first wins for everyone - both
// methods are therefore provided here.
if (!class_exists('Inflector')) {
    class Inflector
    {
        public static function humanize($string)
        {
            return ucwords(str_replace('_', ' ', $string));
        }

        public static function underscore($string)
        {
            $string = preg_replace('/([a-z\d])([A-Z])/', '$1_$2', $string);
            $string = preg_replace(
                '/([A-Z]+)([A-Z][a-z])/',
                '$1_$2',
                $string
            );
            return strtolower($string);
        }
    }
}

// NB: ClassRegistry is also stubbed by PewPewMapWidgetTest and the
// Collection* tests. We keep the SAME contract they rely on - init()
// auto-creates a find()/responses fake for any unregistered name - and
// pre-register our Event double into $instances before init() is
// reached.
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new CsseCovidFakeModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('CsseCovidFakeModel', false)) {
    class CsseCovidFakeModel
    {
        public $responses = array();

        public function find($type, $opts = array())
        {
            if (empty($this->responses)) {
                return array();
            }
            return array_shift($this->responses);
        }
    }
}

/**
 * Event double: the widget only calls filterEventIds() and
 * fetchEvent() on it.
 */
class CsseCovidFakeEvent
{
    /** @var array the single event fetchEvent() hands back */
    public $event = array('Object' => array());

    public function filterEventIds($user, $params)
    {
        return array(1);
    }

    public function fetchEvent($user, $params)
    {
        return array($this->event);
    }
}

require_once __DIR__ . '/../Lib/Dashboard/Tools/WidgetToolkit.php';
require_once __DIR__ . '/../Lib/Dashboard/CsseCovidMapWidget.php';

class CsseCovidMapWidgetTest extends TestCase
{
    /** @var CsseCovidFakeEvent */
    private $event;

    /** @var CsseCovidMapWidget */
    private $w;

    protected function setUp(): void
    {
        $this->event = new CsseCovidFakeEvent();
        ClassRegistry::$instances = array();
        ClassRegistry::$instances['Event'] = $this->event;
        $this->w = new CsseCovidMapWidget();
    }

    /**
     * Helper: run the widget over one covid19-csse-daily-report object
     * per ['country-region' => confirmed] pair, return the map data.
     */
    private function handle($countries)
    {
        $objects = array();
        foreach ($countries as $country => $confirmed) {
            $objects[] = array(
                'name' => 'covid19-csse-daily-report',
                'Attribute' => array(
                    array(
                        'object_relation' => 'country-region',
                        'value' => $country
                    ),
                    array(
                        'object_relation' => 'confirmed',
                        'value' => (string)$confirmed
                    )
                )
            );
        }
        $this->event->event = array('Object' => $objects);
        $out = $this->w->handler(array('Role' => array()), array());
        return $out['data'];
    }

    public function testCountryCodesComeFromTheWidgetToolkit(): void
    {
        $this->handle(array('France' => 1));
        $toolkit = new WidgetToolkit();
        $this->assertSame(
            $toolkit->getCountryCodeMapping(),
            $this->w->countryCodes
        );
    }

    public function testCountriesOnlyKnownToTheToolkitResolve(): void
    {
        // Malta, Czech Republic, Russian Federation and Ireland
        // {Republic} were absent from the widget's own copy, so they
        // all collapsed into a single 'XX' bucket.
        $data = $this->handle(array(
            'Malta' => 5,
            'Czech Republic' => 7,
            'Russian Federation' => 9,
            'Ireland {Republic}' => 13
        ));
        $this->assertArrayNotHasKey('XX', $data);
        $this->assertSame(5, $data['MT']);
        $this->assertSame(7, $data['CZ']);
        $this->assertSame(9, $data['RU']);
        $this->assertSame(13, $data['IE']);
    }

    public function testCsseSpecificCountryNamesStillResolve(): void
    {
        $data = $this->handle(array(
            'Mainland China' => 11,
            'Czech Rep.' => 2,
            'Korea' => 3
        ));
        $this->assertSame(11, $data['CN']);
        $this->assertSame(2, $data['CZ']);
        $this->assertSame(3, $data['KR']);
    }

    public function testAnIsoCodeValueIsPassedThrough(): void
    {
        $data = $this->handle(array('FR' => 4));
        $this->assertSame(4, $data['FR']);
    }

    public function testAnUnknownCountryFallsBackToXx(): void
    {
        $data = $this->handle(array('Atlantis' => 6));
        $this->assertSame(6, $data['XX']);
    }
}
