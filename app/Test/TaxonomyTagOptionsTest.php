<?php
/**
 * Taxonomy::getAllTaxonomyTags() options array contract.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by every
 * other test under app/Test/ (see CollectionCaptureTest). The framework
 * dependencies the method touches are stubbed here when no earlier test file
 * has already defined them, then the real Taxonomy.php is loaded and driven
 * through a TestableTaxonomy subclass that records the query the Tag model is
 * handed. That is enough to pin the contract, because every parameter of
 * getAllTaxonomyTags() ends up either in those conditions or in the choice
 * between find('all') and find('list').
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE Taxonomy.php loads) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
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

        public static function reset()
        {
            self::$values = array();
        }
    }
}

if (!class_exists('TaxonomyTestFakeModel', false)) {
    class TaxonomyTestFakeModel
    {
        /** @var array the find() calls this model received */
        public $calls = array();

        public function find($type, $options = array())
        {
            $this->calls[] = array(
                'type' => $type,
                'conditions' => $options['conditions']
            );
            if ($type === 'all') {
                return array(
                    array('Tag' => array(
                        'id' => 1,
                        'name' => 'custom:tag',
                        'colour' => '#ffffff'
                    ))
                );
            }
            return array(1 => 'custom:tag');
        }
    }
}

// NB: ClassRegistry is stubbed by several other test files as well. They all
// expose ClassRegistry::$instances and auto-create a double for an unknown
// name, so we keep the same contract and pre-register our Tag double in
// setUp() - that way this test works whichever file's stub wins in a
// shared-process run.
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new TaxonomyTestFakeModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $alias = 'Taxonomy';
        public $id = false;

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

require_once __DIR__ . '/../Model/Taxonomy.php';

use PHPUnit\Framework\TestCase;

/**
 * Taxonomy with the taxonomy lookup stubbed out - a single namespace holding a
 * single predicate, so 'custom:tag' is never a taxonomy tag: it survives the
 * inverse filter and is dropped by the non-inverse one.
 */
class TestableTaxonomy extends Taxonomy
{
    public $Tag;

    public function __construct()
    {
    }

    public function find($type, $query = array())
    {
        return array(
            array(
                'Taxonomy' => array('namespace' => 'tlp'),
                'TaxonomyPredicate' => array(
                    array('value' => 'red', 'TaxonomyEntry' => array())
                )
            )
        );
    }
}

class TaxonomyTagOptionsTest extends TestCase
{
    /** @var TaxonomyTestFakeModel */
    private $tag;

    public function setUp(): void
    {
        $this->tag = new TaxonomyTestFakeModel();
        ClassRegistry::$instances['Tag'] = $this->tag;
    }

    public function tearDown(): void
    {
        unset(ClassRegistry::$instances['Tag']);
    }

    /**
     * Calls getAllTaxonomyTags() with the given arguments and returns both the
     * query the Tag model saw and the rows that came back.
     *
     * @param array $args
     * @return array
     */
    private function callWith(array $args)
    {
        $this->tag->calls = array();
        $taxonomy = new TestableTaxonomy();
        $result = call_user_func_array(
            array($taxonomy, 'getAllTaxonomyTags'),
            $args
        );
        return array($this->tag->calls[0], $result);
    }

    /**
     * The positional argument list each call site used, paired with the
     * options array that replaces it.
     *
     * @return array
     */
    public function callSiteCombinations()
    {
        $user = array(
            'id' => 7,
            'org_id' => 3,
            'Role' => array('perm_site_admin' => 0)
        );
        return array(
            // Taxonomy::normalizeCustomTagsToTaxonomyFormat()
            array(
                array(false, false, true, false, true),
                array(array(
                    'full' => true,
                    'hideUnselectable' => false,
                    'local_tag' => true
                ))
            ),
            // Tag::getCustomTagsForPicker(), AttributesController::tags()
            array(
                array(true, $user, true, true, false),
                array(array('inverse' => true, 'user' => $user, 'full' => true))
            ),
            // TagsController::selectTaxonomy(), local_tag from the request
            array(
                array(true, $user, true, true, true),
                array(array(
                    'inverse' => true,
                    'user' => $user,
                    'full' => true,
                    'local_tag' => true
                ))
            ),
            // RestResponseComponent::__overwriteTags()
            array(array(), array(array()))
        );
    }

    /**
     * @dataProvider callSiteCombinations
     */
    public function testOptionsArrayIsEquivalentToThePositionalArguments(
        array $positional,
        array $options
    ) {
        list($positionalQuery, $positionalRows) = $this->callWith($positional);
        list($optionsQuery, $optionsRows) = $this->callWith($options);
        $this->assertSame($positionalQuery, $optionsQuery);
        $this->assertSame($positionalRows, $optionsRows);
    }

    public function testOptionsArrayKeepsTheHideUnselectableDefault()
    {
        list($query, ) = $this->callWith(
            array(array('inverse' => true, 'full' => true))
        );
        $this->assertSame('all', $query['type']);
        $this->assertSame(0, $query['conditions']['Tag.hide_tag']);
        $this->assertSame(0, $query['conditions']['Tag.local_only']);
    }

    public function testOptionsArraySelectsTheFullReturnShape()
    {
        list($query, $result) = $this->callWith(
            array(array('inverse' => true, 'full' => true))
        );
        $this->assertSame('all', $query['type']);
        $this->assertSame('custom:tag', $result[0]['Tag']['name']);
    }

    public function testPositionalArgumentsStillSelectTheListReturnShape()
    {
        list($query, $result) = $this->callWith(array(true));
        $this->assertSame('list', $query['type']);
        $this->assertSame(array(1 => 'custom:tag'), $result);
    }

    public function testNonInverseDropsTagsWithoutATaxonomy()
    {
        list(, $result) = $this->callWith(
            array(array('inverse' => false, 'full' => true))
        );
        $this->assertSame(array(), $result);
    }
}
