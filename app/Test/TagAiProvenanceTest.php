<?php
/**
 * Tag::captureAiProvenanceTags() (AI integration round 2, P1.3): the two
 * ai-computer-assisted tags the AI module puts on everything it produces
 * are guaranteed to exist before an AI write, whatever the state of the
 * taxonomy and whoever asks.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention). The
 * real captureTag() runs against an in-memory tag table; the Taxonomy model
 * is a fake registered in the shared ClassRegistry stub.
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

        public static function import($type = null, $name = null, $parent = true)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}
if (!class_exists('Configure', false)) {
    // captureTag() reads MISP.incoming_tags_disabled_by_default when it creates a tag.
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
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                throw new RuntimeException("No fake registered for $name.");
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

require_once __DIR__ . '/../Model/Module.php';
require_once __DIR__ . '/../Model/Tag.php';

/**
 * The tags table in memory: rows keyed by id, the finds captureTag() and
 * the helper issue, create()/save() as the real quickAdd()/captureTag() use them.
 */
class ProvenanceTestTag extends Tag
{
    public $rows = array();

    // Tag::nameCondition() spells the lookup for the engine; the in-memory
    // table compares the way MySQL's collation does. On the subclass rather
    // than the AppModel stand-in, since another test file may have declared
    // that first.
    protected function isMysql()
    {
        return true;
    }
    public $nextId = 1;
    public $id = null;
    public $saved = array();

    public function addRow($name, $colour = '#123456', $orgId = 0, $userId = 0)
    {
        $id = $this->nextId++;
        $this->rows[$id] = array('id' => $id, 'name' => $name, 'colour' => $colour, 'org_id' => $orgId, 'user_id' => $userId);
        return $id;
    }

    public function find($type, $query = array())
    {
        $conditions = $query['conditions'];
        if ($type === 'list') {
            // captureAiProvenanceTags(): find('list') by Tag.name IN (...),
            // which the column's collation compares case-insensitively.
            $wanted = array_map('mb_strtolower', $conditions['Tag.name']);
            $list = array();
            foreach ($this->rows as $row) {
                if (in_array(mb_strtolower($row['name']), $wanted, true)) {
                    $list[$row['name']] = $row['id'];
                }
            }
            return $list;
        }
        // captureTag(): find('first') by Tag.name, which the column's collation
        // compares case-insensitively.
        $wanted = mb_strtolower($conditions['Tag.name']);
        foreach ($this->rows as $row) {
            if (mb_strtolower($row['name']) === $wanted) {
                return array('Tag' => $row);
            }
        }
        return array();
    }

    public function create($data = null)
    {
        $this->id = null;
        return true;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $tag = isset($data['Tag']) ? $data['Tag'] : $data;
        $this->id = $this->addRow($tag['name'], $tag['colour'], isset($tag['org_id']) ? $tag['org_id'] : 0, isset($tag['user_id']) ? $tag['user_id'] : 0);
        $this->saved[] = $tag['name'];
        return true;
    }
}

/** Taxonomy::addTags() as the helper uses it: creates the listed names it knows, with the taxonomy colour. */
class ProvenanceFakeTaxonomy
{
    public $loaded = true;
    public $knownEntries;
    public $calls = array();
    /** @var ProvenanceTestTag */
    public $tag;

    public function __construct(ProvenanceTestTag $tag)
    {
        $this->tag = $tag;
        $this->knownEntries = Module::AI_PROVENANCE_TAGS;
    }

    public function addTags($id, $tagList = false)
    {
        $this->calls[] = array($id, $tagList);
        if (!$this->loaded) {
            return false;
        }
        foreach ($tagList as $name) {
            if (in_array($name, $this->knownEntries, true)) {
                $this->tag->quickAdd($name, '#taxo00');
            }
        }
        return true;
    }
}

class TagAiProvenanceTest extends TestCase
{
    const GENERATED = 'ai-computer-assisted:assistance-level="ai-generated"';
    const UNREVIEWED = 'ai-computer-assisted:review-level="unreviewed"';

    /** @var ProvenanceTestTag */
    private $tag;
    /** @var ProvenanceFakeTaxonomy */
    private $taxonomy;

    protected function setUp(): void
    {
        $this->tag = new ProvenanceTestTag();
        $this->taxonomy = new ProvenanceFakeTaxonomy($this->tag);
        ClassRegistry::$instances['Taxonomy'] = $this->taxonomy;
    }

    protected function tearDown(): void
    {
        unset(ClassRegistry::$instances['Taxonomy']);
    }

    private function analyst()
    {
        return array('id' => 42, 'org_id' => 3, 'Role' => array('perm_site_admin' => false, 'perm_tag_editor' => false));
    }

    private function colours()
    {
        $colours = array();
        foreach ($this->tag->rows as $row) {
            $colours[$row['name']] = $row['colour'];
        }
        return $colours;
    }

    public function testBothTagsAreCreatedThroughTheTaxonomyForAUserWithoutTagEditor()
    {
        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertSame(array(self::GENERATED, self::UNREVIEWED), array_keys($ids));
        $this->assertSame(array(1, 2), array_values($ids));
        $this->assertSame(array(array('ai-computer-assisted', array(self::GENERATED, self::UNREVIEWED))), $this->taxonomy->calls);
        $this->assertSame(array(self::GENERATED => '#taxo00', self::UNREVIEWED => '#taxo00'), $this->colours());
    }

    public function testWithoutTheTaxonomyTheTagsAreCreatedPlain()
    {
        $this->taxonomy->loaded = false;
        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertSame(array(1, 2), array_values($ids));
        $this->assertCount(2, $this->tag->rows);
        foreach ($this->tag->rows as $row) {
            $this->assertSame($this->tag->tagColor($row['name']), $row['colour']);
            $this->assertSame(0, $row['org_id']);
        }
    }

    public function testExistingTagsAreReturnedUntouched()
    {
        $generated = $this->tag->addRow(self::GENERATED, '#aaaaaa');
        $unreviewed = $this->tag->addRow(self::UNREVIEWED, '#bbbbbb');

        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertSame(array(self::GENERATED => $generated, self::UNREVIEWED => $unreviewed), $ids);
        $this->assertSame(array(), $this->taxonomy->calls);
        $this->assertSame(array(), $this->tag->saved);
        $this->assertSame(array(self::GENERATED => '#aaaaaa', self::UNREVIEWED => '#bbbbbb'), $this->colours());
    }

    public function testOnlyTheMissingNameIsAskedFromTheTaxonomy()
    {
        $generated = $this->tag->addRow(self::GENERATED);

        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertSame(array(array('ai-computer-assisted', array(self::UNREVIEWED))), $this->taxonomy->calls);
        $this->assertSame($generated, $ids[self::GENERATED]);
        $this->assertSame(2, $ids[self::UNREVIEWED]);
        $this->assertSame(array(self::UNREVIEWED), $this->tag->saved);
    }

    public function testAnEntryTheLoadedTaxonomyDoesNotKnowIsCreatedPlain()
    {
        $this->taxonomy->knownEntries = array(self::GENERATED);

        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertSame(array(1, 2), array_values($ids));
        $colours = $this->colours();
        $this->assertSame('#taxo00', $colours[self::GENERATED]);
        $this->assertSame($this->tag->tagColor(self::UNREVIEWED), $colours[self::UNREVIEWED]);
    }

    public function testATagReservedForAnotherOrganisationIsReportedAsUnusable()
    {
        $this->tag->addRow(self::GENERATED, '#aaaaaa', 5);
        $unreviewed = $this->tag->addRow(self::UNREVIEWED);

        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertFalse($ids[self::GENERATED]);
        $this->assertSame($unreviewed, $ids[self::UNREVIEWED]);
        $this->assertSame(array(), $this->tag->saved);
    }

    public function testASiteAdminMayUseAReservedTag()
    {
        $generated = $this->tag->addRow(self::GENERATED, '#aaaaaa', 5);
        $this->tag->addRow(self::UNREVIEWED);
        $admin = array('id' => 1, 'org_id' => 1, 'Role' => array('perm_site_admin' => true, 'perm_tag_editor' => true));

        $ids = $this->tag->captureAiProvenanceTags($admin);

        $this->assertSame($generated, $ids[self::GENERATED]);
    }

    public function testMatchingIsCaseInsensitiveLikeCaptureTag()
    {
        $generated = $this->tag->addRow(strtoupper(self::GENERATED));
        $unreviewed = $this->tag->addRow(self::UNREVIEWED);

        $ids = $this->tag->captureAiProvenanceTags($this->analyst());

        $this->assertSame(array(self::GENERATED => $generated, self::UNREVIEWED => $unreviewed), $ids);
        $this->assertSame(array(), $this->taxonomy->calls);
    }
}
