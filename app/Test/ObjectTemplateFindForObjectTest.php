<?php
/**
 * ObjectTemplate::findForObject(): which template an object is saved under,
 * and that one an admin disabled is never used. The table is in memory.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

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
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

if (!defined('APP')) {
    define('APP', dirname(__DIR__) . '/');
}

require_once __DIR__ . '/../Model/ObjectTemplate.php';

/** Templates as rows, queried by the conditions findForObject() sends. */
class FindForObjectTemplates extends ObjectTemplate
{
    public $rows = array();

    public function __construct()
    {
    }

    private function matching(array $conditions)
    {
        return array_values(array_filter($this->rows, function ($row) use ($conditions) {
            foreach ($conditions as $field => $wanted) {
                if (!in_array($row[$field], (array)$wanted, false)) {
                    return false;
                }
            }
            return true;
        }));
    }

    public function hasAny($conditions = null)
    {
        return !empty($this->matching($conditions));
    }

    public function find($type = 'first', $query = array())
    {
        $rows = $this->matching($query['conditions']);
        $order = $query['order'] ?? array();
        usort($rows, function ($a, $b) use ($order) {
            foreach ($order as $clause) {
                list($field) = explode(' ', $clause);
                if ($a[$field] !== $b[$field]) {
                    return $b[$field] <=> $a[$field];
                }
            }
            return 0;
        });
        return empty($rows) ? array() : array('ObjectTemplate' => $rows[0]);
    }
}

class ObjectTemplateFindForObjectTest extends TestCase
{
    const DOMAIN_IP = '43b3b146-77eb-4931-b4cc-b66c60f28734';
    const FILE = '688c46fb-5edb-40a3-8273-1af7923e2215';

    /** @var FindForObjectTemplates */
    private $templates;

    protected function setUp(): void
    {
        $this->templates = new FindForObjectTemplates();
        $this->templates->rows = array(
            array('uuid' => self::DOMAIN_IP, 'version' => 9, 'name' => 'domain-ip', 'meta-category' => 'network', 'active' => 0),
            array('uuid' => self::DOMAIN_IP, 'version' => 11, 'name' => 'domain-ip', 'meta-category' => 'network', 'active' => 1),
            array('uuid' => self::FILE, 'version' => 24, 'name' => 'file', 'meta-category' => 'file', 'active' => 1),
        );
    }

    private function disable($uuid)
    {
        foreach ($this->templates->rows as $i => $row) {
            if ($row['uuid'] === $uuid) {
                $this->templates->rows[$i]['active'] = 0;
            }
        }
    }

    public function testAnEnabledTemplateHonoursAnOlderVersionPinned()
    {
        $disabled = null;
        $found = $this->templates->findForObject('domain-ip', self::DOMAIN_IP, 9, $disabled);

        $this->assertSame(9, $found['ObjectTemplate']['version']);
        $this->assertFalse($disabled);
    }

    public function testAnEnabledTemplateWithoutThatVersionTakesItsNewestActive()
    {
        $this->assertSame(11, $this->templates->findForObject('domain-ip', strtoupper(self::DOMAIN_IP), 4)['ObjectTemplate']['version']);
        $this->assertSame(11, $this->templates->findForObject('domain-ip', self::DOMAIN_IP)['ObjectTemplate']['version']);
    }

    public function testADisabledTemplateIsNotUsedAndSaysSo()
    {
        $this->disable(self::DOMAIN_IP);

        $disabled = null;
        $this->assertNull($this->templates->findForObject('domain-ip', self::DOMAIN_IP, 11, $disabled));
        $this->assertTrue($disabled);
        $this->assertNull($this->templates->findForObject('domain-ip', self::DOMAIN_IP, null, $disabled), 'nor its newest version');
        $this->assertTrue($disabled);
    }

    public function testAUuidThisInstanceDoesNotHoldFallsBackToTheName()
    {
        $disabled = null;
        $found = $this->templates->findForObject('file', '00000000-0000-4000-8000-000000000001', 3, $disabled);

        $this->assertSame(self::FILE, $found['ObjectTemplate']['uuid']);
        $this->assertFalse($disabled);
    }

    public function testANameAloneFindsTheNewestActiveTemplateOfThatName()
    {
        $this->assertSame(11, $this->templates->findForObject('domain-ip')['ObjectTemplate']['version']);
        $this->disable(self::DOMAIN_IP);
        $disabled = null;
        $this->assertNull($this->templates->findForObject('domain-ip', null, null, $disabled));
        $this->assertFalse($disabled, 'a name alone does not say the template is disabled');
    }
}
