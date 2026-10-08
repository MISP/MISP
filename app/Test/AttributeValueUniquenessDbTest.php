<?php
/**
 * Duplicate detection on value ids against the configured MySQL/MariaDB
 * database: a value is a duplicate only when its bytes are identical, so
 * case and accent variants are distinct attributes.
 *
 * Every test runs in a transaction that is rolled back, which still spends
 * auto-increment ids. Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it
 * boots the real application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueUniquenessDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueUniquenessDbTest extends TestCase
{
    const DUPLICATE = 'A similar attribute already exists for this event.';

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var array */
    private $event;

    /** @var array */
    private $validate;

    protected function setUp(): void
    {
        if (!getenv('ATTRIBUTE_VALUE_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/OracleBootstrap.php';
            App::uses('ClassRegistry', 'Utility');
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        // captureAttribute() with breakOnDuplicate off drops the rule for good
        $this->validate = $this->attribute->validate;
        $this->db->begin();
        $this->token = 'avunique' . bin2hex(random_bytes(4));
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
        ])['Event'];
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
        if ($this->attribute) {
            $this->attribute->validate = $this->validate;
        }
    }

    /**
     * @return array|false The saved row, or false with the errors in validationErrors
     */
    private function save($type, $value, array $fields = [])
    {
        $this->attribute->create();
        return $this->attribute->save(['Attribute' => $fields + [
            'event_id' => $this->event['id'],
            'type' => $type,
            'category' => $this->attribute->typeDefinitions[$type]['default_category'],
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
        ]]);
    }

    private function create($type, $value, array $fields = [])
    {
        $saved = $this->save($type, $value, $fields);
        $this->assertNotFalse($saved, json_encode($this->attribute->validationErrors));
        return (int)$this->attribute->id;
    }

    private function assertDuplicate($saved)
    {
        $this->assertFalse($saved);
        $this->assertSame([self::DUPLICATE], $this->attribute->validationErrors['value'] ?? null);
    }

    private function rowCount($where)
    {
        $statement = $this->db->rawQuery(sprintf(
            'SELECT COUNT(*) FROM attributes WHERE event_id = %d AND %s',
            $this->event['id'],
            $where
        ));
        $count = (int)$statement->fetchColumn();
        $statement->closeCursor();
        return $count;
    }

    private function dictionaryHas($value)
    {
        $hash = bin2hex($this->attribute->loadAttributeValue()->hashOf($value));
        $statement = $this->db->rawQuery("SELECT COUNT(*) FROM attribute_values WHERE hash = X'$hash'");
        $count = (int)$statement->fetchColumn();
        $statement->closeCursor();
        return $count > 0;
    }

    private function user()
    {
        return ClassRegistry::init('User')->getAuthUser(1);
    }

    public function testAByteIdenticalValueIsADuplicate()
    {
        $value = "Valué {$this->token}";
        $this->create('text', $value);

        $this->assertDuplicate($this->save('text', $value));
        $this->assertSame(1, $this->rowCount("comment = '' AND value1 LIKE '%{$this->token}'"));
    }

    public function testCaseAndAccentVariantsAreNotDuplicates()
    {
        $this->create('text', "Valué {$this->token}");
        // One variant the dictionary already holds for some other attribute, one it has never seen
        $this->attribute->loadAttributeValue()->internMany(["valué {$this->token}"]);

        $this->create('text', "valué {$this->token}");
        $this->create('text', "Value {$this->token}");
        $this->assertSame(3, $this->rowCount("value1 LIKE '%{$this->token}'"));
    }

    public function testACompositeComparesBothParts()
    {
        $key = "HKLM\\Software\\{$this->token}";
        $this->create('regkey|value', "$key|Data");

        $this->create('regkey|value', "$key|data");
        $this->create('regkey|value', "$key|Other");
        $this->assertDuplicate($this->save('regkey|value', "$key|Data"));
    }

    public function testAnEmptySecondPartMatchesOnlyAnEmptySecondPart()
    {
        $key = "HKLM\\Software\\{$this->token}";
        $this->create('regkey|value', "$key|0");

        $this->create('regkey|value', "$key|");
        $this->assertDuplicate($this->save('regkey|value', "$key|"));
    }

    public function testDeletedAndObjectAttributesDoNotCount()
    {
        $deleted = $this->create('text', "deleted {$this->token}");
        $inObject = $this->create('text', "object {$this->token}");
        $this->db->rawQuery("UPDATE attributes SET deleted = 1 WHERE id = $deleted");
        $this->db->rawQuery("UPDATE attributes SET object_id = 1, object_relation = 'text' WHERE id = $inObject");

        $this->create('text', "deleted {$this->token}");
        $this->create('text', "object {$this->token}");
    }

    public function testAnEditIsADuplicateOnlyOfAnotherAttribute()
    {
        $this->create('text', "first {$this->token}");
        $id = $this->create('text', "second {$this->token}");
        $row = [
            'id' => $id,
            'event_id' => $this->event['id'],
            'type' => 'text',
            'category' => 'Other',
            'value' => "second {$this->token}",
            'comment' => $this->token,
        ];

        $this->assertNotFalse($this->attribute->save(['Attribute' => $row]), json_encode($this->attribute->validationErrors));
        $this->assertDuplicate($this->attribute->save(['Attribute' => ['value' => "first {$this->token}"] + $row]));
    }

    public function testValidationAddsNothingToTheDictionary()
    {
        $value = "unseen {$this->token}";
        $this->attribute->create();
        $this->attribute->set(['Attribute' => [
            'event_id' => $this->event['id'],
            'type' => 'text',
            'category' => 'Other',
            'value' => $value,
            'distribution' => 5,
        ]]);

        $this->assertTrue($this->attribute->validates(), json_encode($this->attribute->validationErrors));
        $this->assertFalse($this->dictionaryHas($value));
    }

    public function testWithoutBreakOnDuplicateTheValueIsFoundAsItWillBeStored()
    {
        $domain = "upsert-{$this->token}.example.org";
        $id = $this->create('domain', $domain);
        $errors = [];

        $this->attribute->captureAttribute([
            'type' => 'domain',
            'category' => 'Network activity',
            'value' => ' ' . strtoupper($domain) . ' ',
            'comment' => $this->token,
        ], $this->event['id'], $this->user(), false, false, false, $errors, ['breakOnDuplicate' => false]);

        $this->assertEmpty($errors, json_encode($errors));
        $this->assertSame($id, (int)$this->attribute->id);
        $this->assertSame(1, $this->rowCount("value1 = '$domain'"));
        $this->assertSame(1, $this->rowCount("id = $id AND comment = '{$this->token}'"));
    }

    public function testWithoutBreakOnDuplicateACaseVariantIsANewAttribute()
    {
        $id = $this->create('text', "Upsert {$this->token}");
        $this->attribute->loadAttributeValue()->internMany(["upsert {$this->token}"]);
        $errors = [];

        $this->attribute->captureAttribute([
            'type' => 'text',
            'category' => 'Other',
            'value' => "upsert {$this->token}",
        ], $this->event['id'], $this->user(), false, false, false, $errors, ['breakOnDuplicate' => false]);

        $this->assertEmpty($errors, json_encode($errors));
        $this->assertNotSame($id, (int)$this->attribute->id);
        $this->assertSame(2, $this->rowCount("value1 LIKE '%{$this->token}'"));
    }
}
