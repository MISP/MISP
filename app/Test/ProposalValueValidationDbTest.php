<?php
/**
 * Proposals validate their value with the attribute rules: the same input
 * gets the same verdict from both models, against the configured MySQL/MariaDB
 * database.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/ProposalValueValidationDbTest.php
 */

use PHPUnit\Framework\TestCase;

class ProposalValueValidationDbTest extends TestCase
{
    const CONTROL = 'Value provided consists purely of control characters and is therefore considered to be empty.';
    const COMPOSITE = 'Composite type found but the value not in the composite (value1|value2) format.';
    const LENGTH = 'The entered string is too long and would get truncated. Please consider adding the data as an attachment instead';

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var ShadowAttribute */
    private $proposal;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $event;

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
            App::uses('AttributeValue', 'Model');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->proposal = ClassRegistry::init('ShadowAttribute');
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->event = $this->attribute->Event->find('first', [
            'recursive' => -1,
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id'],
        ])['Event'];
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->rollback();
        }
    }

    private function proposalRow($type, $value)
    {
        return [
            'event_id' => $this->event['id'],
            'event_uuid' => $this->event['uuid'],
            'event_org_id' => $this->event['orgc_id'],
            'org_id' => $this->event['orgc_id'],
            'old_id' => 0,
            'type' => $type,
            'category' => $this->attribute->typeDefinitions[$type]['default_category'],
            'value' => $value,
        ];
    }

    private function valueErrors(AppModel $model, array $row)
    {
        $model->create();
        $model->set([$model->alias => $row]);
        $model->validates();
        return $model->validationErrors['value'] ?? [];
    }

    public function values()
    {
        $token = 'avproposal' . bin2hex(random_bytes(4));
        return [
            'plain' => ['domain', "$token.example.org", []],
            'composite' => ['ip-dst|port', '198.51.100.7|8080', []],
            'composite without a pipe' => ['ip-dst|port', '198.51.100.7', [self::COMPOSITE]],
            'composite with two pipes' => ['filename|md5', "$token.exe|a|d41d8cd98f00b204e9800998ecf8427e", [self::COMPOSITE]],
            'control characters' => ['text', "\x01\x02", [self::CONTROL]],
            'composite with a control-only part' => ['filename|md5', "\x01|d41d8cd98f00b204e9800998ecf8427e", [self::CONTROL]],
            'at the length limit' => ['text', $token . str_repeat('A', 65535 - strlen($token)), []],
            'over the length limit' => ['text', $token . str_repeat('A', 65536 - strlen($token)), [self::LENGTH]],
        ];
    }

    /**
     * @dataProvider values
     */
    public function testTheProposalAndTheAttributeAgree($type, $value, array $expected)
    {
        $attribute = $this->valueErrors($this->attribute, [
            'event_id' => $this->event['id'],
            'type' => $type,
            'category' => $this->attribute->typeDefinitions[$type]['default_category'],
            'value' => $value,
            'distribution' => 5,
            'to_ids' => 0,
        ]);
        $proposal = $this->valueErrors($this->proposal, $this->proposalRow($type, $value));

        $this->assertSame($expected, $attribute);
        $this->assertSame($attribute, $proposal);
    }

    public function testAnOverLongProposalIsRefusedWithoutAnException()
    {
        $this->proposal->create();
        $saved = $this->proposal->save(['ShadowAttribute' => $this->proposalRow('text', str_repeat('A', 70000))]);

        $this->assertFalse($saved);
        $this->assertSame([self::LENGTH], $this->proposal->validationErrors['value']);
        $this->assertSame([], $this->proposal->whitelist);
    }

    public function testAnUnsplittableCompositeProposalIsRefusedWithoutAnException()
    {
        $this->proposal->create();
        $saved = $this->proposal->save(['ShadowAttribute' => $this->proposalRow('ip-dst|port', '198.51.100.7')]);

        $this->assertFalse($saved);
        $this->assertSame([self::COMPOSITE], $this->proposal->validationErrors['value']);
    }
}
