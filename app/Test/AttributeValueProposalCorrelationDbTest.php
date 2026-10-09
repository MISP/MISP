<?php
/**
 * Proposals do not correlate: shadow_attribute_correlations is dropped by a
 * migration, deleting an event no longer names it, the event view treats every
 * proposal as uncorrelated, and the recorrelation action, job and command are
 * gone.
 *
 * The event-delete test creates its own event, attribute and proposal in a
 * transaction that is rolled back, then deletes what it created by id.
 * Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real
 * application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueProposalCorrelationDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueProposalCorrelationDbTest extends TestCase
{
    const TABLE = 'shadow_attribute_correlations';

    const MIGRATION = '20261009_083345_drop_shadow_attribute_correlations';

    private static $booted = false;

    /** @var Event */
    private $event;

    /** @var DboSource */
    private $db;

    /** @var string */
    private $token;

    /** @var int|null */
    private $eventId = null;

    /** @var bool */
    private $fullDebug;

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
            App::uses('CakeText', 'Utility');
            App::uses('AttributeValue', 'Model');
            App::uses('ACLComponent', 'Controller/Component');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        Configure::write('CurrentUserId', 1);
        $this->event = ClassRegistry::init('Event');
        $this->db = $this->event->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->fullDebug = $this->db->fullDebug;
        $this->token = 'avpc' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        if ($this->db) {
            $this->db->fullDebug = $this->fullDebug;
        }
    }

    private function exec($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!($statement instanceof PDOStatement)) {
            return [];
        }
        $rows = $statement->columnCount() > 0 ? $statement->fetchAll(PDO::FETCH_ASSOC) : [];
        $statement->closeCursor();
        return $rows;
    }

    public function testTheTableIsDropped()
    {
        $this->assertSame([], $this->exec("SHOW TABLES LIKE '" . self::TABLE . "'"));
        $status = $this->exec(sprintf(
            "SELECT status FROM schema_migrations WHERE migration_id = '%s'",
            self::MIGRATION
        ));
        $this->assertSame([['status' => 'applied']], $status);
    }

    public function testEventDeleteNamesNoProposalCorrelationTable()
    {
        $this->db->begin();
        try {
            $uuid = CakeText::uuid();
            $this->exec(sprintf(
                "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, distribution, sharing_group_id, threat_level_id) VALUES (1, 1, 1, CURDATE(), 'AV-505 fixture %s', '%s', 0, 0, 0, 4)",
                $this->token,
                $uuid
            ));
            $this->eventId = (int)$this->exec("SELECT id FROM events WHERE uuid = '$uuid'")[0]['id'];
            $attribute = ClassRegistry::init('MispAttribute');
            $attribute->create();
            $this->assertNotFalse($attribute->save(['Attribute' => [
                'event_id' => $this->eventId,
                'category' => 'Network activity',
                'type' => 'ip-dst',
                'value' => '198.51.100.7',
                'distribution' => 5,
                'to_ids' => 0,
                'comment' => $this->token,
            ]]), json_encode($attribute->validationErrors));
            $proposal = ClassRegistry::init('ShadowAttribute');
            $proposal->create();
            $this->assertNotFalse($proposal->save(['ShadowAttribute' => [
                'event_id' => $this->eventId,
                'event_uuid' => $uuid,
                'event_org_id' => 1,
                'org_id' => 1,
                'old_id' => 0,
                'type' => 'ip-dst',
                'category' => 'Network activity',
                'value' => '198.51.100.7',
                'comment' => $this->token,
            ]]), json_encode($proposal->validationErrors));

            $event = $this->event->find('first', [
                'recursive' => -1,
                'conditions' => ['Event.id' => $this->eventId],
            ]);
            $this->db->fullDebug = true;
            $this->db->getLog(false, true);
            $this->assertTrue((bool)$this->event->quickDelete($event));
            foreach ($this->db->getLog(false, false)['log'] as $query) {
                $this->assertStringNotContainsString(self::TABLE, $query['query']);
            }
            $this->db->fullDebug = $this->fullDebug;
            foreach (['events' => 'id', 'attributes' => 'event_id', 'shadow_attributes' => 'event_id'] as $table => $key) {
                $left = $this->exec("SELECT COUNT(*) AS n FROM $table WHERE $key = {$this->eventId}");
                $this->assertSame('0', (string)$left[0]['n'], $table);
            }
        } finally {
            try {
                $this->db->rollback();
            } finally {
                $this->deleteFixture();
            }
        }
    }

    private function deleteFixture()
    {
        if ($this->eventId !== null) {
            $this->exec("DELETE FROM shadow_attributes WHERE event_id = {$this->eventId}");
            $this->exec("DELETE FROM attributes WHERE event_id = {$this->eventId}");
            $this->exec("DELETE FROM events WHERE id = {$this->eventId}");
        }
    }

    /**
     * An event as the view receives it: an attribute that correlates and one
     * that does not, each with proposals, two event-level proposals and two
     * objects whose attributes carry proposals, one of them correlating.
     */
    private function viewEvent()
    {
        $proposal = function ($id, $toDelete = 0) {
            return ['id' => $id, 'uuid' => CakeText::uuid(), 'type' => 'ip-dst', 'category' => 'Network activity',
                'value' => "p$id", 'proposal_to_delete' => $toDelete, 'comment' => '', 'old_id' => 0];
        };
        $attribute = function ($id, $type, $proposals = []) {
            $a = ['id' => $id, 'uuid' => CakeText::uuid(), 'type' => $type, 'category' => 'Network activity',
                'value' => "v$id", 'to_ids' => 0, 'deleted' => 0, 'comment' => '', 'object_id' => 0, 'distribution' => 5];
            if ($proposals) {
                $a['ShadowAttribute'] = $proposals;
            }
            return $a;
        };
        return [
            'Event' => ['id' => 4242, 'uuid' => CakeText::uuid(), 'info' => $this->token],
            'Attribute' => [
                $attribute(1, 'ip-dst', [$proposal(11), $proposal(12, 1)]),
                $attribute(2, 'domain', [$proposal(21)]),
            ],
            'ShadowAttribute' => [$proposal(31), $proposal(32, 1)],
            'Object' => [
                ['id' => 70, 'uuid' => CakeText::uuid(), 'name' => 'domain-ip', 'meta-category' => 'network',
                    'Attribute' => [$attribute(71, 'ip-dst', [$proposal(72)])]],
                ['id' => 80, 'uuid' => CakeText::uuid(), 'name' => 'domain-ip', 'meta-category' => 'network',
                    'Attribute' => [$attribute(81, 'ip-dst', [$proposal(82)])]],
            ],
            'RelatedAttribute' => [
                1 => [['id' => 501, 'attribute_id' => 600, 'value' => 'v1']],
                81 => [['id' => 501, 'attribute_id' => 601, 'value' => 'v81']],
            ],
        ];
    }

    /**
     * @return string[] objectType:id, followed by the ids of the proposals kept on it
     */
    private function view(array $args)
    {
        $event = $this->viewEvent();
        $this->event->rearrangeEventForView($event, $args, true);
        $kept = [];
        foreach ($event['objects'] as $object) {
            $line = $object['objectType'] . ':' . $object['id'];
            foreach (isset($object['ShadowAttribute']) ? $object['ShadowAttribute'] : [] as $proposal) {
                $line .= ' p' . $proposal['id'];
            }
            foreach (isset($object['Attribute']) ? $object['Attribute'] : [] as $attribute) {
                $nested = isset($attribute['ShadowAttribute']) ? $attribute['ShadowAttribute'] : [];
                $line .= ' a' . $attribute['id'] . '[' . implode(',', array_column($nested, 'id')) . ']';
            }
            $kept[] = $line;
        }
        sort($kept);
        return $kept;
    }

    public function testProposalsAreUncorrelatedInTheEventView()
    {
        $this->assertSame(
            ['attribute:1 p11 p12', 'attribute:2 p21', 'object:70 a71[72]', 'object:80 a81[82]', 'proposal:31', 'proposal_delete:32'],
            $this->view([])
        );
        // Correlating only: no proposal, not even on a correlating attribute
        $this->assertSame(['attribute:1', 'object:80 a81[82]'], $this->view(['correlation' => 1]));
        $this->assertSame(['attribute:1', 'object:80 a81[82]'], $this->view(['attributeFilter' => 'correlation']));
        // Not correlating: every proposal stays
        $this->assertSame(
            ['attribute:2 p21', 'object:70 a71[72]', 'proposal:31', 'proposal_delete:32'],
            $this->view(['correlation' => 2])
        );
        // Correlating with a given event: no proposal
        $this->assertSame(['attribute:1', 'object:80 a81[82]'], $this->view(['correlationId' => 501]));
        $this->assertSame([], $this->view(['correlationId' => 999]));
        $this->assertSame(
            ['attribute:1 p11 p12', 'attribute:2 p21', 'object:70 a71[72]', 'object:80 a81[82]', 'proposal:31', 'proposal_delete:32'],
            $this->view(['attributeFilter' => 'proposal'])
        );
    }

    public function testTheRecorrelationEntryPointsAreGone()
    {
        App::uses('AppController', 'Controller');
        App::uses('ShadowAttributesController', 'Controller');
        App::uses('Shell', 'Console');
        App::uses('AppShell', 'Console/Command');
        App::uses('AdminShell', 'Console/Command');
        $this->assertFalse(method_exists('ShadowAttribute', 'generateCorrelation'));
        $this->assertFalse(method_exists('ShadowAttribute', 'upgradeToProposalCorrelation'));
        $this->assertFalse(method_exists('ShadowAttributesController', 'generateCorrelation'));
        $this->assertArrayNotHasKey('generateCorrelation', ACLComponent::ACL_LIST['shadowAttributes']);
        $this->assertArrayHasKey('generateCorrelation', ACLComponent::ACL_LIST['attributes']);
        $this->assertFalse(method_exists('AdminShell', 'jobGenerateShadowAttributeCorrelation'));
        $commands = ClassRegistry::init('Server')->command_line_functions['console_admin_tasks']['data'];
        $this->assertArrayNotHasKey('Generate shadow attribute correlation', $commands);
        $this->assertArrayHasKey('Generate correlation', $commands);
    }
}
