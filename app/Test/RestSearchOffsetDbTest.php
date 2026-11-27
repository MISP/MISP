<?php
/**
 * restSearch's offset filter: the check the controller runs once the role's
 * limit is in (RestSearchComponent::offset), and the chunked models (event
 * reports, analyst data, collections, tags, organisations), which start a page
 * at the offset, let page win over it, and page as before without it.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * RESTSEARCH_OFFSET_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     RESTSEARCH_OFFSET_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/RestSearchOffsetDbTest.php
 */

use PHPUnit\Framework\TestCase;

class RestSearchOffsetDbTest extends TestCase
{
    private static $booted = false;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $user;

    /** @var string */
    private $token;

    /** @var mixed */
    private $currentUserId;

    protected function setUp(): void
    {
        if (!getenv('RESTSEARCH_OFFSET_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/OracleBootstrap.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('CakeText', 'Utility');
            App::uses('ComponentCollection', 'Controller');
            App::uses('RestSearchComponent', 'Controller/Component');
            self::$booted = true;
        }
        $this->db = ClassRegistry::init('Tag')->getDataSource();
        if (!($this->db instanceof Mysql)) {
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->db->begin();
        $this->token = 'rsoff' . bin2hex(random_bytes(4));
        $this->user = ClassRegistry::init('User')->getAuthUser(1);
        // The analyst data behaviour reads the request's user from here
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->user['id']);
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
        $this->db->rollback();
    }

    /**
     * @return array [the offset returned, the filters as the model gets them]
     */
    private function check(array $filters, $scope = 'Tag', $returnFormat = 'json')
    {
        $component = new RestSearchComponent(new ComponentCollection());
        $offset = $component->offset($filters, $scope, $returnFormat);
        return [$offset, $filters];
    }

    private function assertRejected(array $filters, $message)
    {
        try {
            $this->check($filters);
            $this->fail('Accepted: ' . json_encode($filters));
        } catch (BadRequestException $e) {
            $this->assertSame($message, $e->getMessage(), json_encode($filters));
        }
    }

    public function testAnOffsetIsCastAndKeptForTheModel()
    {
        foreach ([[4, 4], ['4', 4], ['007', 7], [0, 0], ['0', 0]] as [$given, $expected]) {
            [$offset, $filters] = $this->check(['limit' => 3, 'offset' => $given]);
            $this->assertSame($expected, $offset);
            $this->assertSame(['limit' => 3, 'offset' => $expected], $filters);
        }
        foreach (RestSearchComponent::OFFSET_SCOPES as $scope) {
            $this->assertSame([4, ['limit' => '3', 'offset' => 4]], $this->check(['limit' => '3', 'offset' => '4'], $scope));
        }
    }

    public function testPageWinsOverAnyOffset()
    {
        foreach ([2, 0, '', '2'] as $page) {
            foreach ([4, 'abc', -1] as $given) {
                $this->assertSame([null, ['limit' => 3, 'page' => $page]], $this->check(['limit' => 3, 'page' => $page, 'offset' => $given]));
            }
        }
    }

    public function testAnythingButANonNegativeIntegerIsRejected()
    {
        foreach ([-1, '-1', 4.0, '4.0', '+4', '4abc', '1e3', '', true, false, [4]] as $given) {
            $this->assertRejected(['limit' => 3, 'offset' => $given], 'The offset must be a non-negative integer.');
        }
    }

    public function testAnOffsetNeedsALimit()
    {
        foreach ([[], ['limit' => 0], ['limit' => '0'], ['limit' => 'abc'], ['limit' => -3]] as $filters) {
            $this->assertRejected($filters + ['offset' => 4], 'The offset needs a limit.');
        }
    }

    public function testCountsAndScopesWithoutOffsetDropIt()
    {
        $this->assertSame([null, ['limit' => 3]], $this->check(['limit' => 3, 'offset' => 4], 'Tag', 'count'));
        $this->assertNotContains('Sighting', RestSearchComponent::OFFSET_SCOPES);
        $component = new RestSearchComponent(new ComponentCollection());
        foreach (array_diff(array_keys($component->paramArray), RestSearchComponent::OFFSET_SCOPES) as $scope) {
            $this->assertSame([null, ['limit' => 3]], $this->check(['limit' => 3, 'offset' => 4], $scope), $scope);
        }
        // still checked where it is then dropped
        $this->expectException(BadRequestException::class);
        $this->check(['limit' => 3, 'offset' => 'abc'], 'Sighting');
    }

    public function testNoOffsetLeavesTheFiltersAlone()
    {
        $this->assertSame([null, ['limit' => 3, 'page' => 2]], $this->check(['limit' => 3, 'page' => 2]));
        $this->assertSame([null, []], $this->check([]));
    }

    public function testEventReportsStartAtTheOffset()
    {
        $eventId = (int)ClassRegistry::init('Event')->find('first', [
            'fields' => ['Event.id'], 'order' => ['Event.id' => 'ASC'], 'recursive' => -1,
        ])['Event']['id'];
        $this->assertNotEmpty($eventId, 'Needs an event in the database.');
        $model = ClassRegistry::init('EventReport');
        $ids = $this->insert($model, 8, function ($n, $uuid) use ($eventId) {
            return ['uuid' => $uuid, 'event_id' => $eventId, 'name' => "{$this->token}-$n", 'content' => '',
                'distribution' => 0, 'timestamp' => time(), 'deleted' => 0];
        });
        $this->assertPages($model, 'EventReport', $ids);
    }

    public function testAnalystDataStartsAtTheOffset()
    {
        $model = ClassRegistry::init('Note');
        $orgUuid = $this->user['Organisation']['uuid'];
        $ids = $this->insert($model, 8, function ($n, $uuid) use ($orgUuid) {
            $now = gmdate('Y-m-d H:i:s');
            return ['uuid' => $uuid, 'object_uuid' => CakeText::uuid(), 'object_type' => 'Event',
                'org_uuid' => $orgUuid, 'orgc_uuid' => $orgUuid, 'created' => $now, 'modified' => $now,
                'distribution' => 0, 'note' => "{$this->token}-$n"];
        });
        $this->assertPages($model, 'Note', $ids);
    }

    public function testCollectionsStartAtTheOffset()
    {
        $model = ClassRegistry::init('Collection');
        $ids = $this->insertCollections(8);
        $this->assertPages($model, 'Collection', $ids);
    }

    public function testAnOffsetPageCrossesAChunk()
    {
        $this->assertSame(100, Collection::REST_SEARCH_CHUNK);
        $model = ClassRegistry::init('Collection');
        $ids = $this->insertCollections(115);
        // an IN list that long is over the query limits
        $query = ['name' => ['LIKE' => "{$this->token}-%"]];
        $this->assertSame(array_slice($ids, 3, 110), $this->ids($model, 'Collection', $query, ['limit' => 110, 'offset' => 3]));
    }

    public function testTagsStartAtTheOffset()
    {
        $model = ClassRegistry::init('Tag');
        $ids = $this->insert($model, 8, function ($n) {
            return ['name' => "{$this->token}-$n", 'colour' => '#ffffff', 'exportable' => 1];
        });
        $this->assertPages($model, 'Tag', $ids);
    }

    public function testOrganisationsStartAtTheOffset()
    {
        $model = ClassRegistry::init('Organisation');
        $ids = $this->insert($model, 8, function ($n, $uuid) {
            $now = date('Y-m-d H:i:s');
            return ['name' => "{$this->token}-$n", 'uuid' => $uuid, 'date_created' => $now, 'date_modified' => $now];
        });
        $this->assertPages($model, 'Organisation', $ids);
    }

    private function insertCollections($count)
    {
        $user = $this->user;
        return $this->insert(ClassRegistry::init('Collection'), $count, function ($n, $uuid) use ($user) {
            $now = date('Y-m-d H:i:s');
            return ['uuid' => $uuid, 'org_id' => $user['org_id'], 'orgc_id' => $user['org_id'], 'user_id' => $user['id'],
                'created' => $now, 'modified' => $now, 'distribution' => 0, 'name' => "{$this->token}-$n", 'type' => 'campaign'];
        });
    }

    /**
     * @return int[] the new rows' ids, ascending as inserted
     */
    private function insert(AppModel $model, $count, callable $row)
    {
        $ids = [];
        for ($n = 0; $n < $count; $n++) {
            $model->create();
            $saved = $model->save($row($n, CakeText::uuid()), ['validate' => false, 'callbacks' => false, 'atomic' => false]);
            $this->assertNotEmpty($saved, $model->alias . ' fixture not saved');
            $ids[] = (int)$model->id;
        }
        return $ids;
    }

    /**
     * @return int[] the ids restSearch returns, narrowed by the complex query
     */
    private function ids(AppModel $model, $alias, array $query, array $filters)
    {
        $elementCounter = 0;
        $renderView = false;
        $skipped = 0;
        $result = $model->restSearch($this->user, 'json', $filters, false, false, $elementCounter, $renderView, $skipped, $query);
        $ids = array_map(function ($row) use ($alias) {
            return (int)$row[$alias]['id'];
        }, json_decode($result->intoString(), true)['response']);
        $this->assertSame(count($ids), $elementCounter);
        return $ids;
    }

    private function assertPages(AppModel $model, $alias, array $ids)
    {
        $this->assertCount(8, $ids);
        $rows = ['id' => ['IN' => $ids]];
        // as before: no offset, or page next to one
        $this->assertSame(array_slice($ids, 0, 3), $this->ids($model, $alias, $rows, ['limit' => 3]));
        $this->assertSame(array_slice($ids, 3, 3), $this->ids($model, $alias, $rows, ['limit' => 3, 'page' => 2]));
        $this->assertSame(array_slice($ids, 3, 3), $this->ids($model, $alias, $rows, ['limit' => 3, 'page' => 2, 'offset' => 0]));
        // an offset that is not a multiple of the limit
        $this->assertSame(array_slice($ids, 4, 3), $this->ids($model, $alias, $rows, ['limit' => 3, 'offset' => 4]));
        $this->assertSame(array_slice($ids, 0, 3), $this->ids($model, $alias, $rows, ['limit' => 3, 'offset' => 0]));
        $this->assertSame([$ids[7]], $this->ids($model, $alias, $rows, ['limit' => 3, 'offset' => 7]));
        $this->assertSame([], $this->ids($model, $alias, $rows, ['limit' => 3, 'offset' => 8]));
    }
}
