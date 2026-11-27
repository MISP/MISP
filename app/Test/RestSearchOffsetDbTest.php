<?php
/**
 * restSearch's offset filter: the check the controller runs once the role's
 * limit is in (RestSearchComponent::offset), the chunked models (event
 * reports, analyst data, collections, tags, organisations), attributes,
 * events (on their id query), objects and galaxy clusters, which
 * start a page at the offset, let page win over it, and page as before without
 * it. Attribute pages also cross fetch batches and lose dropped rows from the
 * offset on, without refilling. Event and galaxy cluster orders end with id,
 * so their pages neither overlap nor skip.
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

    /** @var array Configure key => its value before the test (null: unset) */
    private $configured = [];

    /** @var string|null */
    private $memoryLimit;

    /** @var array attribute id => value */
    private $values = [];

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
        foreach ($this->configured as $key => $value) {
            if ($value === null) {
                Configure::delete($key);
            } else {
                Configure::write($key, $value);
            }
        }
        if ($this->memoryLimit !== null) {
            ini_set('memory_limit', $this->memoryLimit);
        }
        $this->db->rollback();
    }

    private function configure($key, $value)
    {
        if (!array_key_exists($key, $this->configured)) {
            $this->configured[$key] = Configure::read($key);
        }
        Configure::write($key, $value);
    }

    private function firstEvent()
    {
        $event = ClassRegistry::init('Event')->find('first', [
            'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id'], 'order' => ['Event.id' => 'ASC'], 'recursive' => -1,
        ]);
        $this->assertNotEmpty($event, 'Needs an event in the database.');
        return $event['Event'];
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
        $eventId = (int)$this->firstEvent()['id'];
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

    public function testAttributesStartAtTheOffset()
    {
        $ids = $this->insertAttributes();
        // unordered pages come in MySQL's order: the reference is the same query, whole
        $all = $this->attributeIds($ids, ['limit' => 10]);
        $this->assertEqualsCanonicalizing($ids, $all);
        $this->assertSame(array_slice($all, 0, 3), $this->attributeIds($ids, ['limit' => 3]));
        $this->assertSame(array_slice($all, 3, 3), $this->attributeIds($ids, ['limit' => 3, 'page' => 2]));
        $this->assertSame(array_slice($all, 3, 3), $this->attributeIds($ids, ['limit' => 3, 'page' => 2, 'offset' => 0]));
        $this->assertSame(array_slice($all, 4, 3), $this->attributeIds($ids, ['limit' => 3, 'offset' => 4]));
        $this->assertSame([$all[9]], $this->attributeIds($ids, ['limit' => 3, 'offset' => 9]));
        $this->assertSame([], $this->attributeIds($ids, ['limit' => 3, 'offset' => 10]));
        // the values sort in the reverse of the ids
        $byValue = array_reverse($ids);
        $this->assertSame(array_slice($byValue, 4, 3), $this->attributeIds($ids, ['limit' => 3, 'offset' => 4, 'order' => 'value asc']));
    }

    public function testAnAttributeOffsetPageCrossesABatch()
    {
        $ids = $this->insertAttributes();
        $this->fetchInBatchesOf4();
        // without an order, the batches after the first follow the id cursor
        $this->assertSame(array_slice($ids, 2, 7), $this->attributeIds($ids, ['limit' => 7, 'offset' => 2]));
        $this->assertSame(array_slice(array_reverse($ids), 2, 7), $this->attributeIds($ids, ['limit' => 7, 'offset' => 2, 'order' => 'value asc']));
    }

    public function testADroppedAttributeOnlyShortensThePage()
    {
        $ids = $this->insertAttributes();
        $this->blockByProposal($ids[5]);
        $filters = ['allow_proposal_blocking' => 1];
        $skipped = 0;
        $this->assertSame([$ids[4], $ids[6]], $this->attributeIds($ids, $filters + ['limit' => 3, 'offset' => 4, 'order' => 'id asc'], $skipped));
        $this->assertSame(1, $skipped);
        $this->assertSame(array_slice($ids, 7, 3), $this->attributeIds($ids, $filters + ['limit' => 3, 'offset' => 7, 'order' => 'id asc']));
        // the dropped row ends the first batch: the cursor still moves past it
        $this->fetchInBatchesOf4();
        $this->assertSame([$ids[2], $ids[3], $ids[4], $ids[6], $ids[7], $ids[8]], $this->attributeIds($ids, $filters + ['limit' => 7, 'offset' => 2], $skipped));
        $this->assertSame(1, $skipped);
    }

    public function testAttributeParamsCarryAnOffsetOnlyWithALimit()
    {
        $attribute = ClassRegistry::init('MispAttribute');
        $params = $attribute->restSearch($this->user, 'json', ['limit' => 3, 'offset' => '4'], true);
        $this->assertSame(4, $params['offset']);
        $this->assertArrayNotHasKey('page', $params);
        $params = $attribute->restSearch($this->user, 'json', ['offset' => 4], true);
        $this->assertArrayNotHasKey('offset', $params);
        $params = $attribute->restSearch($this->user, 'json', ['limit' => 3, 'page' => 2, 'offset' => 4], true);
        $this->assertSame(2, $params['page']);
        $this->assertArrayNotHasKey('offset', $params);
        $params = $attribute->restSearch($this->user, 'json', ['limit' => 3], true);
        $this->assertSame(1, $params['page']);
        $this->assertArrayNotHasKey('offset', $params);
    }

    /**
     * @return int[] ten attributes of the first event, to_ids on, ascending ids
     *               whose values sort the other way
     */
    private function insertAttributes()
    {
        $eventId = (int)$this->firstEvent()['id'];
        $attribute = ClassRegistry::init('MispAttribute');
        $ids = [];
        for ($n = 0; $n < 10; $n++) {
            $value = sprintf('%s-%02d.example.org', $this->token, 9 - $n);
            $attribute->create();
            $saved = $attribute->save(['Attribute' => [
                'event_id' => $eventId,
                'category' => $attribute->typeDefinitions['domain']['default_category'],
                'type' => 'domain',
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 1,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, json_encode($attribute->validationErrors));
            $ids[] = (int)$attribute->id;
            $this->values[(int)$attribute->id] = $value;
        }
        return $ids;
    }

    private function fetchInBatchesOf4()
    {
        // the batch size is memory_limit in MB (8192 when unlimited) times this coefficient
        $this->memoryLimit = $this->memoryLimit ?? ini_get('memory_limit');
        ini_set('memory_limit', '-1');
        $this->configure('MISP.default_attribute_memory_coefficient', 4 / 8192);
    }

    /**
     * A proposal to turn to_ids off hides the attribute from a fetch that allows proposal blocking.
     */
    private function blockByProposal($attributeId)
    {
        $this->configure('MISP.proposals_block_attributes', true);
        $event = $this->firstEvent();
        $proposal = ClassRegistry::init('ShadowAttribute');
        $proposal->create();
        $saved = $proposal->save(['ShadowAttribute' => [
            'event_id' => $event['id'],
            'event_uuid' => $event['uuid'],
            'event_org_id' => $event['orgc_id'],
            'org_id' => $event['orgc_id'],
            'old_id' => $attributeId,
            'type' => 'domain',
            'category' => ClassRegistry::init('MispAttribute')->typeDefinitions['domain']['default_category'],
            'value' => $this->values[$attributeId],
            'to_ids' => 0,
            'comment' => $this->token,
        ]]);
        $this->assertNotFalse($saved, json_encode($proposal->validationErrors));
    }

    /**
     * @return int[] the ids attribute restSearch returns, narrowed to the given attributes
     */
    private function attributeIds(array $ids, array $filters, &$skipped = 0)
    {
        $elementCounter = 0;
        $renderView = false;
        $skipped = 0;
        $result = ClassRegistry::init('MispAttribute')->restSearch($this->user, 'json', $filters, false, false, $elementCounter, $renderView, $skipped, ['id' => ['IN' => $ids]]);
        return array_map(function ($attribute) {
            return (int)$attribute['id'];
        }, json_decode($result->intoString(), true)['response']['Attribute']);
    }

    public function testEventsStartAtTheOffset()
    {
        $ids = $this->insertEvents();
        // unordered pages come in MySQL's order: the reference is the same query, whole
        $all = $this->eventIds($ids, ['limit' => 8]);
        $this->assertEqualsCanonicalizing($ids, $all);
        $this->assertSame(array_slice($all, 0, 3), $this->eventIds($ids, ['limit' => 3]));
        $this->assertSame(array_slice($all, 3, 3), $this->eventIds($ids, ['limit' => 3, 'page' => 2]));
        $this->assertSame(array_slice($all, 3, 3), $this->eventIds($ids, ['limit' => 3, 'page' => 2, 'offset' => 0]));
        $this->assertSame(array_slice($all, 4, 3), $this->eventIds($ids, ['limit' => 3, 'offset' => 4]));
        $this->assertSame([$all[7]], $this->eventIds($ids, ['limit' => 3, 'offset' => 7]));
        $this->assertSame([], $this->eventIds($ids, ['limit' => 3, 'offset' => 8]));
        // without a limit nothing pages, as before
        $this->assertEqualsCanonicalizing($ids, $this->eventIds($ids, ['offset' => 4]));
    }

    public function testEventRestSearchStartsAtTheOffset()
    {
        $ids = $this->insertEvents();
        $elementCounter = 0;
        $renderView = false;
        $skipped = 0;
        $filters = ['eventid' => $ids, 'limit' => 3, 'offset' => 4, 'order' => 'info asc', 'metadata' => 1];
        $result = ClassRegistry::init('Event')->restSearch($this->user, 'json', $filters, false, false, $elementCounter, $renderView, $skipped);
        $rows = json_decode($result->intoString(), true)['response'];
        $this->assertSame(array_slice(array_reverse($ids), 4, 3), array_map(function ($row) {
            return (int)$row['Event']['id'];
        }, $rows));
        // every match, as with page
        $this->assertSame(8, $elementCounter);
    }

    public function testIdBreaksTheTiesOfAnEventOrder()
    {
        $ids = $this->insertEvents();
        $paged = [];
        foreach ([1, 2, 3] as $page) {
            $paged = array_merge($paged, $this->eventIds($ids, ['limit' => 3, 'page' => $page, 'order' => 'timestamp desc']));
        }
        $this->assertSame(array_reverse($ids), $paged);
    }

    public function testObjectsStartAtTheOffset()
    {
        $model = ClassRegistry::init('MispObject');
        $ids = $this->insertObjects();
        // objects cannot be ordered: the reference is the same query, whole
        $all = $this->ids($model, 'Object', ['id' => ['IN' => $ids]], ['limit' => 8]);
        $this->assertEqualsCanonicalizing($ids, $all);
        $this->assertPages($model, 'Object', $all);
    }

    public function testObjectsWithoutALimitStepAsBefore()
    {
        $model = ClassRegistry::init('MispObject');
        $ids = $this->insertObjects();
        // two fetches of 4, then an empty one
        $this->configure('MISP.object_fetch_hard_limit', 4);
        $this->assertEqualsCanonicalizing($ids, $this->ids($model, 'Object', ['id' => ['IN' => $ids]], ['offset' => 4]));
    }

    public function testGalaxyClustersStartAtTheOffset()
    {
        $model = ClassRegistry::init('GalaxyCluster');
        $ids = $this->insertClusters();
        // one type: the id tie-break orders them
        $this->assertPages($model, 'GalaxyCluster', $ids, ['order' => 'type asc']);
        $this->assertEqualsCanonicalizing($ids, $this->ids($model, 'GalaxyCluster', ['id' => ['IN' => $ids]], ['offset' => 4]));
    }

    public function testObjectAndClusterParamsCarryAnOffsetOnlyWithALimit()
    {
        foreach (['MispObject', 'GalaxyCluster'] as $name) {
            $model = ClassRegistry::init($name);
            $params = $model->restSearch($this->user, 'json', ['limit' => 3, 'offset' => 4], true);
            $this->assertSame([3, 4, 1], [$params['limit'], $params['offset'], $params['page']], $name);
            $params = $model->restSearch($this->user, 'json', ['limit' => 3, 'page' => 2, 'offset' => 4], true);
            $this->assertArrayNotHasKey('offset', $params, $name);
            foreach ([['offset' => 4], ['limit' => 0, 'offset' => 4]] as $filters) {
                $this->assertArrayNotHasKey('offset', $model->restSearch($this->user, 'json', $filters, true), $name);
            }
        }
    }

    /**
     * @return int[] eight objects in the first event, ascending ids
     */
    private function insertObjects()
    {
        $eventId = (int)$this->firstEvent()['id'];
        return $this->insert(ClassRegistry::init('MispObject'), 8, function ($n, $uuid) use ($eventId) {
            return ['uuid' => $uuid, 'event_id' => $eventId, 'name' => $this->token, 'meta-category' => 'misc',
                'description' => '', 'template_uuid' => $uuid, 'template_version' => 1, 'timestamp' => time(),
                'distribution' => 0, 'sharing_group_id' => 0, 'comment' => '', 'deleted' => 0];
        });
    }

    public function testIdBreaksTheTiesOfAGalaxyClusterOrder()
    {
        $model = ClassRegistry::init('GalaxyCluster');
        $ids = $this->insertClusters();
        $rows = ['id' => ['IN' => $ids]];
        $paged = [];
        foreach ([1, 2, 3] as $page) {
            $paged = array_merge($paged, $this->ids($model, 'GalaxyCluster', $rows, ['limit' => 3, 'page' => $page, 'order' => 'type desc']));
        }
        $this->assertSame(array_reverse($ids), $paged);
        // an order on id is left as it is
        $this->assertSame(array_reverse($ids), $this->ids($model, 'GalaxyCluster', $rows, ['limit' => 8, 'order' => 'id desc']));
    }

    /**
     * @return int[] eight clusters of one type, ascending ids whose values sort the other way
     */
    private function insertClusters()
    {
        $user = $this->user;
        $now = date('Y-m-d H:i:s');
        $galaxy = $this->insert(ClassRegistry::init('Galaxy'), 1, function ($n, $uuid) use ($user, $now) {
            return ['uuid' => $uuid, 'name' => $this->token, 'type' => $this->token, 'description' => '', 'version' => '1',
                'namespace' => 'misp', 'org_id' => $user['org_id'], 'orgc_id' => $user['org_id'], 'created' => $now,
                'modified' => $now, 'distribution' => 3];
        })[0];
        return $this->insert(ClassRegistry::init('GalaxyCluster'), 8, function ($n, $uuid) use ($user, $galaxy) {
            return ['uuid' => $uuid, 'collection_uuid' => $uuid, 'type' => $this->token, 'galaxy_id' => $galaxy,
                'value' => sprintf('%s-%02d', $this->token, 7 - $n), 'tag_name' => "misp-galaxy:{$this->token}=\"$n\"",
                'description' => '', 'source' => '', 'authors' => '[]', 'version' => 1, 'distribution' => 3,
                'org_id' => $user['org_id'], 'orgc_id' => $user['org_id'], 'default' => 0, 'published' => 1, 'deleted' => 0];
        });
    }

    /**
     * @return int[] eight events with one timestamp, ascending ids whose infos sort the other way
     */
    private function insertEvents()
    {
        $user = $this->user;
        return $this->insert(ClassRegistry::init('Event'), 8, function ($n, $uuid) use ($user) {
            return ['uuid' => $uuid, 'org_id' => $user['org_id'], 'orgc_id' => $user['org_id'], 'user_id' => $user['id'],
                'date' => '2026-11-27', 'info' => sprintf('%s-%02d', $this->token, 7 - $n), 'analysis' => 0,
                'distribution' => 0, 'sharing_group_id' => 0, 'threat_level_id' => 4, 'timestamp' => 1700000000];
        });
    }

    /**
     * @return int[] the event ids filterEventIds pages for restSearch, narrowed to the given events
     */
    private function eventIds(array $ids, array $params)
    {
        $params += ['eventid' => $ids, 'include_attribute_count' => 1];
        return array_map('intval', array_keys(ClassRegistry::init('Event')->filterEventIds($this->user, $params)));
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

    /**
     * @param int[] $ids the rows in the order the model returns them
     * @param array $filters added to every request
     */
    private function assertPages(AppModel $model, $alias, array $ids, array $filters = [])
    {
        $this->assertCount(8, $ids);
        $rows = ['id' => ['IN' => $ids]];
        // as before: no offset, or page next to one
        $this->assertSame(array_slice($ids, 0, 3), $this->ids($model, $alias, $rows, $filters + ['limit' => 3]));
        $this->assertSame(array_slice($ids, 3, 3), $this->ids($model, $alias, $rows, $filters + ['limit' => 3, 'page' => 2]));
        $this->assertSame(array_slice($ids, 3, 3), $this->ids($model, $alias, $rows, $filters + ['limit' => 3, 'page' => 2, 'offset' => 0]));
        // an offset that is not a multiple of the limit
        $this->assertSame(array_slice($ids, 4, 3), $this->ids($model, $alias, $rows, $filters + ['limit' => 3, 'offset' => 4]));
        $this->assertSame(array_slice($ids, 0, 3), $this->ids($model, $alias, $rows, $filters + ['limit' => 3, 'offset' => 0]));
        $this->assertSame([$ids[7]], $this->ids($model, $alias, $rows, $filters + ['limit' => 3, 'offset' => 7]));
        $this->assertSame([], $this->ids($model, $alias, $rows, $filters + ['limit' => 3, 'offset' => 8]));
    }
}
