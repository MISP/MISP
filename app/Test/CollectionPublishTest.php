<?php
/**
 * A collection shared beyond its organisation reaches partners when
 * published: what counts as withheld, what it holds back (its organisation's
 * graphs on it and links between its members), who may publish, what a local
 * save, a publish, a graph or a link saved here does to the published state,
 * and that only another instance is served without what is held back.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database, as the other tests
 * under app/Test/. The framework classes touched are stubbed below, each
 * guarded so that a full-suite run sharing one process keeps whichever stub
 * loaded first.
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

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
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
    }
}

if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
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
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

require_once __DIR__ . '/../Lib/Tools/SyncTool.php';
require_once __DIR__ . '/../Lib/Tools/ComplexQueryTool.php';
require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Collection.php';
require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Model/CollectionElement.php';

class PublishTestSharingGroups
{
    public function authorizedIds($user)
    {
        return array(5);
    }
}

class PublishTestUsers
{
    private $user;

    public function __construct(array $user)
    {
        $this->user = $user;
    }

    public function getAuthUser($id)
    {
        return $this->user;
    }
}

/** Collection with its writes and reads recorded instead of run. */
class PublishTestCollection extends Collection
{
    public $saves = array();
    public $updates = array();
    public $scopes = array();
    public $scopeReads = 0;
    public $listed = array();
    public $fields = array();

    public function __construct()
    {
    }

    public function field($name, $conditions = null, $order = null)
    {
        return $this->fields[$name] ?? false;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->data = $data;
        $this->beforeSave();
        $this->saves[] = array($this->data, $validate);
        return $this->data;
    }

    public function updateAll($fields, $conditions = true)
    {
        $this->updates[] = array($fields, $conditions);
        return true;
    }

    public function find($type = 'first', $query = array())
    {
        return array_shift($this->listed) ?? array();
    }

    public function withheldScopes()
    {
        $this->scopeReads++;
        return $this->scopes;
    }
}

/** Collection elements: updates recorded, lists answered in turn. */
class PublishTestElements
{
    public $updates = array();
    public $lists = array();
    public $asked = array();

    public function updateAll($fields, $conditions = true)
    {
        $this->updates[] = array($fields, $conditions);
        return true;
    }

    public function find($type, $query = array())
    {
        $this->asked[] = $query['conditions'];
        return array_shift($this->lists) ?? array();
    }

    /** @var array SHA-256s narrowerValues() answers narrower */
    public $narrower = array();

    public function narrowerValues(array $user, $distribution, array $hexes)
    {
        return array_values(array_intersect($this->narrower, $hexes));
    }
}

class PublishTestDescriber
{
    public function describeTargets(array $user, array $targets)
    {
        return array();
    }
}

class PublishTestRemovals
{
    public $deleted = array();

    public function deleteAll($conditions, $cascade = true)
    {
        $this->deleted[] = $conditions;
        return true;
    }

    public function find($type, $query = array())
    {
        return $type === 'count' ? 0 : array();
    }
}

/** Graphs and relationships: the conditions they are asked with. */
class PublishTestAnalystData
{
    public $asked = array();

    public function find($type, $query = array())
    {
        $this->asked[] = $query['conditions'];
        return $type === 'count' ? 0 : array();
    }

    public function summaries(array $user, array $conditions, array $options = array())
    {
        $this->asked[] = $conditions;
        return array();
    }
}

class PublishTestOrgs
{
    public $id = 9;

    public function find($type, $query = array())
    {
        return $this->id === null ? array() : array('Orgc' => array('id' => $this->id));
    }
}

class CollectionPublishTest extends TestCase
{
    const COLLECTION = 'c0000000-0000-4000-8000-00000000000a';
    const EVENT = 'e0000000-0000-4000-8000-00000000000b';
    const ATTRIBUTE = 'a0000000-0000-4000-8000-00000000000c';
    const ELSEWHERE = 'f0000000-0000-4000-8000-00000000000d';
    const HASH = '9c180de0cd699ee78897c47cfdb3e7ee1d75906e31b7746a4747dea536909837';

    private $collection;
    private $elements;
    private $removals;
    private $saved = array();

    protected function setUp(): void
    {
        $this->saved = ClassRegistry::$instances;
        $this->collection = new PublishTestCollection();
        $this->elements = new PublishTestElements();
        $this->removals = new PublishTestRemovals();
        $this->collection->CollectionElement = $this->elements;
        $this->collection->Orgc = new PublishTestOrgs();
        ClassRegistry::$instances['CollectionElementRemoval'] = $this->removals;
        Configure::write('CurrentRequesterMispVersion', null);
    }

    protected function tearDown(): void
    {
        ClassRegistry::$instances = $this->saved;
        Configure::write('CurrentRequesterMispVersion', null);
    }

    private function scopes()
    {
        return array(array(
            'uuid' => self::COLLECTION,
            'orgc_uuid' => 'org-a',
            'members' => array(self::EVENT => true, self::ATTRIBUTE => true, self::HASH => true, self::COLLECTION => true),
        ));
    }

    private function link($from, $to, $orgc = 'org-a', $fromType = 'Event', $toType = 'Attribute')
    {
        $row = array('orgc_uuid' => $orgc, 'object_type' => $fromType, 'related_object_type' => $toType);
        $row[$fromType === 'AttributeValue' ? 'object_sha256' : 'object_uuid'] = $from;
        $row[$toType === 'AttributeValue' ? 'related_object_sha256' : 'related_object_uuid'] = $to;
        return $row;
    }

    private function user(array $role, $org = 1, $id = 3)
    {
        return array('id' => $id, 'org_id' => $org, 'Role' => $role + array('perm_site_admin' => false));
    }

    public function testWithheldMeansSharedAndUnpublished()
    {
        $this->assertFalse(Collection::isWithheld(array('distribution' => 0, 'published' => false)), 'organisation only: nothing to publish');
        $this->assertFalse(Collection::isWithheld(array('distribution' => 1, 'published' => true)));
        $this->assertTrue(Collection::isWithheld(array('distribution' => '1', 'published' => '0')));
        $this->assertTrue(Collection::isWithheld(array('distribution' => 4, 'published' => false)), 'a sharing group too');
        $this->assertSame(
            array('OR' => array(array('Collection.distribution' => 0), array('Collection.published' => true))),
            Collection::releasedConditions()
        );
    }

    public function testAGraphOnTheCollectionByItsOrganisationIsHeldBack()
    {
        $graph = array('object_type' => 'Collection', 'object_uuid' => strtoupper(self::COLLECTION), 'orgc_uuid' => 'ORG-A');
        $this->assertTrue(Collection::holdsBack($this->scopes(), 'Graph', $graph));
        $this->assertFalse(Collection::holdsBack($this->scopes(), 'Graph', array('orgc_uuid' => 'org-b') + $graph), 'another organisation\'s');
        $this->assertFalse(Collection::holdsBack($this->scopes(), 'Graph', array('object_type' => 'Event', 'object_uuid' => self::EVENT) + $graph), 'a graph on a member');
    }

    public function testALinkBetweenMembersByItsOrganisationIsHeldBack()
    {
        $scopes = $this->scopes();
        $this->assertTrue(Collection::holdsBack($scopes, 'Relationship', $this->link(self::EVENT, strtoupper(self::ATTRIBUTE))));
        $this->assertTrue(Collection::holdsBack($scopes, 'Relationship', $this->link(self::COLLECTION, self::EVENT, 'org-a', 'Collection', 'Event')), 'from the collection itself');
        $this->assertTrue(Collection::holdsBack($scopes, 'Relationship', $this->link(self::EVENT, strtoupper(self::HASH), 'org-a', 'Event', 'AttributeValue')), 'to a value member');
        $this->assertFalse(Collection::holdsBack($scopes, 'Relationship', $this->link(self::EVENT, self::ELSEWHERE)), 'one end outside');
        $this->assertFalse(Collection::holdsBack($scopes, 'Relationship', $this->link(self::EVENT, self::ATTRIBUTE, 'org-b')), 'another organisation\'s');
        $this->assertFalse(Collection::holdsBack($scopes, 'Relationship', array('orgc_uuid' => '') + $this->link(self::EVENT, self::ATTRIBUTE)));
        $this->assertFalse(Collection::holdsBack($scopes, 'Note', array('orgc_uuid' => 'org-a', 'object_uuid' => self::EVENT)), 'notes never wait');
    }

    public function testWithoutHeldBackLeavesTheRestAlone()
    {
        $this->collection->scopes = $this->scopes();
        $byType = array(
            'Note' => array(array('Note' => array('orgc_uuid' => 'org-a', 'object_uuid' => self::EVENT))),
            'Relationship' => array(
                array('Relationship' => array('uuid' => 'held') + $this->link(self::EVENT, self::ATTRIBUTE)),
                array('Relationship' => array('uuid' => 'goes') + $this->link(self::EVENT, self::ATTRIBUTE, 'org-b')),
            ),
            'Graph' => array(array('Graph' => array('uuid' => 'held', 'object_type' => 'Collection', 'object_uuid' => self::COLLECTION, 'orgc_uuid' => 'org-a'))),
        );
        $out = $this->collection->withoutHeldBack($byType);
        $this->assertSame($byType['Note'], $out['Note']);
        $this->assertSame(array('goes'), Hash::extract($out['Relationship'], '{n}.Relationship.uuid'));
        $this->assertSame(array(), $out['Graph']);

        $this->collection->scopes = array();
        $this->assertSame($byType, $this->collection->withoutHeldBack($byType), 'nothing withheld, nothing left out');
        $this->assertSame(array('Note' => array()), $this->collection->withoutHeldBack(array('Note' => array())));
        $this->assertSame(2, $this->collection->scopeReads, 'no graph nor link: the scopes are not read');
    }

    public function testOnlyAnotherInstanceIsServedWithoutWhatIsHeldBack()
    {
        $this->collection->scopes = $this->scopes();
        $rows = array(array('Relationship' => $this->link(self::EVENT, self::ATTRIBUTE)));
        $this->assertSame($rows, $this->collection->servedRelationships($rows), 'an API client');
        $this->assertSame(0, $this->collection->scopeReads);

        Configure::write('CurrentRequesterMispVersion', '3.0.0');
        $this->assertSame(array(), $this->collection->servedRelationships($rows));
        $this->collection->servedRelationships($rows);
        $this->assertSame(1, $this->collection->scopeReads, 'read once for the request');
    }

    public function testAnotherInstanceIsServedAsAnyUserUnlessOlderThan30()
    {
        $this->assertSame(array(), Collection::servedConditions(), 'an API client');
        Configure::write('CurrentRequesterMispVersion', '3.0.0');
        $this->assertSame(array(), Collection::servedConditions(), 'a 3.0 instance pulls published ones itself');
        Configure::write('CurrentRequesterMispVersion', '2.5.22');
        $this->assertSame(Collection::releasedConditions(), Collection::servedConditions(), 'no publish step to tell');
        $this->assertSame(
            array('Collection.distribution !=' => 0, 'Collection.published' => false),
            Collection::withheldConditions()
        );
    }

    public function testUnpublishedPrivateKeepsAnUnpublishedCollectionInItsOrganisation()
    {
        ClassRegistry::$instances['SharingGroup'] = new PublishTestSharingGroups();
        $user = $this->user(array('perm_site_admin' => false), 2);
        $setting = Configure::read('MISP.unpublishedprivate');

        Configure::write('MISP.unpublishedprivate', false);
        $open = $this->collection->buildConditions($user);
        Configure::write('MISP.unpublishedprivate', true);
        $private = $this->collection->buildConditions($user);

        $this->collection->User = new PublishTestUsers($user);
        $this->collection->listed = array(array('Collection' => array('org_id' => 1, 'distribution' => 1, 'published' => false)));
        $mayView = $this->collection->mayView(3, 10);
        $this->collection->listed = array(array('Collection' => array('org_id' => 2, 'distribution' => 1, 'published' => false)));
        $mayViewOwn = $this->collection->mayView(3, 10);
        Configure::write('MISP.unpublishedprivate', false);
        $this->collection->listed = array(array('Collection' => array('org_id' => 1, 'distribution' => 1, 'published' => false)));
        $mayViewOpen = $this->collection->mayView(3, 10);
        Configure::write('MISP.unpublishedprivate', $setting);

        $this->assertSame(array('Collection.org_id' => 2), $open['OR'][0]);
        $this->assertSame(array(), $open['OR'][1]['AND'][1], 'unset: shared unpublished collections are seen');
        $this->assertSame(array('Collection.published' => true), $private['OR'][1]['AND'][1]);
        $this->assertSame(array('Collection.published' => true), $private['OR'][2]['AND'][1], 'a sharing group too');
        $this->assertSame(array(5), $private['OR'][2]['AND'][0]['Collection.sharing_group_id']);
        $this->assertSame(array('Collection.org_id' => 2), $private['OR'][0], 'its organisation still sees it');
        $this->assertFalse($mayView);
        $this->assertTrue($mayViewOwn);
        $this->assertTrue($mayViewOpen);
    }

    public function testACollectionThatIsNotThereCannotBeViewed()
    {
        $this->collection->User = new PublishTestUsers($this->user(array('perm_site_admin' => true)));
        $this->collection->listed = array();

        $this->assertFalse($this->collection->mayView(3, 987654), 'not even by a site admin');
    }

    public function testPublishingTakesPermPublishAndTheEditRight()
    {
        $collection = array('org_id' => 1, 'orgc_id' => 1, 'user_id' => 3);
        $this->assertTrue($this->collection->canPublish($this->user(array('perm_site_admin' => true), 5, 1), $collection));
        $publisher = array('perm_modify' => true, 'perm_modify_org' => true, 'perm_publish' => true);
        $this->assertTrue($this->collection->canPublish($this->user($publisher, 1, 4), $collection));
        $this->assertFalse($this->collection->canPublish($this->user($publisher, 2, 4), $collection), 'another organisation\'s publisher');
        $this->assertFalse($this->collection->canPublish($this->user(array('perm_publish' => false) + $publisher), $collection), 'a User-role analyst who may edit it');
    }

    public function testALocalSaveLeavesItUnpublished()
    {
        $this->collection->data = array('Collection' => array('name' => 'x', 'published' => true, 'last_published' => '2026-10-28 10:00:00'));
        $this->collection->beforeSave();
        $this->assertFalse($this->collection->data['Collection']['published']);
        $this->assertArrayNotHasKey('last_published', $this->collection->data['Collection'], 'a request cannot set it either');
    }

    public function testPublishReleasesTheCollectionItsMembersAndItsRemovals()
    {
        $this->assertTrue($this->collection->publish(5, 2));
        list($saved) = $this->collection->saves[0];
        $this->assertTrue($saved['Collection']['published'], 'not undone by the local-save rule');
        $this->assertSame(2, $saved['Collection']['analysis']);
        $this->assertRegExp('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $saved['Collection']['last_published']);
        $this->assertSame($saved['Collection']['last_published'], $saved['Collection']['modified'], 'partners fetch it again');
        $this->assertSame(array(array(
            array('CollectionElement.published' => true),
            array('CollectionElement.collection_id' => 5, 'CollectionElement.published' => false),
        )), $this->elements->updates);
        $this->assertSame(array(array('CollectionElementRemoval.collection_id' => 5)), $this->removals->deleted);

        $this->collection->publish(5);
        $this->assertArrayNotHasKey('analysis', $this->collection->saves[1][0]['Collection'], 'left out, it is kept');
        $this->collection->data = array('Collection' => array('published' => true));
        $this->collection->beforeSave();
        $this->assertFalse($this->collection->data['Collection']['published'], 'the next local save unpublishes again');
    }

    public function testUnpublishWithdrawsItAndChangesNothingElse()
    {
        $this->collection->fields['modified'] = '2026-10-28 09:00:00';
        $this->assertTrue($this->collection->unpublish(5));
        list($saved) = $this->collection->saves[0];
        $this->assertSame(array('id' => 5, 'published' => false, 'modified' => '2026-10-28 09:00:00'), $saved['Collection'], 'modified kept: partners need not fetch it again');
        $this->assertSame(array(), $this->elements->updates, 'its members stay as they were released');
        $this->assertSame(array(), $this->removals->deleted);
    }

    public function testSettingTheStatusIsAChangePartnersDoNotHaveYet()
    {
        $this->assertTrue($this->collection->setAnalysis(5, 2));
        list($saved) = $this->collection->saves[0];
        $this->assertSame(2, $saved['Collection']['analysis']);
        $this->assertFalse($saved['Collection']['published'], 'a shared collection waits for its next publish');
        $this->assertArrayNotHasKey('last_published', $saved['Collection']);
        $this->assertRegExp('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $saved['Collection']['modified']);
    }

    /**
     * @param array $fields What unpublishFor() wrote
     */
    private function assertUnpublishedAndChanged(array $fields)
    {
        $this->assertSame(false, $fields['Collection.published']);
        $this->assertRegExp("/^'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'$/", $fields['Collection.modified'], 'a change partners lack, not unpublished by hand');
    }

    public function testAGraphSavedHereUnpublishesItsOrganisationsCollection()
    {
        $this->collection->graphSaved(array('object_type' => 'Collection', 'object_uuid' => 'C0000000-0000-4000-8000-00000000000A', 'orgc_uuid' => 'org-a', 'locked' => false, 'distribution' => '1'));
        $this->assertCount(1, $this->collection->updates);
        $this->assertUnpublishedAndChanged($this->collection->updates[0][0]);
        $this->assertSame(array('AND' => array(
            array('Collection.uuid' => array(self::COLLECTION, strtoupper(self::COLLECTION))),
            array('Collection.orgc_id' => 9, 'Collection.published' => true),
        )), $this->collection->updates[0][1]);

        $this->collection->updates = array();
        $this->collection->graphSaved(array('object_type' => 'Collection', 'object_uuid' => self::COLLECTION, 'orgc_uuid' => 'org-a', 'locked' => true));
        $this->collection->graphSaved(array('object_type' => 'Event', 'object_uuid' => self::EVENT, 'orgc_uuid' => 'org-a', 'locked' => false));
        $this->collection->Orgc->id = null;
        $this->collection->graphSaved(array('object_type' => 'Collection', 'object_uuid' => self::COLLECTION, 'orgc_uuid' => 'org-unknown', 'locked' => false));
        $this->assertSame(array(), $this->collection->updates, 'a capture, a graph on an event, an organisation unknown here');
    }

    public function testALinkSavedHereUnpublishesTheCollectionsHoldingBothEnds()
    {
        // element id => collection id, one list per end
        $this->elements->lists = array(array(10 => 1, 11 => 2), array(12 => 2, 13 => 3));
        $this->collection->relationshipSaved($this->link(self::EVENT, self::ATTRIBUTE));
        $this->assertSame(array('CollectionElement.element_uuid' => self::EVENT), $this->elements->asked[0], 'members are stored lowercase');
        $this->assertUnpublishedAndChanged($this->collection->updates[0][0]);
        $this->assertSame(array('AND' => array(
            array('Collection.id' => array(2)),
            array('Collection.orgc_id' => 9, 'Collection.published' => true),
        )), $this->collection->updates[0][1]);

        $this->collection->updates = array();
        $this->collection->listed = array(array(7 => 7));
        $this->elements->lists = array(array(14 => 7));
        $this->collection->relationshipSaved($this->link(self::COLLECTION, self::EVENT, 'org-a', 'Collection', 'Event'));
        $this->assertSame(array(7), $this->collection->updates[0][1]['AND'][0]['Collection.id'], 'from the collection to a member');

        $this->collection->updates = array();
        $this->elements->lists = array(array(10 => 1), array(12 => 2));
        $this->collection->relationshipSaved($this->link(self::EVENT, self::ATTRIBUTE));
        $this->collection->relationshipSaved(array('locked' => true) + $this->link(self::EVENT, self::ATTRIBUTE));
        $this->assertSame(array(), $this->collection->updates, 'no collection holds both; a capture');
    }

    public function testWhatStaysOnThisInstanceLeavesTheCollectionPublished()
    {
        $this->collection->graphSaved(array('object_type' => 'Collection', 'object_uuid' => self::COLLECTION, 'orgc_uuid' => 'org-a', 'locked' => false, 'distribution' => '0'));
        $this->elements->lists = array(array(10 => 2), array(12 => 2));
        $this->collection->relationshipSaved(array('locked' => false, 'distribution' => 0) + $this->link(self::EVENT, self::ATTRIBUTE));

        $this->assertSame(array(), $this->collection->updates);
        $this->assertSame(array(), $this->elements->asked, 'nothing looked up');
    }

    public function testTheReviewListsMembersFoundByAskingAboutANarrowerValue()
    {
        ClassRegistry::$instances['Graph'] = new PublishTestAnalystData();
        ClassRegistry::$instances['Relationship'] = new PublishTestAnalystData();
        ClassRegistry::$instances['AnalystData'] = new PublishTestDescriber();
        $asked = 'org-only.example';
        $found = hash('sha256', 'found.example');
        $origin = json_encode(array('module' => 'circl_passivedns', 'type' => 'domain', 'value' => $asked, 'ran_at' => 1700000000));
        $this->elements->narrower = array(hash('sha256', $asked));
        // added, their count, the members not yet published
        $this->elements->lists = array(array(), array(), array(
            array('CollectionElement' => array(
                'id' => 1, 'element_type' => 'AttributeValue', 'element_uuid' => null,
                'element_sha256' => $found, 'element_value' => 'found.example', 'origin' => $origin,
            )),
            array('CollectionElement' => array(
                'id' => 2, 'element_type' => 'Event', 'element_uuid' => self::EVENT,
                'element_sha256' => null, 'element_value' => null, 'origin' => null,
            )),
        ));

        $review = $this->collection->publishReview($this->user(array()), array(
            'id' => 7, 'uuid' => self::COLLECTION, 'name' => 'APT28', 'distribution' => 3,
            'last_published' => null, 'Orgc' => array('uuid' => 'org-a'),
        ));

        $this->assertSame(0, $review['narrower']['count'], 'the value found is not narrower');
        $this->assertSame(1, $review['narrower_origins']['count']);
        $this->assertSame(
            array('type' => 'AttributeValue', 'address' => $found, 'asked' => $asked, 'label' => 'found.example', 'meta' => array()),
            $review['narrower_origins']['items'][0]
        );
    }

    public function testTheReviewLeavesOutGraphsAndLinksThatStayOnThisInstance()
    {
        $graphs = new PublishTestAnalystData();
        $relationships = new PublishTestAnalystData();
        ClassRegistry::$instances['Graph'] = $graphs;
        ClassRegistry::$instances['Relationship'] = $relationships;
        // added, their count, value members, member addresses
        $this->elements->lists = array(array(), array(), array(), array(
            array('CollectionElement' => array('collection_id' => 7, 'element_uuid' => self::EVENT, 'element_sha256' => null)),
        ));

        $review = $this->collection->publishReview($this->user(array()), array(
            'id' => 7, 'uuid' => self::COLLECTION, 'name' => 'APT28', 'distribution' => 3,
            'last_published' => '2026-11-01 10:00:00', 'Orgc' => array('uuid' => 'org-a'),
        ));

        $this->assertSame(0, $review['graphs']['count']);
        foreach ($graphs->asked as $conditions) {
            $this->assertSame(0, $conditions['Graph.distribution !='] ?? null);
        }
        $this->assertNotEmpty($relationships->asked);
        foreach ($relationships->asked as $conditions) {
            $this->assertSame(0, $conditions['Relationship.distribution !='] ?? null);
            $this->assertSame('2026-11-01 10:00:00', $conditions['Relationship.modified >']);
        }
    }

    public function testMembersSentToPartnersKeepTheirFlagHome()
    {
        $this->assertSame(
            array(array('uuid' => 'e1', 'created' => '2026-10-28 10:00:00')),
            Collection::withoutAdders(array(array('uuid' => 'e1', 'created' => '2026-10-28 10:00:00', 'user_id' => 3, 'published' => true)))
        );
    }
}
