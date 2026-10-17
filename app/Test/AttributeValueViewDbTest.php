<?php
/**
 * /values/view and /values/search. A value is shown with the attributes
 * holding it that the user can see; a value with none of those is answered
 * exactly like a value that does not exist. Search lists only values the user
 * sees at least one holder of.
 *
 * The values are interned before the test's transaction, so that the
 * FULLTEXT index holds them, and deleted by id after it; the attributes are
 * saved inside the transaction, which is rolled back. Every value holds a
 * random token no stored value holds. The lesser user is user 195, of
 * another organisation than the fixture events.
 *
 * Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real
 * application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueViewDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueViewDbTest extends TestCase
{
    const LESSER_USER = 195;

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var AttributeValue */
    private $values;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $admin;

    /** @var array */
    private $lesser;

    /** @var string */
    private $t;

    /** @var array name => event id */
    private $events;

    /** @var array name => attribute id */
    private $ids = [];

    /** @var int[] dictionary ids interned for the test */
    private $interned = [];

    /** @var array value => dictionary id */
    private $valueIds = [];

    /** @var bool */
    private $cachedMethods;

    /** @var mixed */
    private $currentUserId;

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
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('AttributeValue', 'Model');
            App::uses('ValuesController', 'Controller');
            App::uses('CakeText', 'Utility');
            App::uses('ComponentCollection', 'Controller');
            App::uses('CRUDComponent', 'Controller/Component');
            App::uses('ACLComponent', 'Controller/Component');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->values = $this->attribute->loadAttributeValue();
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->cachedMethods = $this->db->cacheMethods;
        $users = ClassRegistry::init('User');
        $this->admin = $users->getAuthUser(1);
        $this->lesser = $users->getAuthUser(self::LESSER_USER);
        if (empty($this->lesser) || $this->lesser['Role']['perm_site_admin']) {
            $this->markTestSkipped('Needs user 195, without site admin rights.');
        }
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->admin['id']);
        $org = (int)$this->lesser['org_id'];
        $this->events = [
            'hidden' => $this->firstEvent("distribution = 0 AND org_id <> $org"),
            'open' => $this->firstEvent("distribution = 3 AND published = 1 AND org_id <> $org"),
        ];
        $this->t = 'vc' . bin2hex(random_bytes(5));
        $fixture = $this->fixture();
        $this->intern($fixture);
        $this->db->begin();
        $this->add($fixture);
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
        $this->db->cacheMethods = $this->cachedMethods;
        foreach ($this->attributeModels() as $model) {
            $model->schema(true);
        }
        $this->db->rollback();
        if (!empty($this->interned)) {
            $ids = implode(', ', $this->interned);
            $held = $this->exec("SELECT 1 FROM attributes WHERE value1_id IN ($ids) OR value2_id IN ($ids) LIMIT 1");
            $this->assertEmpty($held, 'An interned fixture value is still referenced.');
            $this->exec("DELETE FROM value_ip_ranges WHERE value_id IN ($ids)");
            $this->exec("DELETE FROM attribute_values WHERE id IN ($ids)");
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

    private function firstEvent($where)
    {
        $rows = $this->exec("SELECT id FROM events WHERE $where ORDER BY id LIMIT 1");
        if (empty($rows)) {
            $this->markTestSkipped("Needs an event with $where.");
        }
        return (int)$rows[0]['id'];
    }

    /**
     * @return array name => [event, type, value, deleted]
     */
    private function fixture()
    {
        $t = $this->t;
        return [
            'hidden' => ['hidden', 'text', "$t-hidden.example", false],
            'shared_hidden' => ['hidden', 'text', "$t-shared.example", false],
            'shared_open' => ['open', 'text', "$t-shared.example", false],
            'upper' => ['open', 'text', strtoupper("$t-shared.example"), false],
            'composite' => ['open', 'filename|md5', "$t.exe|" . md5($t), false],
            'deleted' => ['open', 'text', "$t-deleted.example", true],
            'object' => ['open', 'text', "$t-object.example", false],
        ];
    }

    /**
     * Committed, so that the FULLTEXT index holds the values; also one value
     * no attribute holds.
     *
     * @param array $fixture
     * @return void
     */
    private function intern(array $fixture)
    {
        $t = $this->t;
        $parts = ["$t-orphan.example", "$t-proposal.example", "$t-blocked.example", "$t-keyed.example", $this->ip()];
        foreach ($fixture as $spec) {
            foreach (explode('|', $spec[2]) as $part) {
                $parts[] = $part;
            }
        }
        $parts = array_values(array_unique($parts));
        $this->assertEmpty($this->values->idsOf($parts), 'A fixture value is already stored.');
        $this->valueIds = array_map('intval', $this->values->internMany($parts));
        $this->interned = array_values($this->valueIds);
    }

    /**
     * Attributes saved without correlating, inside the transaction.
     *
     * @param array $fixture
     * @return void
     */
    private function add(array $fixture)
    {
        foreach ($fixture as $name => $spec) {
            list($event, $type, $value, $deleted) = $spec;
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'event_id' => $this->events[$event],
                'category' => $this->attribute->typeDefinitions[$type]['default_category'],
                'type' => $type,
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 0,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, $name . json_encode($this->attribute->validationErrors));
            $this->ids[$name] = (int)$this->attribute->id;
            if ($deleted) {
                $this->exec(sprintf('UPDATE attributes SET deleted = 1 WHERE id = %d', $this->ids[$name]));
            }
        }
        $this->exec(sprintf(
            "INSERT INTO objects (name, `meta-category`, template_uuid, template_version, event_id, uuid, timestamp, distribution, comment, deleted) VALUES ('file', 'file', '%s', 1, %d, '%s', %d, 5, '', 0)",
            CakeText::uuid(),
            $this->events['open'],
            CakeText::uuid(),
            time()
        ));
        $this->exec(sprintf(
            'UPDATE attributes SET object_id = LAST_INSERT_ID() WHERE id = %d',
            $this->ids['object']
        ));
        $ids = implode(', ', $this->ids);
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = 'column-x', value2 = IF(value2 = '', '', 'column-x') WHERE id IN (%s)",
            $ids
        ));
        $this->hideTextColumns();
    }

    private function attributeModels()
    {
        $models = [spl_object_id($this->attribute) => $this->attribute];
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute) {
                $models[spl_object_id($object)] = $object;
            }
        }
        return $models;
    }

    private function hideTextColumns()
    {
        $property = new ReflectionProperty('Model', '_schema');
        foreach ($this->attributeModels() as $model) {
            $schema = $model->schema();
            unset($schema['value1'], $schema['value2']);
            $property->setValue($model, $schema);
        }
        $this->db->cacheMethods = false;
    }

    private function id($value)
    {
        return $this->valueIds[$value];
    }

    /**
     * A REST controller with the user signed in; what it would send is kept
     * in its RestResponse.
     *
     * @param array $user
     * @param array $query
     * @param array $named
     * @param array|null $post
     * @return ValuesController
     */
    private function controller(array $user, array $query = [], array $named = [], ?array $post = null)
    {
        $request = new CakeRequest(null, false);
        $request->query = $query;
        $request->params['named'] = $named;
        if ($post !== null) {
            $request->data = $post;
            $request->addDetector('post', ['callback' => function () {
                return true;
            }]);
        }
        $controller = new ValuesController($request, new CakeResponse());
        $controller->AttributeValue = $this->values;
        // As constructClasses() would from $uses
        $controller->modelClass = 'AttributeValue';
        $controller->Auth = new class($user) {
            private $user;

            public function __construct(array $user)
            {
                $this->user = $user;
            }

            public function user($key = null)
            {
                return $key === null ? $this->user : $this->user[$key];
            }
        };
        $controller->IndexFilter = new class {
            public function isRest()
            {
                return true;
            }
        };
        $controller->RestResponse = new class {
            public $sent;

            public function viewData($data, $format = false)
            {
                $this->sent = $data;
                return $data;
            }

            public function saveFailResponse($model, $action, $id, $errors)
            {
                return ['saved' => false, 'id' => $id, 'errors' => $errors];
            }

            public function saveSuccessResponse($model, $action, $id, $format, $message)
            {
                return ['saved' => true, 'id' => $id, 'message' => $message];
            }
        };
        $controller->CRUD = new CRUDComponent(new ComponentCollection());
        $controller->CRUD->initialize($controller);
        return $controller;
    }

    private function view(array $user, $id = null, array $query = [], array $named = [], ?array $post = null)
    {
        return $this->controller($user, $query, $named, $post)->view($id);
    }

    /**
     * @return string|null The message of the 404, null when the view answered.
     */
    private function missing(array $user, $id = null, array $query = [], array $named = [], ?array $post = null)
    {
        try {
            $this->view($user, $id, $query, $named, $post);
        } catch (NotFoundException $e) {
            $this->assertSame(404, $e->getCode());
            return $e->getMessage();
        }
        return null;
    }

    private function attributeIds(array $view)
    {
        $ids = array_map('intval', array_column($view['Attribute'], 'id'));
        sort($ids);
        return $ids;
    }

    private function ids(...$names)
    {
        $ids = [];
        foreach ($names as $name) {
            $ids[] = $this->ids[$name];
        }
        sort($ids);
        return $ids;
    }

    private function search(array $user, array $post)
    {
        $found = $this->controller($user, [], [], $post)->search();
        return array_column(array_column($found, 'Value'), 'value');
    }

    public function testAValueNoVisibleAttributeHoldsLooksLikeNoValue()
    {
        $t = $this->t;
        $hidden = "$t-hidden.example";
        $message = 'Invalid value.';

        $this->assertSame([$this->ids['hidden']], $this->attributeIds($this->view($this->admin, $this->id($hidden))));
        foreach ([
            'hidden by id' => [$this->id($hidden)],
            'hidden by sha256' => [null, [], ['sha256' => hash('sha256', $hidden)]],
            'hidden by text' => [null, ['value' => $hidden]],
            'hidden by posted text' => [null, [], [], ['value' => $hidden]],
            'held by a deleted attribute' => [$this->id("$t-deleted.example")],
            'held by nothing' => [$this->id("$t-orphan.example")],
            'not stored' => [max($this->interned) + 1000],
            'not stored, by text' => [null, ['value' => "$t-absent.example"]],
            'not an id' => ['1 OR 1=1'],
        ] as $case => $arguments) {
            $this->assertSame($message, $this->missing($this->lesser, ...$arguments), $case);
        }
        $this->assertSame($message, $this->missing($this->admin, max($this->interned) + 1000));
        $this->assertSame($message, $this->missing($this->admin, null, ['value' => "$t-absent.example"]));
    }

    public function testASiteAdminAlsoSeesAValueNothingVisibleHolds()
    {
        $t = $this->t;

        foreach (["$t-deleted.example", "$t-orphan.example"] as $value) {
            $view = $this->view($this->admin, null, ['value' => $value]);
            $this->assertSame(['id' => $this->id($value), 'value' => $value, 'sha256' => hash('sha256', $value), 'attribute_count' => 0], $view['Value']);
            $this->assertSame([], $view['Attribute']);
        }
    }

    public function testTheViewHoldsOnlyTheAttributesTheUserCanSee()
    {
        $shared = "{$this->t}-shared.example";

        $admin = $this->view($this->admin, $this->id($shared));
        $this->assertSame(2, $admin['Value']['attribute_count']);
        $this->assertSame($this->ids('shared_hidden', 'shared_open'), $this->attributeIds($admin));

        $lesser = $this->view($this->lesser, $this->id($shared));
        $this->assertSame([
            'id' => $this->id($shared),
            'value' => $shared,
            'sha256' => hash('sha256', $shared),
            'attribute_count' => 1,
        ], $lesser['Value']);
        $this->assertSame($this->ids('shared_open'), $this->attributeIds($lesser));
        $attribute = $lesser['Attribute'][0];
        $this->assertSame($shared, $attribute['value']);
        $this->assertArrayNotHasKey('value1', $attribute);
        $this->assertSame((string)$this->events['open'], (string)$attribute['Event']['id']);
        $this->assertArrayHasKey('Orgc', $attribute['Event']);
        $this->assertSame([], $attribute['Tag']);

        $this->assertSame($lesser, $this->view($this->lesser, null, ['value' => $shared]));
        $this->assertSame($lesser, $this->view($this->lesser, null, [], ['sha256' => strtoupper(hash('sha256', $shared))]));
        $this->assertSame($lesser, $this->view($this->lesser, null, [], [], ['value' => $shared]));
    }

    public function testAValueHeldAsValue2IsShownWithItsAttribute()
    {
        $md5 = md5($this->t);

        $view = $this->view($this->lesser, $this->id($md5));

        $this->assertSame($this->ids('composite'), $this->attributeIds($view));
        $this->assertSame("{$this->t}.exe|$md5", $view['Attribute'][0]['value']);
    }

    public function testAnObjectAttributeIsShownWithItsObject()
    {
        $view = $this->view($this->lesser, $this->id("{$this->t}-object.example"));

        $this->assertSame($this->ids('object'), $this->attributeIds($view));
        $this->assertSame('file', $view['Attribute'][0]['Object']['name']);
    }

    public function testTheTextIsMatchedByteForByte()
    {
        $shared = "{$this->t}-shared.example";

        $upper = $this->view($this->lesser, null, ['value' => strtoupper($shared)]);

        $this->assertSame($this->id(strtoupper($shared)), $upper['Value']['id']);
        $this->assertSame($this->ids('upper'), $this->attributeIds($upper));
    }

    public function testTheAttributesArePaged()
    {
        $shared = "{$this->t}-shared.example";
        $id = $this->id($shared);

        $first = $this->view($this->admin, $id, ['limit' => 1]);
        $second = $this->view($this->admin, $id, [], ['page' => 2, 'limit' => 1]);
        $past = $this->view($this->admin, $id, ['page' => 3, 'limit' => 1]);

        $this->assertSame(2, $first['Value']['attribute_count']);
        $this->assertSame([$this->ids['shared_open']], $this->attributeIds($first));
        $this->assertSame([$this->ids['shared_hidden']], $this->attributeIds($second));
        $this->assertSame([], $past['Attribute']);
        foreach ([['limit' => 0], ['limit' => 1001], ['page' => 0], ['page' => 'x']] as $paging) {
            try {
                $this->view($this->admin, $id, $paging);
                $this->fail('Accepted ' . json_encode($paging));
            } catch (BadRequestException $e) {
                $this->assertStringStartsWith('Invalid paging', $e->getMessage());
            }
        }
    }

    public function testASearchSpendsTheRoleSearchBudget()
    {
        App::uses('RateLimitComponent', 'Controller/Component');

        $this->assertArrayHasKey('search', RateLimitComponent::LIMITED_FUNCTIONS['values']);
    }

    public function testAViewNeedsAnAddress()
    {
        $this->expectException(BadRequestException::class);
        $this->view($this->admin);
    }

    public function testASearchListsOnlyValuesTheUserSeesAHolderOf()
    {
        $t = $this->t;
        $shared = "$t-shared.example";
        $upper = strtoupper($shared);

        $this->assertSame([$upper, "$t-hidden.example", "$t-object.example", $shared, "$t.exe"], $this->sorted($this->search($this->admin, ['value' => $t])));
        $this->assertSame([$upper, "$t-object.example", $shared, "$t.exe"], $this->sorted($this->search($this->lesser, ['value' => $t])));
        $this->assertSame([$upper, $shared], $this->sorted($this->search($this->lesser, ['value' => $shared, 'mode' => 'exact'])));
        $this->assertSame([], $this->search($this->lesser, ['value' => "$t-hidden.example", 'mode' => 'exact']));
        $this->assertSame([], $this->search($this->admin, ['value' => "$t-orphan.example", 'mode' => 'exact']));
        $this->assertSame([], $this->search($this->admin, ['value' => "$t-deleted.example", 'mode' => 'exact']));
        $this->assertSame([$upper, $shared], $this->sorted($this->search($this->lesser, ['value' => "%$t-sh%", 'mode' => 'like'])));
        $this->assertSame([md5($t)], $this->search($this->lesser, ['value' => md5($t)]));
    }

    public function testASearchIsPagedInIdOrder()
    {
        $t = $this->t;
        $expected = [];
        foreach (["$t-hidden.example", "$t-shared.example", strtoupper("$t-shared.example"), "$t.exe", "$t-object.example"] as $value) {
            $expected[$this->id($value)] = $value;
        }
        ksort($expected);
        $expected = array_values($expected);

        $pages = [];
        for ($page = 1; $page <= 4; $page++) {
            $pages[] = $this->search($this->admin, ['value' => $t, 'page' => $page, 'limit' => 2]);
        }

        $this->assertSame([array_slice($expected, 0, 2), array_slice($expected, 2, 2), array_slice($expected, 4), []], $pages);
    }

    public function testASearchRefusesAnInvalidRequest()
    {
        foreach ([
            'too broad' => [['value' => '%', 'mode' => 'like'], 'The search matches too many values, narrow it down.'],
            'unknown mode' => [['value' => $this->t, 'mode' => 'regex'], 'Invalid mode: use search, like or exact.'],
            'empty' => [['value' => ''], 'Give the text to search for as value.'],
            'not text' => [['value' => [$this->t]], 'Give the text to search for as value.'],
            'too long' => [['value' => str_repeat('a', AttributeValue::MAX_BYTES + 1)], 'Give the text to search for as value.'],
        ] as $case => list($post, $message)) {
            try {
                $this->search($this->admin, $post);
                $this->fail("Accepted: $case");
            } catch (BadRequestException $e) {
                $this->assertSame($message, $e->getMessage(), $case);
            }
        }
    }

    public function testVisibleValueIdsFollowsTheRulesOfTheAttributeFetch()
    {
        $t = $this->t;
        $all = array_values($this->valueIds);
        $expect = function (array $values) {
            $ids = [];
            foreach ($values as $value) {
                $ids[] = $this->id($value);
            }
            sort($ids);
            return $ids;
        };
        $md5 = md5($t);
        $openValues = ["$t-shared.example", strtoupper("$t-shared.example"), "$t.exe", $md5, "$t-object.example"];

        $this->assertSame($expect(array_merge($openValues, ["$t-hidden.example"])), $this->attribute->visibleValueIds($this->admin, $all, 100));
        $this->assertSame($expect($openValues), $this->attribute->visibleValueIds($this->lesser, $all, 100));
        $this->assertSame(array_slice($expect($openValues), 0, 2), $this->attribute->visibleValueIds($this->lesser, $all, 2));
        $this->assertSame([], $this->attribute->visibleValueIds($this->lesser, [], 10));

        // Past one chunk the lowest ids still come first, whatever the input order
        $first = $this->attribute->visibleValueIds($this->admin, range(1, 400), 1);
        $this->assertNotEmpty($first, 'Needs a stored value among the first ids.');
        $this->assertSame($first, $this->attribute->visibleValueIds($this->admin, range(1600, 1), 1));
    }

    /**
     * An address in the documentation range, made unique by the token.
     *
     * @return string
     */
    private function ip()
    {
        return '2001:db8:' . implode(':', str_split(substr($this->t, 2, 8), 4)) . '::7';
    }

    private function delete(array $user, $id)
    {
        return $this->controller($user, [], [], [])->delete($id);
    }

    private function countRows($sql)
    {
        return (int)$this->exec($sql)[0]['n'];
    }

    public function testOnlyASiteAdminMayDelete()
    {
        $acl = new ACLComponent(new ComponentCollection());

        $this->assertTrue($acl->checkAccess($this->admin, 'values', 'delete', false));
        $this->assertTrue($acl->checkAccess($this->lesser, 'values', 'view', false));
        $this->assertTrue($acl->checkAccess($this->lesser, 'values', 'search', false));
        $this->expectException(ForbiddenException::class);
        $acl->checkAccess($this->lesser, 'values', 'delete', false);
    }

    public function testADeleteNamesWhatStillRefersToTheValue()
    {
        $t = $this->t;
        $open = $this->events['open'];
        $eventUuid = $this->exec("SELECT uuid FROM events WHERE id = $open")[0]['uuid'];
        $this->exec(sprintf(
            "INSERT INTO shadow_attributes (event_id, type, category, uuid, org_id, event_org_id, comment, event_uuid, value1_id, deleted) VALUES (%d, 'text', 'Other', '%s', 1, 1, '', '%s', %d, 0)",
            $open,
            CakeText::uuid(),
            $eventUuid,
            $this->id("$t-proposal.example")
        ));
        $proposal = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        $this->exec(sprintf('INSERT INTO over_correlating_values (value_id, occurrence) VALUES (%d, 0)', $this->id("$t-blocked.example")));
        $this->exec(sprintf(
            'INSERT INTO no_acl_correlations (attribute_id, 1_attribute_id, event_id, 1_event_id, value_id) VALUES (%d, %d, %d, %d, %d)',
            $this->ids['shared_open'],
            $this->ids['upper'],
            $open,
            $open,
            $this->id("$t-keyed.example")
        ));
        $holders = [
            "$t-hidden.example" => sprintf('1 attributes: #%d in event %d', $this->ids['hidden'], $this->events['hidden']),
            "$t-deleted.example" => sprintf('1 attributes: #%d in event %d (soft-deleted)', $this->ids['deleted'], $open),
            md5($t) => sprintf('1 attributes: #%d in event %d', $this->ids['composite'], $open),
            "$t-proposal.example" => sprintf('1 proposals: #%d in event %d', $proposal, $open),
            "$t-blocked.example" => '1 over-correlation entries',
            "$t-keyed.example" => '1 correlations keyed on it (no ACL engine)',
        ];

        foreach ($holders as $value => $holder) {
            $id = $this->id($value);
            $this->assertSame([$holder], $this->values->holders($id), $value);
            $answer = $this->delete($this->admin, $id);
            $this->assertFalse($answer['saved'], $value);
            $this->assertSame("The value is still in use, remove these first: $holder.", $answer['errors'], $value);
            $this->assertFalse($this->values->deleteUnheld($id), $value);
            $this->assertSame([$id => $value], $this->values->fetchValues([$id]), $value);
        }
        $shared = $this->ids('shared_hidden', 'shared_open');
        $this->assertSame(
            [sprintf('2 attributes: #%d in event %d, 1 more', $shared[0], $shared[0] === $this->ids['shared_hidden'] ? $this->events['hidden'] : $open)],
            $this->values->holders($this->id("$t-shared.example"), 1)
        );
    }

    public function testAnUnheldValueIsDeletedWithItsFacetAndCountRows()
    {
        $id = $this->id($this->ip());
        $this->exec("INSERT INTO attr_value_counts (value_id, cnt_v1, cnt_v2) VALUES ($id, 0, 0)");
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) AS n FROM value_ip_ranges WHERE value_id = $id"));

        $answer = $this->delete($this->admin, $id);

        $this->assertTrue($answer['saved']);
        $this->assertSame([], $this->values->fetchValues([$id]));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) AS n FROM value_ip_ranges WHERE value_id = $id"));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) AS n FROM attr_value_counts WHERE value_id = $id"));
        $log = $this->exec("SELECT title, `change` FROM logs WHERE model = 'AttributeValue' AND model_id = $id AND action = 'delete'");
        $this->assertSame([['title' => "Value #$id deleted from the value dictionary", 'change' => '']], $log);
        $orphan = $this->id("{$this->t}-orphan.example");
        foreach ([$id, 'abc', '0', $orphan . 'x'] as $gone) {
            try {
                $this->delete($this->admin, $gone);
                $this->fail('Deleted ' . $gone);
            } catch (NotFoundException $e) {
                $this->assertSame(404, $e->getCode());
            }
        }
        $this->assertCount(1, $this->values->fetchValues([$orphan]));
    }

    private function sorted(array $values)
    {
        sort($values);
        return $values;
    }
}
