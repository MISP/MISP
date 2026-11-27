<?php
/**
 * MispQL statements run by MISP on a real database, compared with what the
 * table's own restSearch and queryDescribe answer. Reads only: users are
 * taken from the database and their roles adjusted in memory, and every
 * table needs a few rows the site admin can see.
 *
 * Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real
 * application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/MispQLRunDbTest.php
 */

use PHPUnit\Framework\TestCase;

class MispQLRunDbTest extends TestCase
{
    // table => controller, the models its queryDescribe reads, its argument
    const DESCRIBED = [
        'attributes' => ['AttributesController', ['MispAttribute'], null],
        'events' => ['EventsController', ['Event'], null],
        'objects' => ['ObjectsController', ['MispObject'], null],
        'galaxy_clusters' => ['GalaxyClustersController', ['GalaxyCluster'], null],
        'event_reports' => ['EventReportsController', ['EventReport'], null],
        'notes' => ['AnalystDataController', [], 'Note'],
        'opinions' => ['AnalystDataController', [], 'Opinion'],
        'relationships' => ['AnalystDataController', [], 'Relationship'],
        'collections' => ['CollectionsController', ['Collection'], null],
        'tags' => ['TagsController', ['Tag'], null],
        'organisations' => ['OrganisationsController', ['Organisation'], null],
    ];

    private static $booted = false;

    /** @var array */
    private $admin;

    /** @var array a user without site admin rights, allowed complex queries */
    private $lesser;

    /** @var mixed */
    private $hideOrganisations;

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
            App::uses('ClassRegistry', 'Utility');
            App::uses('ComponentCollection', 'Controller');
            App::uses('ACLComponent', 'Controller/Component');
            App::uses('RestSearchComponent', 'Controller/Component');
            App::uses('MispqlController', 'Controller');
            foreach (self::DESCRIBED as $described) {
                App::uses($described[0], 'Controller');
            }
            self::$booted = true;
        }
        $users = ClassRegistry::init('User');
        $this->admin = $users->getAuthUser(1);
        $lesser = $users->find('first', [
            'conditions' => ['User.disabled' => 0, 'Role.perm_site_admin' => 0],
            'contain' => ['Role'],
            'fields' => ['User.id'],
            'order' => 'User.id',
        ]);
        if (empty($this->admin['Role']['perm_site_admin']) || empty($lesser)) {
            $this->markTestSkipped('Needs user 1, a site admin, and a user without site admin rights.');
        }
        $this->lesser = $users->getAuthUser($lesser['User']['id']);
        $this->lesser['Role']['perm_complex_query'] = true;
        $this->hideOrganisations = Configure::read('Security.hide_organisation_index_from_users');
        // Read by the analyst data behaviours, as AppController::beforeFilter() sets it
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->admin['id']);
    }

    protected function tearDown(): void
    {
        if (self::$booted) {
            Configure::write('Security.hide_organisation_index_from_users', $this->hideOrganisations);
            Configure::write('CurrentUserId', $this->currentUserId);
        }
    }

    private function runner(array $user)
    {
        $controller = new MispqlController(new CakeRequest(null, false), new CakeResponse());
        $controller->User = ClassRegistry::init('User');
        $controller->RestSearch = new RestSearchComponent(new ComponentCollection());
        $runRestSearch = Closure::bind(function (...$arguments) {
            return $this->_runRestSearch(...$arguments);
        }, $controller, MispqlController::class);
        $tables = new MispQLTables([MispQLCakeBackend::class, 'orderFields']);
        $backend = new MispQLCakeBackend($user, $tables, new ACLComponent(new ComponentCollection()), $runRestSearch);
        return new MispQLRunner($tables, $backend);
    }

    private static function decoded($value)
    {
        return json_decode(json_encode($value), true);
    }

    /**
     * The rows the model's own restSearch returns for a body.
     */
    private function restSearchRows($model, array $user, array $body, $rowKey)
    {
        $query = $body['query'] ?? null;
        unset($body['query']);
        $count = 0;
        $view = false;
        $skipped = 0;
        $result = ClassRegistry::init($model)->restSearch(
            $user,
            $body['returnFormat'],
            $body,
            false,
            false,
            $count,
            $view,
            $skipped,
            $query
        );
        $reply = json_decode($result->intoString(), true);
        if (isset($reply['response'][$rowKey])) {
            return $reply['response'][$rowKey];
        }
        return array_map(function ($item) use ($rowKey) {
            return $item[$rowKey] + array_diff_key($item, [$rowKey => true]);
        }, $reply['response']);
    }

    public function testRowsAreTheRowsRestSearchReturns()
    {
        $statements = [
            'MispAttribute' => [
                "SELECT * FROM attributes WHERE type = 'ip-src' ORDER BY id DESC LIMIT 4 OFFSET 4",
                'Attribute',
            ],
            'Tag' => ["SELECT * FROM tags WHERE name LIKE 'tlp:%' ORDER BY name LIMIT 3", 'Tag'],
            'GalaxyCluster' => ['SELECT * FROM galaxy_clusters WHERE id > 0 LIMIT 2 OFFSET 2', 'GalaxyCluster'],
            'EventReport' => ['SELECT * FROM event_reports LIMIT 2', 'EventReport'],
            'Note' => ['SELECT * FROM notes LIMIT 2', 'Note'],
            'Collection' => ['SELECT * FROM collections LIMIT 2', 'Collection'],
            'Organisation' => ['SELECT * FROM organisations ORDER BY name DESC LIMIT 3', 'Organisation'],
            'MispObject' => ["SELECT * FROM objects WHERE object_name = 'file' LIMIT 2", 'Object'],
        ];
        $runner = $this->runner($this->admin);
        foreach ($statements as $model => list($statement, $rowKey)) {
            $reply = $runner->run($statement);
            $expected = $this->restSearchRows($model, $this->admin, $reply['request']['body'], $rowKey);
            $this->assertNotEmpty($expected, "$statement: nothing to compare");
            $this->assertSame($expected, self::decoded($reply['rows']), $statement);
            $this->assertNull($reply['total'], $statement);
            $this->assertSame(array_fill(0, count($expected), $rowKey), array_column($reply['records'], 'type'));
            $this->assertSame(array_map('strval', array_column($expected, 'id')), array_column($reply['records'], 'id'));
            if ($rowKey !== 'Tag') {
                $this->assertSame(array_column($expected, 'uuid'), array_column($reply['records'], 'uuid'), $statement);
            }
        }
    }

    public function testEventColumnsAndTotal()
    {
        $reply = $this->runner($this->admin)
            ->run('SELECT id, info, org FROM events WHERE id > 100 ORDER BY id LIMIT 3');
        $expected = $this->restSearchRows('Event', $this->admin, $reply['request']['body'], 'Event');
        $this->assertCount(3, $expected);
        $this->assertSame(1, $reply['request']['body']['metadata']);
        $this->assertSame(['id', 'info', 'Orgc.name'], $reply['columns']);
        $this->assertSame(array_map(function ($event) {
            return ['id' => $event['id'], 'info' => $event['info'], 'Orgc.name' => $event['Orgc']['name']];
        }, $expected), self::decoded($reply['rows']));
        $this->assertSame(array_map(function ($event) {
            return ['type' => 'Event', 'id' => $event['id'], 'uuid' => $event['uuid'], 'label' => $event['info']];
        }, $expected), $reply['records']);
        $events = ClassRegistry::init('Event')->find('count', ['conditions' => ['Event.id >' => 100]]);
        $this->assertSame($events, $reply['total']);
    }

    public function testCounts()
    {
        $runner = $this->runner($this->admin);
        $events = ClassRegistry::init('Event')->find('count', ['conditions' => ['Event.id >' => 100]]);
        $this->assertSame($events, $runner->run('SELECT COUNT(*) FROM events WHERE id > 100')['count']);
        $tags = ClassRegistry::init('Tag')->find('count', ['conditions' => ['Tag.name LIKE' => 'tlp:%']]);
        $this->assertSame($tags, $runner->run("SELECT COUNT(*) FROM tags WHERE name LIKE 'tlp:%'")['count']);
        $reply = $runner->run("SELECT COUNT(*) FROM attributes WHERE type = 'ip-src' AND id > 0 AND id < 2000");
        $this->assertIsInt($reply['count']);
    }

    public function testDescribeIsWhatEachTableDescribes()
    {
        $runner = $this->runner($this->admin);
        $tables = new MispQLTables([MispQLCakeBackend::class, 'orderFields']);
        foreach (self::DESCRIBED as $table => list($class, $models, $argument)) {
            $described = $this->queryDescribe($class, $models, $argument);
            $reply = self::decoded($runner->run("DESCRIBE $table"));
            foreach ($reply['fields'] as $name => $field) {
                $this->assertNotEmpty($field['description'] ?? null, "$table.$name says what it means");
                unset($reply['fields'][$name]['description']);
            }
            $this->assertSame($described['tables'][$table]['fields'], $reply['fields'], $table);
            $this->assertSame($described['limits'], $reply['limits'], $table);
            $sortable = $described['tables'][$table]['sortable'];
            foreach ($tables->sortable($table) as $name => $target) {
                $this->assertContains($target, $sortable, "$table: $name");
            }
        }
    }

    /**
     * @return array what the controller's queryDescribe action sends
     */
    private function queryDescribe($class, array $models, $argument)
    {
        $controller = new $class(new CakeRequest(null, false), new CakeResponse());
        foreach ($models as $model) {
            $controller->$model = ClassRegistry::init($model);
        }
        $user = $this->admin;
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
            public function viewData($data, $format = false)
            {
                return $data;
            }
        };
        return self::decoded($argument === null ? $controller->queryDescribe() : $controller->queryDescribe($argument));
    }

    public function testErrorsFromTheTablesValidators()
    {
        $runner = $this->runner($this->admin);
        $statement = "SELECT * FROM events WHERE colour = 'x' AND id = 'seven' LIMIT 1";
        try {
            $runner->run($statement);
            $this->fail('the statement ran');
        } catch (MispQLErrors $e) {
            $this->assertSame(
                [
                    ['unknown_field', 'colour', 'query.AND[0].<unknown>'],
                    ['bad_type', "id = 'seven'", 'query.AND[1].id'],
                ],
                array_map(function ($error) use ($statement) {
                    $fragment = mb_substr($statement, $error['start'], $error['end'] - $error['start']);
                    return [$error['code'], $fragment, $error['path']];
                }, $e->errors)
            );
        }
        $explained = $runner->explain(
            "SELECT * FROM tags WHERE id = 1 LIMIT 1; USE other; SELECT * FROM tags WHERE colour = 'x' LIMIT 1"
        );
        $this->assertSame([true, true, false], array_column($explained['statements'], 'validated'));
    }

    public function testMispFormatsComeBackAsRestSearchRanThem()
    {
        $reply = $this->runner($this->admin)->run("SELECT * FROM attributes WHERE type = 'domain' LIMIT 2 FORMAT csv");
        $this->assertSame(['export', 'Attribute'], [$reply['kind'], $reply['scope']]);
        $this->assertSame(['csv', 'csv'], [$reply['run']['returnFormat'], $reply['run']['responseType']]);
        $this->assertStringStartsWith('uuid,event_id,', $reply['run']['result']->intoString());
    }

    public function testTheRoleLimitIsAppliedAndReported()
    {
        $user = $this->lesser;
        $user['Role']['restsearch_limit_result'] = 30;
        $runner = $this->runner($user);
        // Divided for objects and events, as on their own controllers
        foreach (['attributes' => 30, 'objects' => 10, 'events' => 3] as $table => $allowed) {
            $reply = $runner->run("SELECT id FROM $table WHERE id > 0");
            $this->assertCount($allowed, $reply['rows'], $table);
            $this->assertSame(
                ["the role's restSearch limit stopped this search at $allowed rows"],
                $reply['warnings'],
                $table
            );
        }
        $this->assertSame([], $runner->run('SELECT id FROM attributes WHERE id > 0 LIMIT 5')['warnings']);
    }

    public function testTheEndpointsAndEachTableKeepTheirAcl()
    {
        $acl = new ACLComponent(new ComponentCollection());
        $this->assertTrue($acl->checkAccess($this->lesser, 'mispql', 'run', false));
        $without = $this->lesser;
        $without['Role']['perm_complex_query'] = false;
        foreach (['run', 'explain'] as $action) {
            try {
                $acl->checkAccess($without, 'mispql', $action, false);
                $this->fail("$action allowed without perm_complex_query");
            } catch (ForbiddenException $e) {
            }
        }

        Configure::write('Security.hide_organisation_index_from_users', true);
        $user = $this->lesser;
        $user['Role']['perm_sharing_group'] = false;
        $runner = $this->runner($user);
        $this->assertNotContains('organisations', $runner->run('SHOW TABLES')['tables']);
        $this->assertContains('attributes', $runner->run('SHOW TABLES')['tables']);
        $refused = [
            'SELECT * FROM organisations LIMIT 1',
            'SELECT COUNT(*) FROM organisations WHERE id > 0',
            'DESCRIBE organisations',
        ];
        foreach ($refused as $statement) {
            try {
                $runner->run($statement);
                $this->fail("$statement ran");
            } catch (ForbiddenException $e) {
            }
        }
        $user['Role']['perm_sharing_group'] = true;
        $this->assertCount(1, $this->runner($user)->run('SELECT * FROM organisations LIMIT 1')['rows']);
    }

    public function testWhoami()
    {
        $this->assertSame(
            [
                'email' => $this->lesser['email'],
                'role' => $this->lesser['Role']['name'],
                'org' => $this->lesser['Organisation']['name'],
            ],
            array_intersect_key($this->runner($this->lesser)->run('WHOAMI'), array_flip(['email', 'role', 'org']))
        );
    }
}
