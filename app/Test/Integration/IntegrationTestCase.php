<?php

use PHPUnit\Framework\TestCase;

/**
 * Base for layer-2 tests: real CakePHP models against the real database.
 *
 * Layer 2 exists for behaviour that needs model internals AND cannot be
 * asserted over HTTP - the correlation strategies agreeing with each other
 * being the motivating case. Anything assertable over HTTP belongs in the
 * live Python suite instead.
 *
 * Each test records the events it creates and removes them in tearDown, so a
 * failing test cannot leave state that breaks the next one. (The live suite
 * learned that lesson the hard way.)
 */
abstract class IntegrationTestCase extends TestCase
{
    /** @var array<int,int> event ids created by the running test */
    protected $createdEventIds = [];

    public static function setUpBeforeClass(): void
    {
        if (!class_exists('ClassRegistry')) {
            self::markTestSkipped('CakePHP was not bootstrapped; run with phpunit-integration.xml');
        }
    }

    protected function setUp(): void
    {
        // AnalystDataParentBehavior resolves the acting user from
        // Configure::read('CurrentUserId') and fatals if it is unset (see
        // EventFetchCharacterizationTest::testAnalystDataWithoutCurrentUserId).
        // A web request sets it; a test, a shell and a worker do not. Set it
        // so tests exercise the normal authenticated path.
        Configure::write('CurrentUserId', 1);
        try {
            $this->model('Event')->find('count');
        } catch (\Throwable $e) {
            $this->markTestSkipped('no usable database connection: ' . $e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->createdEventIds) as $eventId) {
            try {
                $this->model('Event')->delete($eventId);
            } catch (\Throwable $e) {
                // Best effort: a test must not fail during cleanup.
            }
        }
        $this->createdEventIds = [];
    }

    /**
     * Register an event created outside createEvent() - e.g. by _add() under
     * test - so tearDown still removes it.
     */
    protected function trackEvent(int $eventId): int
    {
        $this->createdEventIds[] = $eventId;
        return $eventId;
    }

    protected function model(string $name)
    {
        return ClassRegistry::init($name);
    }

    /** The site-admin user array MISP's model layer expects. */
    protected function adminUser(): array
    {
        $user = $this->model('User')->find('first', [
            'recursive' => -1,
            'conditions' => ['User.id' => 1],
            'contain' => false,
        ]);
        if (empty($user)) {
            $this->markTestSkipped('no user with id 1 on this instance');
        }
        $user = $user['User'];
        $user['Role'] = $this->model('Role')->find('first', [
            'recursive' => -1,
            'conditions' => ['Role.id' => $user['role_id']],
        ])['Role'] ?? ['perm_site_admin' => 1];
        $user['Organisation'] = $this->model('Organisation')->find('first', [
            'recursive' => -1,
            'conditions' => ['Organisation.id' => $user['org_id']],
        ])['Organisation'] ?? ['id' => $user['org_id'], 'name' => 'ORGNAME'];
        return $user;
    }

    /**
     * Create an event carrying the given attribute values, and register it
     * for cleanup.
     *
     * @param array<int,array{type:string,value:string}> $attributes
     */
    protected function createEvent(string $info, array $attributes): int
    {
        $eventModel = $this->model('Event');
        $eventModel->create();
        $saved = $eventModel->save([
            'Event' => [
                'info' => $info,
                'date' => date('Y-m-d'),
                'analysis' => 0,
                'threat_level_id' => 1,
                'distribution' => 3,
                'org_id' => 1,
                'orgc_id' => 1,
                'user_id' => 1,
                'uuid' => CakeText::uuid(),
                'published' => false,
            ],
        ]);
        $this->assertNotEmpty($saved, "could not create the fixture event '$info'");
        $eventId = (int)$eventModel->id;
        $this->createdEventIds[] = $eventId;

        $attributeModel = $this->model('MispAttribute');
        foreach ($attributes as $attribute) {
            $attributeModel->create();
            $ok = $attributeModel->save([
                'Attribute' => [
                    'event_id' => $eventId,
                    'category' => $attribute['category'] ?? 'Network activity',
                    'type' => $attribute['type'],
                    'value' => $attribute['value'],
                    'to_ids' => 1,
                    'distribution' => 5,
                    'uuid' => CakeText::uuid(),
                ],
            ]);
            $this->assertNotEmpty($ok, "could not create attribute {$attribute['value']}");
        }

        return $eventId;
    }
}
