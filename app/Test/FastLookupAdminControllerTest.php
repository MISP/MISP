<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupAdminControllerTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupAdminControllerStubs.php';
    }

    public function testDashboardReadsMetricsOnlyWhenRequestedAndNeverChangesIndex(): void
    {
        $this->assertTrue(method_exists(ServersController::class, 'fastLookup'));
        $controller = new ServersController();
        $controller->request = new FastLookupControllerRequest();
        $controller->request->method = 'GET';
        $controller->request->query = [];
        $controller->fastLookup();
        $this->assertSame([false], FastLookupIndexManager::$metrics);
        $controller->request->query = ['metrics' => '1'];
        $controller->fastLookup();
        $this->assertSame([false, true], FastLookupIndexManager::$metrics);
    }

    public function testDashboardRejectsNonAdmin(): void
    {
        $this->assertTrue(method_exists(ServersController::class, 'fastLookup'));
        $controller = new ServersController();
        $controller->admin = false;
        $controller->request = new FastLookupControllerRequest();
        $controller->request->method = 'GET';
        $this->expectException(ForbiddenException::class);
        $controller->fastLookup();
    }

    public function testRebuildRejectsGetBeforeSchedulingWork(): void
    {
        $this->assertTrue(method_exists(ServersController::class, 'rebuildFastLookup'));
        $controller = new ServersController();
        $controller->request = new FastLookupControllerRequest();
        $controller->request->method = 'GET';
        $this->expectException(MethodNotAllowedException::class);
        $controller->rebuildFastLookup();
    }

    public function testDisabledBackgroundJobsProvideCliInstructionWithoutBlockingRequest(): void
    {
        $this->assertTrue(method_exists(ServersController::class, 'rebuildFastLookup'));
        $controller = new ServersController();
        $controller->request = new FastLookupControllerRequest();
        $controller->request->data = [];
        $response = $controller->rebuildFastLookup();
        $this->assertSame(409, $response->statusCode());
        $body = json_decode($response->body(), true);
        $this->assertStringContainsString('Admin rebuildFastLookup', $body['message']);
        $this->assertSame('no-store', $response->headers['Cache-Control']);
    }

    /** @dataProvider adminRepresentations */
    public function testInvalidConfigurationKeepsDashboardAndPollingAvailable($rest): void
    {
        Configure::write('MISP.fast_lookup_max_values', 0);
        Configure::write('MISP.fast_lookup_attribute_types', 'domain');
        $controller = $this->controller('GET');
        $controller->rest = $rest;
        try {
            $response = $controller->fastLookup();
        } catch (InvalidArgumentException $e) {
            $this->fail('Configuration errors must be shown by the admin dashboard: ' . $e->getMessage());
        }
        $body = $rest ? json_decode($response->body(), true) : $controller->viewVars['lookupStatus'];
        $this->assertSame('error', $body['status']);
        $this->assertSame(['domain'], $body['scope']['attribute_types']);
        $this->assertFalse($body['scope']['configuration_valid']);
        $this->assertNull($body['scope']['max_values']);
        $this->assertStringContainsString('positive integer', $body['message']);
        if ($rest) { $this->assertSame(200, $response->statusCode()); }
    }

    public function adminRepresentations(): array { return [[true], [false]]; }

    /** @dataProvider queuedModes */
    public function testEnabledJobsQueueTheSelectedCommandWithTheCreatedJobId($data, $command): void
    {
        Configure::write('MISP.background_jobs', true);
        $controller = $this->controller('POST');
        $controller->request->data = $data;
        $response = $controller->rebuildFastLookup();
        $this->assertSame(202, $response->statusCode());
        $this->assertSame(47, json_decode($response->body(), true)['job_id']);
        $this->assertSame([['default', 'admin', [$command, 47], true, 47]], $controller->Server->queue->calls);
        $this->assertSame($controller->Auth->user(), $controller->Job->created[0][0]);
        $this->assertSame('no-store', $response->headers['Cache-Control']);
    }

    public function queuedModes(): array
    {
        return [[[], 'rebuildFastLookup'], [['mode' => 'resume'], 'resumeFastLookup'], [['Server' => ['mode' => 'rebuild']], 'rebuildFastLookup']];
    }

    public function testQueueFailureMarksTheCreatedJobFailed(): void
    {
        Configure::write('MISP.background_jobs', true);
        $controller = $this->controller('POST');
        $controller->request->data = ['mode' => 'resume'];
        $controller->Server->queue->exception = new RuntimeException('Queue unavailable');
        try {
            $controller->rebuildFastLookup();
            $this->fail('Queue failure must not produce a success response.');
        } catch (RuntimeException $e) {
            $this->assertSame('Queue unavailable', $e->getMessage());
        }
        $this->assertSame([[47, false, 'Could not queue fast lookup backfill.']], $controller->Job->statuses);
    }

    public function testRebuildRejectsNonAdminBeforeCreatingAJob(): void
    {
        Configure::write('MISP.background_jobs', true);
        $controller = $this->controller('POST');
        $controller->admin = false;
        try {
            $controller->rebuildFastLookup();
            $this->fail('Non-admin rebuild must be forbidden.');
        } catch (ForbiddenException $e) {
            $this->assertNull($controller->Job);
            $this->assertSame([], $controller->Server->queue->calls);
        }
    }

    private function controller($method): ServersController
    {
        $controller = new ServersController();
        $controller->request = new FastLookupControllerRequest();
        $controller->request->method = $method;
        $controller->response = new CakeResponse();
        $controller->Server = new FastLookupAdminServer();
        $controller->Auth = new class {
            public function user() { return ['id' => '7', 'org_id' => '3', 'Role' => ['perm_site_admin' => true]]; }
        };
        return $controller;
    }
}
