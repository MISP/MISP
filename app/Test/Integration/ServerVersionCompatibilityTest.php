<?php

require_once __DIR__ . '/IntegrationTestCase.php';

App::uses('ServerSyncTool', 'Tools');
App::uses('HttpSocketExtended', 'Tools');
// HttpSocketHttpException is declared inside HttpSocketExtended.php, so the
// autoloader never fires for its own name. Touch the class that IS mapped to
// that file to pull both declarations in.
class_exists('HttpSocketExtended');

/**
 * Characterization of Server::checkVersionCompatibility().
 *
 * This is the gate every sync passes through: it decides whether a push or a
 * pull may run at all, and what the remote instance is permitted to do. It is
 * also the one method in the whole sync path that is already injectable -
 * Server.php:3254 accepts an optional ServerSyncTool - so its version
 * comparison ladder can be driven without a remote instance and without any
 * change to production code.
 *
 * Expectations are derived from checkMISPVersion() at runtime rather than
 * hardcoded, so this file does not need editing every release.
 */
class ServerVersionCompatibilityTest extends IntegrationTestCase
{
    /** @var int|null */
    private $serverId;

    protected function setUp(): void
    {
        parent::setUp();
        $serverModel = $this->model('Server');
        $serverModel->create();
        $saved = $serverModel->save([
            'Server' => [
                'name' => 'checkVersionCompatibility fixture',
                'url' => 'https://sync.invalid',
                'authkey' => str_repeat('a', 40),
                'org_id' => 1,
                'remote_org_id' => 1,
                'push' => 0,
                'pull' => 0,
                // servers has several NOT NULL columns with no DB default;
                // omitting any of them makes save() fail with a 1364.
                'self_signed' => 0,
                'pull_rules' => '',
                'push_rules' => '',
            ],
        ]);
        $this->assertNotEmpty($saved, 'could not create the fixture server');
        $this->serverId = (int)$serverModel->id;
    }

    protected function tearDown(): void
    {
        if ($this->serverId) {
            try {
                $this->model('Server')->delete($this->serverId);
            } catch (\Throwable $e) {
                // Best effort: a test must not fail during cleanup.
            }
            $this->serverId = null;
        }
        parent::tearDown();
    }

    private function server(): array
    {
        return $this->model('Server')->find('first', [
            'recursive' => -1,
            'conditions' => ['Server.id' => $this->serverId],
        ]);
    }

    private function localVersion(): array
    {
        return $this->model('Server')->checkMISPVersion();
    }

    /** Run the check against a remote advertising $info. */
    private function check(array $info): array
    {
        return $this->model('Server')->checkVersionCompatibility(
            $this->server(),
            $this->adminUser(),
            new FakeServerSync($info)
        );
    }

    /** Build a remote getVersion payload offset from the local version. */
    private function remoteInfo(int $majorDelta, int $minorDelta, int $hotfixDelta, array $extra = []): array
    {
        $local = $this->localVersion();
        return array_merge([
            'version' => sprintf(
                '%d.%d.%d',
                $local['major'] + $majorDelta,
                $local['minor'] + $minorDelta,
                $local['hotfix'] + $hotfixDelta
            ),
        ], $extra);
    }

    // ------------------------------------------------------- the happy path

    public function testIdenticalVersionsSyncCleanly(): void
    {
        $result = $this->check($this->remoteInfo(0, 0, 0));
        $this->assertTrue($result['success']);
        $this->assertFalse($result['response'], 'an exact version match produces no message');
    }

    public function testCapabilityFlagsAreTakenFromTheRemotePayload(): void
    {
        $result = $this->check($this->remoteInfo(0, 0, 0, [
            'perm_sync' => true,
            'perm_sighting' => true,
            'perm_galaxy_editor' => true,
            'perm_analyst_data' => true,
        ]));
        $this->assertTrue($result['canPush']);
        $this->assertTrue($result['canSight']);
        $this->assertTrue($result['canEditGalaxyCluster']);
        $this->assertTrue($result['canEditAnalystData']);
    }

    public function testMissingCapabilityFlagsDefaultToFalse(): void
    {
        $result = $this->check($this->remoteInfo(0, 0, 0));
        $this->assertFalse($result['canPush'], 'absent perm_sync must not be read as permission');
        $this->assertFalse($result['canSight']);
        $this->assertFalse($result['canEditGalaxyCluster']);
        $this->assertFalse($result['canEditAnalystData']);
    }

    // ------------------------------------------------- the comparison ladder

    public function testRemoteBehindByAMajorVersionAbortsSync(): void
    {
        $result = $this->check($this->remoteInfo(-1, 0, 0));
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('behind by a major version', $result['response']);
    }

    public function testRemoteAheadByAMajorVersionAbortsSync(): void
    {
        $result = $this->check($this->remoteInfo(1, 0, 0));
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('full major version ahead', $result['response']);
    }

    public function testRemoteBehindByAMinorVersionAbortsSync(): void
    {
        $result = $this->check($this->remoteInfo(0, -1, 0));
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('behind by a minor version', $result['response']);
    }

    public function testRemoteAheadByAMinorVersionAbortsSync(): void
    {
        $result = $this->check($this->remoteInfo(0, 1, 0));
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('full minor version ahead', $result['response']);
    }

    public function testAHotfixGapStillSucceedsButWarns(): void
    {
        // The hotfix comparisons run only after $success has already been set
        // to true, so a hotfix gap reports a message AND success.
        $result = $this->check($this->remoteInfo(0, 0, -1));
        $this->assertTrue($result['success'], 'a hotfix gap must not block sync');
        $this->assertStringContainsString('a few hotfixes behind', $result['response']);
    }

    public function testRemoteAheadByAHotfixSucceedsButWarns(): void
    {
        $result = $this->check($this->remoteInfo(0, 0, 1));
        $this->assertTrue($result['success']);
        $this->assertStringContainsString('a few hotfixes ahead', $result['response']);
    }

    public function testMajorMismatchWinsOverMinorMismatch(): void
    {
        // Each comparison is guarded by `$response === false`, so the first
        // one to match is the one reported.
        $result = $this->check($this->remoteInfo(-1, -1, 0));
        $this->assertStringContainsString('behind by a major version', $result['response']);
        $this->assertStringNotContainsString('minor', $result['response']);
    }

    // -------------------------------------------------------- protectedMode

    public function testProtectedModeIsOnFromTwoFourOneFiftySix(): void
    {
        $this->assertTrue($this->check(['version' => '2.4.156'])['protectedMode']);
        $this->assertTrue($this->check($this->remoteInfo(0, 0, 0))['protectedMode']);
    }

    public function testProtectedModeIsOffBelowTwoFourOneFiftySix(): void
    {
        $this->assertFalse($this->check(['version' => '2.4.155'])['protectedMode']);
    }

    public function testAncientRemoteIsToldProposalsNeedTwoFourOneEleven(): void
    {
        // Reached only when nothing above matched, which needs the local major
        // and minor to be 2.4 - skip rather than lie about coverage otherwise.
        $local = $this->localVersion();
        if ((int)$local['major'] !== 2 || (int)$local['minor'] !== 4) {
            $this->markTestSkipped('the 2.4.111 proposals branch is only reachable from a 2.4.x local version');
        }
        $result = $this->check(['version' => '2.4.110']);
        $this->assertStringContainsString('2.4.111 is required', $result['response']);
    }

    // ------------------------------------------------------------- failures

    /**
     * HttpSocketHttpException takes a response object, not a message - it
     * derives both its message and its code from the response. Build the
     * smallest thing that satisfies it.
     */
    private static function httpError(int $code): HttpSocketHttpException
    {
        $response = new HttpSocketResponseExtended();
        $response->code = $code;
        $response->body = '';
        return new HttpSocketHttpException($response, 'https://sync.invalid/servers/getVersion');
    }

    public function testAnHttpErrorReportsTheResponseCode(): void
    {
        $result = $this->model('Server')->checkVersionCompatibility(
            $this->server(),
            $this->adminUser(),
            new FakeServerSync(self::httpError(403))
        );
        $this->assertIsString($result, 'a failed connection returns the message, not the result array');
        $this->assertStringContainsString('Returned response code: 403', $result);
    }

    public function testANonHttpErrorReportsTheExceptionMessage(): void
    {
        $result = $this->model('Server')->checkVersionCompatibility(
            $this->server(),
            $this->adminUser(),
            new FakeServerSync(new Exception('name resolution failed'))
        );
        $this->assertIsString($result);
        $this->assertStringContainsString('name resolution failed', $result);
    }

    /**
     * KNOWN-DEFECT: the guard for a malformed remote response is
     *
     *   $remoteVersion = explode('.', $remoteVersion['version']);
     *   if (!isset($remoteVersion[0])) { ... }
     *
     * explode() always returns at least one element, so index 0 is always set
     * and this branch is unreachable. A remote answering with a version of
     * '2' therefore falls through to the comparison ladder, where indexes 1
     * and 2 do not exist. Under PHP 8 that is an undefined-array-key warning
     * and a null comparison, not the intended clean error message.
     *
     * The test asserts the branch is dead rather than that the outcome is
     * good: it records that a truncated version is NOT reported as a bad
     * response, which is exactly what a fix would change.
     */
    public function testTheMalformedVersionGuardIsUnreachable(): void
    {
        $result = @$this->check(['version' => '2']);
        $this->assertIsArray(
            $result,
            'if this is now a string the malformed-response guard has been made reachable - good, ' .
            'but the callers that expect an array on a bad version need checking'
        );
        $this->assertSame(['2'], $result['version'], 'the version is passed through unsplit');
    }

    public function testTheEmptyVersionStringIsAlsoNotCaught(): void
    {
        $result = @$this->check(['version' => '']);
        $this->assertIsArray($result, 'explode on an empty string still yields index 0');
    }
}

/**
 * ServerSyncTool with the HTTP layer removed. The constructor is deliberately
 * NOT called, so no socket is ever built; info() replays the injected payload,
 * or throws the injected Throwable.
 */
class FakeServerSync extends ServerSyncTool
{
    /** @var array|Throwable */
    private $injected;

    public function __construct($injected)
    {
        $this->injected = $injected;
    }

    public function info()
    {
        if ($this->injected instanceof Throwable) {
            throw $this->injected;
        }
        return $this->injected;
    }
}
