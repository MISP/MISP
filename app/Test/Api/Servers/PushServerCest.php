<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\OrganisationFixture;
use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \WireMock\Client\WireMock;

class PushServerCest
{

    private const URL = '/servers/push/%s/%s';

    public function testPushReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $serverId = 1;
        $technique = 'full';
        $I->sendGet(sprintf(self::URL, $serverId, $technique));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testPushCreatesJob(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '1');

        $serverId = 1;
        $technique = 'full';
        $remoteOrgId = 2;
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId]);
        $fakeServer = ServerFixture::fake(
            [
                'id' => $serverId,
                'org_id' => $orgId,
                'remote_org_id' => $remoteOrgId,
                'pull' => true
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        $I->sendGet(sprintf(self::URL, $serverId, $technique));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
            ]
        );

        $I->seeResponseMatchesJsonType([
            'message' => 'string:regex(/Push queued for background execution. Job ID: [\d]/)'
        ]);

        // TODO: Check job was created in Redis
    }

    public function testFullPushWithoutJobs(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0 --force');

        $serverId = 1;
        $technique = 'full';
        $remoteOrgId = 2;
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId]);
        $fakeServer = ServerFixture::fake(
            [
                'id' => $serverId,
                'org_id' => $orgId,
                'remote_org_id' => $remoteOrgId,
                'push' => true,
                'url' => 'http://wiremock:8080'
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        // $this->mockGetServerVersionRequest($I->getWireMock());

        $eventId = 1;
        $eventUuid = 'bb1fcb44-953a-4b76-acc9-98557ce69c66';
        $attributeUuid = 'f72597d9-481b-40e9-b3c9-842e2f80daf7';
        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'uuid' => $eventUuid,
                'org_id' => $remoteOrgId,
                'published' => true,
                'distribution' => '2'
            ]
        );
        $fakeAttribute = AttributeFixture::fake(
            [
                'uuid' => $attributeUuid,
                'event_id' => $eventId,
                'deleted' => false
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());
        $this->mockRemoteServerPushRequests($I->getWireMock(), $fakeEvent);

        $I->sendGet(sprintf(self::URL, $serverId, $technique));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'message' => 'Push complete. 1 events pushed, 0 events could not be pushed.'
            ]
        );
        $I->seeInDatabase('events', ['uuid' => $eventUuid]);
        $I->seeInDatabase('attributes', ['uuid' => $attributeUuid]);

        // reset setting
        $I->haveMispSetting('MISP.background_jobs', '1');
    }

    private function mockRemoteServerPushRequests(
        WireMock $wiremock,
        EventFixture $event
    ): void {

        $wiremock->stubFor(WireMock::post(WireMock::urlEqualTo('/events/filterEventIdsForPush'))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody(
                    (string)json_encode(
                        [$event->toResponse()['uuid']]
                    )
                )));

        $wiremock->stubFor(WireMock::post(WireMock::urlEqualTo('/events'))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody('{}')));
    }
}
