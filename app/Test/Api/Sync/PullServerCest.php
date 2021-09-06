<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\OrganisationFixture;
use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \WireMock\Client\WireMock;

class PullServerCest
{

    private const URL = '/servers/pull/%s/%s';

    public function testPullReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $serverId = 1;
        $technique = 'full';
        $I->sendGet(sprintf(self::URL, $serverId, $technique));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testPullCreatesJob(ApiTester $I): void
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
                'pull' => true,
                'url' => $I->getWireMockBaseUrl()
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
            'message' => 'string:regex(/^Pull queued for background execution. Job ID: [\d]$/)'
        ]);
        // TODO: Check job was created in Redis
    }

    public function testFullPullWithoutJobs(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $serverId = 1;
        $technique = 'full';
        $remoteOrgId = 2;
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId]);
        $fakeServer = ServerFixture::fake(
            [
                'id' => $serverId,
                'org_id' => $orgId,
                'remote_org_id' => $remoteOrgId,
                'pull' => true,
                'url' => $I->getWireMockBaseUrl()
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        $I->mockGetServerVersionRequest();

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
        $this->mockRemoteServerPullRequests($I->getWireMock(), $fakeEvent, $fakeAttribute);

        $I->sendGet(sprintf(self::URL, $serverId, $technique));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'message' => 'Pull completed. 1 events pulled, 0 events could not be pulled, 0 proposals pulled, 0 sightings pulled, 0 clusters pulled.'
            ]
        );
        $I->seeInDatabase('events', ['uuid' => $eventUuid]);
        $I->seeInDatabase('attributes', ['uuid' => $attributeUuid]);
    }

    private function mockRemoteServerPullRequests(
        WireMock $wiremock,
        EventFixture $event,
        AttributeFixture $attribute
    ): void {

        $wiremock->stubFor(WireMock::post(WireMock::urlEqualTo('/events/index'))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody((string)json_encode([$event->toResponse()]))));

        $wiremock->stubFor(
            WireMock::get(
                WireMock::urlMatching(sprintf('/events/view/%s/deleted.*', $event->toResponse()['uuid']))
            )->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody((string)json_encode(
                    [
                        'Event' => array_merge(
                            $event->toResponse(),
                            [
                                'Attribute' => $attribute->toResponse()
                            ]
                        )
                    ]
                )))
        );

        $wiremock->stubFor(
            WireMock::get(
                WireMock::urlMatching(
                    '/shadow_attributes/index/all.*'
                )
            )
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode('[]')))
        );
    }
}
