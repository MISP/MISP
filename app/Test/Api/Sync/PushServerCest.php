<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\OrganisationFixture;
use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use Helper\Fixture\Data\SharingGroupFixture;
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
            'message' => 'string:regex(/^Push queued for background execution. Job ID: [\d]+$/)'
        ]);

        // TODO: Check job was created in Redis
    }

    public function testFullPushWithoutJobs(ApiTester $I): void
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
                'push' => true,
                'url' => $I->getWireMockBaseUrl()
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        $eventId = 1;
        $eventUuid = 'bb1fcb44-953a-4b76-acc9-98557ce69c66';
        $attributeUuid = 'f72597d9-481b-40e9-b3c9-842e2f80daf7';
        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'uuid' => $eventUuid,
                'org_id' => $remoteOrgId,
                'published' => true,
                'distribution' => '2',
                'locked' => 1
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

        $I->mockGetServerVersionRequest();
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
                // 'message' => 'Server pushed'
            ]
        );
        $I->seeInDatabase('events', ['uuid' => $eventUuid]);
        $I->seeInDatabase('attributes', ['uuid' => $attributeUuid]);
    }

    public function testServerInSharingGroupFullPushWithoutJobs(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $serverId = 1;
        $technique = 'full';
        $remoteOrgId = 2;
        $orgUuid = '28601831-466d-4031-849d-147f31e7fb27';
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId, 'uuid' => $orgUuid]);
        $fakeServer = ServerFixture::fake(
            [
                'id' => $serverId,
                'org_id' => $orgId,
                'remote_org_id' => $remoteOrgId,
                'push' => true,
                'url' => $I->getWireMockBaseUrl(),
                'internal' => true
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        $eventId = 1;
        $eventUuid = 'bb1fcb44-953a-4b76-acc9-98557ce69c66';
        $attributeUuid = 'f72597d9-481b-40e9-b3c9-842e2f80daf7';
        $sharingGroupId = 1;

        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => $sharingGroupId,
                'org_id' => $orgId,
                'active' => true,
                'roaming' => false
            ]
        );
        $I->haveInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());
        $I->haveInDatabase(
            'sharing_group_servers',
            [
                'sharing_group_id' => $sharingGroupId,
                'server_id' => $serverId,
                'all_orgs' => 0
            ]
        );
        $I->haveInDatabase(
            'sharing_group_orgs',
            [
                'sharing_group_id' => $sharingGroupId,
                'org_id' => $remoteOrgId,
                'extend' => 0
            ]
        );

        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'uuid' => $eventUuid,
                'org_id' => $remoteOrgId,
                'published' => true,
                'distribution' => '4',
                'sharing_group_id' => $sharingGroupId
            ]
        );
        $fakeAttribute = AttributeFixture::fake(
            [
                'uuid' => $attributeUuid,
                'event_id' => $eventId,
                'deleted' => false,
                'distribution' => '4'
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->mockGetServerVersionRequest();
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
    }

    public function testServerNotInSharingGroupSameOrgUuidFullPushWithoutJobs(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $serverId = 1;
        $technique = 'full';
        $remoteOrgId = 2;
        $orgUuid = '28601831-466d-4031-849d-147f31e7fb27';
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId, 'uuid' => $orgUuid]);
        $fakeServer = ServerFixture::fake(
            [
                'id' => $serverId,
                'org_id' => $orgId,
                'remote_org_id' => $remoteOrgId,
                'push' => true,
                'url' => $I->getWireMockBaseUrl(),
                'internal' => true
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        $eventId = 1;
        $eventUuid = 'bb1fcb44-953a-4b76-acc9-98557ce69c66';
        $attributeUuid = 'f72597d9-481b-40e9-b3c9-842e2f80daf7';
        $sharingGroupId = 1;

        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => $sharingGroupId,
                'org_id' => $orgId,
                'active' => true,
                'roaming' => false
            ]
        );
        $I->haveInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());
        $I->haveInDatabase(
            'sharing_group_orgs',
            [
                'sharing_group_id' => $sharingGroupId,
                'org_id' => $remoteOrgId,
                'extend' => 0
            ]
        );

        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'uuid' => $eventUuid,
                'org_id' => $remoteOrgId,
                'published' => true,
                'distribution' => '4',
                'sharing_group_id' => $sharingGroupId
            ]
        );
        $fakeAttribute = AttributeFixture::fake(
            [
                'uuid' => $attributeUuid,
                'event_id' => $eventId,
                'deleted' => false,
                'distribution' => '4'
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->mockGetServerVersionRequest();
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
    }

    private function mockRemoteServerPushRequests(
        WireMock $wiremock,
        EventFixture $event
    ): void {
        $eventResponse = $event->toResponse();

        $wiremock->stubFor(WireMock::post(WireMock::urlEqualTo('/events/filterEventIdsForPush'))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody(
                    (string)json_encode(
                        [$eventResponse['uuid']]
                    )
                )));

        $wiremock->stubFor(WireMock::head(WireMock::urlEqualTo(
            sprintf('/events/view/%s', $eventResponse['uuid'])
        ))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody('[]')));

        $wiremock->stubFor(WireMock::post(WireMock::urlEqualTo(
            sprintf('/events/edit/%s/metadata:1', $event->toResponse()['uuid'])
        ))
            ->withRequestBody(WireMock::equalToJson(
                (string)json_encode(['Event' => [
                    'id' => $eventResponse['id'],
                    'uuid' => $eventResponse['uuid']
                ]]),
                true,
                true
            ))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody('{}')));

        $wiremock->stubFor(WireMock::post(WireMock::urlEqualTo('/events/index'))
            ->withRequestBody(WireMock::equalToJson(
                (string)json_encode([
                    'minimal' => 1,
                    'published' => 1
                ])
            ))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody('[]')));
    }
}
