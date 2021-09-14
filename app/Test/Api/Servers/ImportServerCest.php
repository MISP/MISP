<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class ImportServerCest
{

    private const URL = '/servers/import';

    public function testCreateSyncReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testCreateSync(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $remoteOrgId = 999;
        $remoteOrgName = 'TestOrga';
        $serverName = 'test';
        $serverUrl = 'http://localhost.local';
        $serverUuid = 'b9d6cf55-463e-49f2-9fc6-ede94419abbd';
        $serverAuthkey = '8843d7f92416211de9ebb963ff4ce28125932878';

        $fakeOrg = OrganisationFixture::fake(['id' => $remoteOrgId, 'name' => $remoteOrgName]);
        $I->haveInDatabase('organisations', $fakeOrg->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'name' => $serverName,
                'url' => $serverUrl,
                'uuid' => $serverUuid,
                'authkey' => $serverAuthkey,
                'Organisation' => [
                    'name' => $remoteOrgName
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Server' => [
            'name' => $serverName,
            'url' => $serverUrl,
            // 'uuid' => $serverUuid,
            'authkey' => $serverAuthkey,
            'remote_org_id' => (string)$remoteOrgId
        ]]);

        $I->seeInDatabase('servers', [
            'name' => $serverName,
            'url' => $serverUrl,
            // 'uuid' => $serverUuid,
            'authkey' => $serverAuthkey,
            'remote_org_id' => (string)$remoteOrgId
        ]);
    }
}
