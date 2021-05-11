<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class DeleteServersCest
{

    private const URL = '/servers/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $serverId = 1;
        $I->sendPost(sprintf(self::URL, $serverId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $serverId = 1;
        $remoteOrgId = 2;
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId]);
        $fakeServer = ServerFixture::fake(
            [
                'id' => $serverId,
                'org_id' => $orgId,
                'remote_org_id' => $remoteOrgId
            ]
        );
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());

        $I->sendPost(sprintf(self::URL, $serverId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Server deleted',
                'message' => 'Server deleted',
                'url' => sprintf(self::URL, $serverId),
            ]
        );
        $I->cantSeeInDatabase('servers', ['id' => $serverId]);
    }
}
