<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class EditServersCest
{

    private const URL = '/servers/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $serverId = 1;
        $I->sendPut(sprintf(self::URL, $serverId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEdit(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $remoteOrgId = 2;
        $remoteOrg = OrganisationFixture::fake(['id' => $remoteOrgId]);
        $serverId = 1;
        $fakeServer = ServerFixture::fake(
            [
                'id' => (string)$serverId,
                'org_id' => (string)$orgId,
                'remote_org_id' => (string)$remoteOrgId
            ]
        );
        $I->haveInDatabase('organisations', $remoteOrg->toDatabase());
        $I->haveInDatabase('servers', $fakeServer->toDatabase());

        $fakeServer->set(['name' => 'foobar', 'url' => 'http://foobar.local']);

        $I->sendPut(sprintf(self::URL, $serverId), $fakeServer->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Server' => $fakeServer->toResponse()]);
        $I->seeInDatabase('servers', $fakeServer->toDatabase());
    }
}
