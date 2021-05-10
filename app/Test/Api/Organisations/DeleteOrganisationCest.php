<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class DeleteOrganisationCest
{

    private const URL = '/admin/organisations/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $I->sendDelete(sprintf(self::URL, $orgId));

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

        $fakeOrgId = 2;
        $fakeOrg = OrganisationFixture::fake(['id' => (string)$fakeOrgId,]);
        $I->haveInDatabase('organisations', $fakeOrg->toDatabase());

        $I->sendDelete(sprintf(self::URL, $fakeOrgId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Organisation deleted',
                'message' => 'Organisation deleted',
                'url' => sprintf(self::URL, $fakeOrgId),
            ]
        );
        $I->cantSeeInDatabase('organisations', ['id' => $fakeOrgId]);
    }
}
