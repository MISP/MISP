<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class EditOrganisationCest
{

    private const URL = '/admin/organisations/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $I->sendPut(sprintf(self::URL, $orgId));

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

        $fakeOrgId = 2;
        $fakeOrg = OrganisationFixture::fake(
            [
                'id' => (string)$fakeOrgId,
                'name' => 'foo org',
            ]
        );
        $I->haveInDatabase('organisations', $fakeOrg->toDatabase());

        $fakeOrg->set(['name' => 'bar org']);

        $I->sendPut(sprintf(self::URL, $fakeOrgId), $fakeOrg->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeOrg->set([
            'date_modified' => $I->grabDataFromResponseByJsonPath('$..Organisation.date_modified')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $response = $fakeOrg->toResponse();
        // unset($response['restricted_to_domain']);
        // $I->seeResponseContainsJson(['Organisation' => $fakeOrg->toResponse()]);
        $I->seeResponseContainsJson(['Organisation' => $response]);
    }
}
