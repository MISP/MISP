<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class AddOrganisationCest
{

    private const URL = '/admin/organisations/add';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAdd(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeOrg = OrganisationFixture::fake(
            [
                'created_by' => (string)$userId,
                'restricted_to_domain' => 'example.com'
            ]
        );

        $I->sendPost(self::URL, $fakeOrg->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeOrg->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..Organisation.id')[0],
            'date_created' => $I->grabDataFromResponseByJsonPath('$..Organisation.date_created')[0],
            'date_modified' => $I->grabDataFromResponseByJsonPath('$..Organisation.date_modified')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Organisation' => $fakeOrg->toResponse()]);
        $I->seeInDatabase('organisations', $fakeOrg->toDatabase());
    }
}
