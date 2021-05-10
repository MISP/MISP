<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class ViewOrganisationCest
{

    private const URL = '/organisations/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedOrganisation(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $fakeOrg = OrganisationFixture::fake(['id' => $orgId]);

        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN, null, $fakeOrg);

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Organisation' => $fakeOrg->toResponse()]);
    }
}
