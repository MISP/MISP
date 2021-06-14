<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\OrganisationFixture;

class ViewOrganisationCest
{

    private const URL = '/organisations/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $organisationId = 1;
        $I->sendGet(sprintf(self::URL, $organisationId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedOrganisation(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $fakeOrg = OrganisationFixture::fake(['id' => (string)$orgId]);

        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN, null, $fakeOrg);

        $I->sendGet(sprintf(self::URL, $orgId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Organisation' => $fakeOrg->toResponse()]);
    }
}
