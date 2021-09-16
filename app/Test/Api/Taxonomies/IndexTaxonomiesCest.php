<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TaxonomyFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexTaxonomiesCest
{

    private const URL = '/taxonomies';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedTaxonomy(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeTaxonomy = TaxonomyFixture::fake();
        $I->haveInDatabase('taxonomies', $fakeTaxonomy->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['Taxonomy' => $fakeTaxonomy->toResponse()]]);
    }
}
