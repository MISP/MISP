<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TaxonomyFixture;
use \Helper\Fixture\Data\TaxonomyEntryFixture;
use \Helper\Fixture\Data\TaxonomyPredicateFixture;
use \Helper\Fixture\Data\UserFixture;

class DisableTaxonomyCest
{

    private const URL = '/taxonomies/disable/%s';

    public function testDisableReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $taxonomyId = 1;
        $I->sendPost(sprintf(self::URL, $taxonomyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDisableTaxonomy(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $taxonomyId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeTaxonomy = TaxonomyFixture::fake(['id' => $taxonomyId, 'enabled' => true]);
        $I->haveInDatabase('taxonomies', $fakeTaxonomy->toDatabase());

        $I->sendPost(sprintf(self::URL, $taxonomyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => "Taxonomy disabled",
                'message' => "Taxonomy disabled",
                'url' => sprintf(self::URL, $taxonomyId),
            ]
        );
        $I->seeInDatabase('taxonomies', ['id' => $taxonomyId, 'enabled' => false]);
    }
}
