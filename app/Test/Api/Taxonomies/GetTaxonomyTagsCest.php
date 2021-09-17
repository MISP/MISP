<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TaxonomyFixture;
use \Helper\Fixture\Data\TaxonomyEntryFixture;
use \Helper\Fixture\Data\TaxonomyPredicateFixture;
use \Helper\Fixture\Data\UserFixture;

class GetTaxonomyTagsCest
{

    private const URL = '/taxonomies/taxonomy_tags/%s';

    public function testGetTaxonomyTagsReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $taxonomyId = 1;
        $I->sendGet(sprintf(self::URL, $taxonomyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testGetTaxonomyTags(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $taxonomyId = 1;
        $taxonomyPredicateId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeTaxonomy = TaxonomyFixture::fake(['id' => $taxonomyId, 'namespace' => 'foo']);
        $fakeTaxonomyPredicate = TaxonomyPredicateFixture::fake([
            'id' => $taxonomyPredicateId,
            'taxonomy_id' => $taxonomyId,
            'value' => 'bar'
        ]);
        $fakeTaxonomyEntry = TaxonomyEntryFixture::fake([
            'taxonomy_predicate_id' => $taxonomyPredicateId,
            'value' => 'leet'
        ]);
        $I->haveInDatabase('taxonomies', $fakeTaxonomy->toDatabase());
        $I->haveInDatabase('taxonomy_predicates', $fakeTaxonomyPredicate->toDatabase());
        $I->haveInDatabase('taxonomy_entries', $fakeTaxonomyEntry->toDatabase());

        $I->sendGet(sprintf(self::URL, $taxonomyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Taxonomy' => $fakeTaxonomy->toResponse(),
                'entries' => [
                    [
                        'tag' => 'foo:bar="leet"',
                        'events' => 0,
                        'attributes' => 0
                    ]
                ]
            ]
        );
    }
}
