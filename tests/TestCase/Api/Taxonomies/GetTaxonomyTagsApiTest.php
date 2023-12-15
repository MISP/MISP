<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\TaxonomiesFixture;
use App\Test\Fixture\TaxonomyEntriesFixture;
use App\Test\Fixture\TaxonomyPredicatesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class GetTaxonomyTagsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/taxonomy_tags';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
        'app.TaxonomyPredicates',
        'app.TaxonomyEntries',
        'app.Tags',
    ];

    public function testGetTaxonomyTagsById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, TaxonomiesFixture::TAXONOMY_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $taxonomy = $this->getJsonResponseAsArray();

        $this->assertEquals(TaxonomiesFixture::TAXONOMY_1_ID, $taxonomy['Taxonomy']['id']);
        $this->assertEquals(TaxonomiesFixture::TAXONOMY_1_NAMESPACE, $taxonomy['Taxonomy']['namespace']);

        $tag = sprintf(
            '%s:%s="%s"',
            $taxonomy['Taxonomy']['namespace'],
            $taxonomy['Taxonomy']['TaxonomyPredicate'][0]['value'],
            $taxonomy['Taxonomy']['TaxonomyPredicate'][0]['TaxonomyEntry'][0]['value']
        );
        $this->assertEquals($tag, $taxonomy['entries'][0]['tag']);
    }
}
