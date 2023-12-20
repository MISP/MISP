<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\TaxonomiesFixture;
use App\Test\Fixture\TaxonomyEntriesFixture;
use App\Test\Fixture\TaxonomyPredicatesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ExportTaxonomyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/export';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
        'app.TaxonomyPredicates',
        'app.TaxonomyEntries',
        'app.Tags',
    ];

    public function testExportTaxonomy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, TaxonomiesFixture::TAXONOMY_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $taxonomy = $this->getJsonResponseAsArray();

        $this->assertEquals(TaxonomiesFixture::TAXONOMY_1_NAMESPACE, $taxonomy['namespace']);

        # check that the taxonomy has the correct predicates exported
        $this->assertEquals(TaxonomyPredicatesFixture::TAXONOMY_PREDICATE_1_VALUE, $taxonomy['predicates'][0]['value']);

        # check that the taxonomy has the correct entries exported
        $this->assertEquals(TaxonomyPredicatesFixture::TAXONOMY_PREDICATE_1_VALUE, $taxonomy['values'][0]['predicate']);
        $this->assertEquals(TaxonomyEntriesFixture::TAXONOMY_ENTRY_1_VALUE, $taxonomy['values'][0]['entry'][0]['value']);
    }
}
