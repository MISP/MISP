<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\TaxonomiesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EnableTaxonomyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/enable';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
        'app.TaxonomyPredicates',
        'app.TaxonomyEntries',
    ];

    public function testEnableTaxonomy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, TaxonomiesFixture::TAXONOMY_2_ID);

        $this->assertDbRecordExists('Taxonomies', ['id' => TaxonomiesFixture::TAXONOMY_2_ID, 'enabled' => false]);

        # enable
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Taxonomy enabled"');
        $this->assertDbRecordExists('Taxonomies', ['id' => TaxonomiesFixture::TAXONOMY_2_ID, 'enabled' => true]);
    }
}
