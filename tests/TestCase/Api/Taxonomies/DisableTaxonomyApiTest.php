<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\TaxonomiesFixture;
use App\Test\Helper\ApiTestTrait;

class DisableTaxonomyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/disable';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
        'app.TaxonomyPredicates',
        'app.TaxonomyEntries',
    ];

    public function testDisableTaxonomy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, TaxonomiesFixture::TAXONOMY_1_ID);

        $this->assertDbRecordExists('Taxonomies', ['id' => TaxonomiesFixture::TAXONOMY_1_ID, 'enabled' => true]);

        # disable
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Taxonomy disabled"');
        $this->assertDbRecordExists('Taxonomies', ['id' => TaxonomiesFixture::TAXONOMY_1_ID, 'enabled' => false]);
    }
}
