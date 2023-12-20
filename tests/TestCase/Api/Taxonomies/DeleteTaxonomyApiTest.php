<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\TaxonomiesFixture;
use App\Test\Fixture\TaxonomyPredicatesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteTaxonomyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
        'app.TaxonomyPredicates',
        'app.TaxonomyEntries',
    ];

    public function testDeleteTaxonomy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, TaxonomiesFixture::TAXONOMY_1_ID);
        $this->post($url);

        // TODO: handle API request
        // $this->assertResponseOk();

        $this->assertDbRecordNotExists(
            'Taxonomies',
            [
                'id' => TaxonomiesFixture::TAXONOMY_1_ID
            ]
        );
        $this->assertDbRecordNotExists(
            'TaxonomyPredicates',
            [
                'id' => TaxonomyPredicatesFixture::TAXONOMY_PREDICATE_1_ID
            ]
        );

        // TODO: taxonomies entries are not deleted, should they be?
        // $this->assertDbRecordNotExists(
        //     'TaxonomyEntries',
        //     [
        //         'id' => TaxonomyEntriesFixture::TAXONOMY_ENTRY_1_ID
        //     ]
        // );
    }
}
