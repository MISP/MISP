<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ImportTaxonomyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/import';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
        'app.TaxonomyPredicates',
        'app.TaxonomyEntries',
        'app.Tags',
    ];

    public function testImportTaxonomy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $jsonTaxonomy = [
            "namespace" => "test-imported-taxonomy",
            "description" => "Test Imported Taxonomy",
            "version" => 1,
            "predicates" => [
                [
                    "value" => "test-imported-predicate",
                    "expanded" => "Test Imported Predicate"
                ]
            ],
            "values" => [
                [
                    "predicate" => "test-imported-predicate",
                    "entry" => [
                        [
                            "value" => "test-imported-entry",
                            "expanded" => "Test Imported Entry"
                        ]
                    ]
                ]
            ]
        ];

        $this->post(self::ENDPOINT, $jsonTaxonomy);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Taxonomies',
            [
                'namespace' => 'test-imported-taxonomy'
            ]
        );

        // # check that the taxonomy has the correct predicates
        $this->assertDbRecordExists(
            'TaxonomyPredicates',
            [
                'value' => 'test-imported-predicate'
            ]
        );

        # check that the taxonomy has the correct entries
        $this->assertDbRecordExists(
            'TaxonomyEntries',
            [
                'value' => 'test-imported-entry'
            ]
        );
    }
}
