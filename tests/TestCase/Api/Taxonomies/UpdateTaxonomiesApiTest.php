<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Core\Configure;
use Cake\TestSuite\TestCase;

class UpdateTaxonomiesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/update';

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

    public function testUpdateTaxonomies(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        Configure::write('MISP.custom_taxonomies_path', '/var/www/html/tests/Libraries/misp-taxonomies/');

        $this->assertDbRecordNotExists('Taxonomies', ['namespace' => 'test-library-taxonomy-1']);

        $this->post(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Taxonomies',
            [
                'namespace' => 'test-library-taxonomy-1',
                'description' => 'Test Taxonomy Library 1',
                'version' => '1'
            ]
        );

        # check that the taxonomy has the correct predicates
        $this->assertDbRecordExists(
            'TaxonomyPredicates',
            [
                'value' => 'test-library-predicate-1',
                'expanded' => 'Test Taxonomy Library Predicate 1',
            ]
        );

        # check that the galaxy has the correct elements
        $this->assertDbRecordExists(
            'TaxonomyEntries',
            [
                'value' => 'test-library-entry-1',
                'expanded' => 'Test Taxonomy Library Entry 1',
            ]
        );
    }
}
