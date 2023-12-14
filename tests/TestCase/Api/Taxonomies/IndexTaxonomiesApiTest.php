<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Taxonomies;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\TaxonomiesFixture;
use App\Test\Helper\ApiTestTrait;

class IndexTaxonomiesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/taxonomies/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Taxonomies',
    ];

    public function testIndexTaxonomies(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', TaxonomiesFixture::TAXONOMY_1_ID));
    }
}
