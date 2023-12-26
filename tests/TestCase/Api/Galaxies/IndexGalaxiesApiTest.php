<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexGalaxiesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Galaxies',
        'app.GalaxyClusters',
        'app.GalaxyElements',
        'app.GalaxyClusterRelations',
        'app.GalaxyClusterRelationTags',
        'app.Tags',
    ];

    public function testIndexGalaxies(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', GalaxiesFixture::GALAXY_1_NAME));
        $this->assertResponseContains(sprintf('"name": "%s"', GalaxiesFixture::GALAXY_2_NAME));
    }
}
