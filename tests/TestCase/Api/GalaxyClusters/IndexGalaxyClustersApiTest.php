<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;

class IndexGalaxyClustersApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusters/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Galaxies',
        'app.GalaxyClusters',
        'app.GalaxyElements',
        'app.GalaxyClusterRelations',
        'app.GalaxyClusterRelationTags',
        'app.Tags',
    ];

    public function testIndexGalaxyClusters(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxiesFixture::GALAXY_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $galaxyClusters = $this->getJsonResponseAsArray();

        $this->assertEquals(1, count($galaxyClusters));
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_ID, $galaxyClusters[0]['id']);
        $this->assertEquals(GalaxiesFixture::GALAXY_1_ID, $galaxyClusters[0]['galaxy_id']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxyClusters[0]['uuid']);
    }
}
