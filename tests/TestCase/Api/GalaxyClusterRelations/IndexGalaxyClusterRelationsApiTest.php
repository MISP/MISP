<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClusterRelationsFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexGalaxyClusterRelationsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusterRelations/index';

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

    public function testIndexGalaxyClusterRelations(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClustersFixture::GALAXY_CLUSTER_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $galaxyClusterRelations = $this->getJsonResponseAsArray();

        $this->assertEquals(1, count($galaxyClusterRelations));
        $this->assertEquals(GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID, $galaxyClusterRelations[0]['id']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_ID, $galaxyClusterRelations[0]['galaxy_cluster_id']);
    }
}
