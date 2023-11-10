<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewGalaxyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/view';

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

    public function testViewGalaxyById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, GalaxiesFixture::GALAXY_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $galaxy = $this->getJsonResponseAsArray();

        $this->assertEquals(GalaxiesFixture::GALAXY_1_ID, $galaxy['id']);
        $this->assertEquals(GalaxiesFixture::GALAXY_1_NAME, $galaxy['name']);

        # check that the galaxy has the correct clusters
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxy['GalaxyCluster'][0]['uuid']);
        $this->assertEquals(GalaxiesFixture::GALAXY_1_ID, $galaxy['GalaxyCluster'][0]['galaxy_id']);

        # check that the galaxy has the correct elements
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_ID, $galaxy['GalaxyCluster'][0]['GalaxyElement'][0]['galaxy_cluster_id']);
        $this->assertEquals('test-fixture-element-key', $galaxy['GalaxyCluster'][0]['GalaxyElement'][0]['key']);
        $this->assertEquals('test-fixture-element-value', $galaxy['GalaxyCluster'][0]['GalaxyElement'][0]['value']);

        # TODO: check that the galaxy has the correct relations
        # TODO: check that the galaxy has the correct tags
    }
}
