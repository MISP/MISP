<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClusterRelationsFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Fixture\TagsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewGalaxyClusterApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusters/view';

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

    public function testViewGalaxyClusterById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClustersFixture::GALAXY_CLUSTER_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $galaxyCluster = $this->getJsonResponseAsArray();

        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_ID, $galaxyCluster['id']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxyCluster['uuid']);

        # check that the galaxy has the correct elements
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_ID, $galaxyCluster['GalaxyCluster']['GalaxyElement'][0]['galaxy_cluster_id']);
        $this->assertEquals('test-fixture-element-key', $galaxyCluster['GalaxyCluster']['GalaxyElement'][0]['key']);
        $this->assertEquals('test-fixture-element-value', $galaxyCluster['GalaxyCluster']['GalaxyElement'][0]['value']);

        # check that the galaxy has the correct relations
        $this->assertEquals(GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID, $galaxyCluster['GalaxyCluster']['GalaxyClusterRelation'][0]['id']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_ID, $galaxyCluster['GalaxyCluster']['GalaxyClusterRelation'][0]['referenced_galaxy_cluster_id']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxyCluster['GalaxyCluster']['GalaxyClusterRelation'][0]['referenced_galaxy_cluster_uuid']);
        $this->assertEquals('similar', $galaxyCluster['GalaxyCluster']['GalaxyClusterRelation'][0]['referenced_galaxy_cluster_type']);

        # check that the galaxy has the correct tags
        $this->assertEquals(TagsFixture::TAG_1_ID, $galaxyCluster['GalaxyCluster']['GalaxyClusterRelation'][0]['Tag'][0]['id']);
        $this->assertEquals('test:tag', $galaxyCluster['GalaxyCluster']['GalaxyClusterRelation'][0]['Tag'][0]['Tag']['name']);
    }
}
