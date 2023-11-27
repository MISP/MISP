<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClusterRelationsFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Fixture\TagsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewGalaxyClusterRelationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusterRelations/view';

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

    public function testViewGalaxyClusterRelationById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClustersFixture::GALAXY_CLUSTER_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $galaxyClusterRelation = $this->getJsonResponseAsArray();

        $this->assertEquals(GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID, $galaxyClusterRelation['id']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxyClusterRelation['referenced_galaxy_cluster_uuid']);
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxyClusterRelation['galaxy_cluster_uuid']);
        $this->assertEquals('similar', $galaxyClusterRelation['referenced_galaxy_cluster_type']);

        # check that the galaxy has the correct tags
        $this->assertEquals(TagsFixture::TAG_1_ID, $galaxyClusterRelation['Tag'][0]['id']);
        $this->assertEquals('test:tag', $galaxyClusterRelation['Tag'][0]['Tag']['name']);
    }
}
