<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddGalaxyClusterRelationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusterRelations/add';

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

    public function testAddGalaxyClusterRelation(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $jsonGalaxyClusterRelation = [
            'distribution' => '0',
            'galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
            'referenced_galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_2_UUID,
            'referenced_galaxy_cluster_type' => 'test-relation-type',
            'galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID
        ];

        $this->post(self::ENDPOINT, $jsonGalaxyClusterRelation);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'GalaxyClusterRelations',
            [
                'galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
                'referenced_galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_2_UUID,
                'referenced_galaxy_cluster_type' => 'test-relation-type',
                'galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID
            ]
        );
    }
}
