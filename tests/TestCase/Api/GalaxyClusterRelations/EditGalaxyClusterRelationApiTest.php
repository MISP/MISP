<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Model\Entity\GalaxyClusterRelation;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Fixture\GalaxyClusterRelationsFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EditGalaxyClusterRelationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusterRelations/edit';

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

    public function testEditGalaxyClusterRelation(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $jsonGalaxyClusterRelation = [
            'distribution' => '0',
            'galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
            'referenced_galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
            'referenced_galaxy_cluster_type' => 'test-relation-type-edited',
            'galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID
        ];

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID);
        $this->post($url, $jsonGalaxyClusterRelation);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'GalaxyClusterRelations',
            [
                'id' => GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID,
                'galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
                'referenced_galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
                'referenced_galaxy_cluster_type' => 'test-relation-type-edited',
                'galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID
            ]
        );
    }
}
