<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteGalaxyClusterApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusters/delete';

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

    public function testDeleteGalaxyCluster(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->assertDbRecordExists(
            'GalaxyClusters',
            [
                'id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID,
                'deleted' => false
            ]
        );

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClustersFixture::GALAXY_CLUSTER_1_ID);
        $this->post($url);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'GalaxyClusters',
            [
                'id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID,
                'deleted' => true
            ]
        );
    }
}
