<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EditGalaxyClusterApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusters/edit';

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

    public function testEditGalaxyCluster(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $jsonGalaxyCluster = [
            'value' => 'new-value',
        ];

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClustersFixture::GALAXY_CLUSTER_1_ID);
        $this->post($url, $jsonGalaxyCluster);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'GalaxyClusters',
            [
                'id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID,
                'value' => 'new-value',
            ]
        );
    }
}
