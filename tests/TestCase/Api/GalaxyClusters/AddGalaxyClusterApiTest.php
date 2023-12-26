<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusters;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddGalaxyClusterApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusters/add';

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

    public function testAddGalaxyCluster(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $jsonGalaxyCluster = [
            'value' => 'test-value',
            'description' => 'test-description',
        ];

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxiesFixture::GALAXY_1_ID);
        $this->post($url, $jsonGalaxyCluster);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'GalaxyClusters',
            [
                'value' => 'test-value',
                'description' => 'test-description',
            ]
        );
    }
}
