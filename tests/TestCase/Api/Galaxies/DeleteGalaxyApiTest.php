<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteGalaxyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/delete';

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

    public function testDeleteGalaxy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, GalaxiesFixture::GALAXY_1_UUID);
        $this->post($url);

        $this->assertResponseOk();

        $this->assertDbRecordNotExists(
            'Galaxies',
            [
                'id' => GalaxiesFixture::GALAXY_1_ID
            ]
        );

        $this->assertDbRecordNotExists(
            'GalaxyClusters',
            [
                'id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID
            ]
        );

        // TODO: should cluster relations be deleted?
        // $this->assertDbRecordNotExists(
        //     'GalaxyClusterRelations',
        //     [
        //         'id' => GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID
        //     ]
        // );
        // $this->assertDbRecordNotExists(
        //     'GalaxyClusterRelationTags',
        //     [
        //         'id' => GalaxyClusterRelationTagsFixture::GALAXY_CLUSTER_RELATION_TAG_1_ID
        //     ]
        // );
    }
}
