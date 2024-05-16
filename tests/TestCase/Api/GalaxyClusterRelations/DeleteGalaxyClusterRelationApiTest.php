<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\GalaxyClusterRelations;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxyClusterRelationsFixture;
use App\Test\Fixture\GalaxyClusterRelationTagsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteGalaxyClusterRelationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxyClusterRelations/delete';

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

    public function testEditGalaxyClusterRelation(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID);
        $this->post($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists(
            'GalaxyClusterRelations',
            [
                'id' => GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID
            ]
        );
        $this->assertDbRecordNotExists(
            'GalaxyClusterRelationTags',
            [
                'id' => GalaxyClusterRelationTagsFixture::GALAXY_CLUSTER_RELATION_TAG_1_ID
            ]
        );
    }
}
