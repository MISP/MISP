<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class PushGalaxyClusterApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/pushCluster';

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

    public function testUpdateGalaxies(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $jsonGalaxyCluster = [
            [
                "GalaxyCluster" => [
                    "value" => "foo",
                    "description" => "bar",
                    "distribution" => "0",
                    "type" => "botnet",
                    "uuid" => "06251f72-9d60-43b5-a28a-48a2e0452d1e",
                    "collection_uuid" => "d985d2eb-d6ad-4b44-9c69-44eb90095e23",
                    "default" => false,
                    "version" => "1",
                    "tag_name" => "misp-galaxy:test-type=\"test-cluster-1\"",
                    "Galaxy" => [
                        "uuid" => "c51c59e9-f213-4ad4-9913-09a43d78dff5",
                        "type" => "type",
                        "description" => "description",
                        "version" => "1"
                    ],
                    "GalaxyElement" => [
                        [
                            "key" => "test-pushed-element-key",
                            "value" => "test-pushed-element-value"
                        ]
                    ],
                    "GalaxyClusterRelation" => [
                        [
                            "Tag" => [
                                [
                                    "name" => "foo:bar"
                                ]
                            ],
                            "referenced_galaxy_cluster_uuid" => "06251f72-9d60-43b5-a28a-48a2e0452d1e",
                            "referenced_galaxy_cluster_type" => "self-referenced-cluster-type"
                        ]
                    ]
                ]
            ]
        ];

        $this->post(self::ENDPOINT, $jsonGalaxyCluster);

        $this->assertResponseOk();
        $this->assertDbRecordExists('Galaxies', [
            'uuid' => 'c51c59e9-f213-4ad4-9913-09a43d78dff5'
        ]);

        // # check that the galaxy has the correct clusters
        $this->assertDbRecordExists('GalaxyClusters', [
            'uuid' => '06251f72-9d60-43b5-a28a-48a2e0452d1e'
        ]);

        # check that the galaxy has the correct elements
        $this->assertDbRecordExists('GalaxyElements', [
            'key' => 'test-pushed-element-key',
            'value' => 'test-pushed-element-value'
        ]);

        // # check that the galaxy has the correct relations
        $this->assertDbRecordExists('GalaxyClusterRelations', [
            'referenced_galaxy_cluster_uuid' => '06251f72-9d60-43b5-a28a-48a2e0452d1e',
            'referenced_galaxy_cluster_type' => 'self-referenced-cluster-type',
            'galaxy_cluster_uuid' => '06251f72-9d60-43b5-a28a-48a2e0452d1e'
        ]);

        # check that the galaxy has the correct tags
        $this->assertDbRecordExists('Tags', [
            'name' => 'foo:bar'
        ]);
    }
}
