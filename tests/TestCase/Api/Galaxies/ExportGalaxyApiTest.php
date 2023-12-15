<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Fixture\GalaxyClustersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ExportGalaxyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/export';

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

    public function testExportGalaxyMispFormat(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, GalaxiesFixture::GALAXY_1_UUID);
        $this->post(
            $url,
            [
                "Galaxy" => [
                    "default" => false,
                    "custom" => false,
                    "distribution" => "0",
                    "format" => "misp-galaxy",
                    "download" => false
                ]
            ]
        );

        $this->assertResponseOk();
        $galaxy = $this->getJsonResponseAsArray();

        $this->assertEquals(GalaxiesFixture::GALAXY_1_UUID, $galaxy['uuid']);
        $this->assertEquals(GalaxiesFixture::GALAXY_1_NAME, $galaxy['name']);

        # check that the galaxy has the correct clusters exported
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxy['values'][0]['uuid']);
        $this->assertEquals('test-fixture-cluster-1', $galaxy['values'][0]['value']);

        # check that the galaxy has the correct elements exported
        $this->assertEquals('test-fixture-element-value', $galaxy['values'][0]['meta']['test-fixture-element-key']);

        # check that the galaxy has the correct relations exported
        $this->assertEquals(GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID, $galaxy['values'][0]['related'][0]['dest-uuid']);
        $this->assertEquals('similar', $galaxy['values'][0]['related'][0]['type']);

        # check that the galaxy has the correct relation tags exported
        $this->assertEquals('test:tag', $galaxy['values'][0]['related'][0]['tags'][0]);
    }
}
