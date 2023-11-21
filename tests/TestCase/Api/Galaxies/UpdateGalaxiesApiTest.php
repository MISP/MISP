<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Core\Configure;
use Cake\TestSuite\TestCase;

class UpdateGalaxiesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/update';

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

        Configure::write('MISP.custom_galaxies_path', '/var/www/html/tests/libraries/misp-galaxy/galaxies/*.json');
        Configure::write('MISP.custom_galaxy_clusters_path', '/var/www/html/tests/libraries/misp-galaxy/clusters/*.json');

        $this->assertDbRecordNotExists('Galaxies', ['name' => 'test-library-galaxy-1']);

        $this->post(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Galaxies',
            [
                'name' => 'test-library-galaxy-1',
                'icon' => 'user-secret',
                'namespace' => 'test-namespace',
                'type' =>  'test-type',
                'uuid' => '090874b1-b9bd-4ed4-b9b7-c3a1982dcea8',
                'version' => '1'
            ]
        );

        # check that the galaxy has the correct clusters
        $this->assertDbRecordExists(
            'GalaxyClusters',
            [
                'uuid' => 'b99d5a56-b761-4410-9cb8-6d1628fe7ca3',
                'description' => 'Test description cluster 1',
                'source' => 'test-source',
                'type' => 'test-type'
            ]
        );

        # check that the galaxy has the correct elements
        $this->assertDbRecordExists(
            'GalaxyElements',
            [
                'key' => 'country',
                'value' => 'test-country'
            ]
        );
        $this->assertDbRecordExists(
            'GalaxyElements',
            [
                'key' => 'refs',
                'value' => 'ref-1'
            ]
        );
        $this->assertDbRecordExists(
            'GalaxyElements',
            [
                'key' => 'suspected-victims',
                'value' => 'suspected-victim-1'
            ]
        );
        $this->assertDbRecordExists(
            'GalaxyElements',
            [
                'key' => 'target-category',
                'value' => 'target-category-1'
            ]
        );

        # check that the galaxy has the correct relations
        $this->assertDbRecordExists(
            'GalaxyClusterRelations',
            [
                'referenced_galaxy_cluster_uuid' => '8fd92fe2-1bed-43a0-b885-b1630e21dc2f',
                'referenced_galaxy_cluster_type' => 'similar',
                'galaxy_cluster_uuid' => 'b99d5a56-b761-4410-9cb8-6d1628fe7ca3'
            ]
        );

        # check that the galaxy has the correct tags
        $this->assertDbRecordExists(
            'Tags',
            [
                'name' => 'test-galaxy-cluster-tag-namespace:test-galaxy-cluster-tag-value'
            ]
        );
    }
}
