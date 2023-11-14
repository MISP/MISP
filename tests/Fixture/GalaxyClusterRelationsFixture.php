<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class GalaxyClusterRelationsFixture extends TestFixture
{
    public $connection = 'test';

    public const GALAXY_CLUSTER_RELATION_1_ID = 1000;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::GALAXY_CLUSTER_RELATION_1_ID,
                'galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID,
                'referenced_galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID,
                'referenced_galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
                'referenced_galaxy_cluster_type' => 'similar',
                'galaxy_cluster_uuid' => GalaxyClustersFixture::GALAXY_CLUSTER_1_UUID,
                'distribution' => '0',
                'sharing_group_id' => null,
                'default' => false,
            ]
        ];
        parent::init();
    }
}
