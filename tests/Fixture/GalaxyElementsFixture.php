<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class GalaxyElementsFixture extends TestFixture
{
    public $connection = 'test';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'galaxy_cluster_id' => GalaxyClustersFixture::GALAXY_CLUSTER_1_ID,
                'key' => 'test-fixture-element-key',
                'value' => 'test-fixture-element-value',
            ]
        ];
        parent::init();
    }
}
