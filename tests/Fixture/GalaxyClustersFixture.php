<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use App\Test\Fixture\GalaxiesFixture;
use Cake\TestSuite\Fixture\TestFixture;

class GalaxyClustersFixture extends TestFixture
{
    public $connection = 'test';

    public const GALAXY_CLUSTER_1_ID = 1000;
    public const GALAXY_CLUSTER_1_UUID = 'c00941d0-d4ae-42cc-bac8-c240b809bd8f';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::GALAXY_CLUSTER_1_ID,
                'galaxy_id' => GalaxiesFixture::GALAXY_1_ID,
                'uuid' => self::GALAXY_CLUSTER_1_UUID,
                'description' => 'Test description fixture cluster 1',
                'source' => 'test-fixture-source',
                'type' => 'test-fixture-type',
                'authors' => '["test-fixture-author"]',
                'collection_uuid' => GalaxiesFixture::GALAXY_1_UUID,
                'value' => 'test-fixture-cluster-1',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'orgc_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'default' => true
            ]
        ];
        parent::init();
    }
}
