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

    public const GALAXY_CLUSTER_2_ID = 2000;
    public const GALAXY_CLUSTER_2_UUID = '21e9b2f8-fe0e-418c-810c-e91887f8fd6c';

    public const GALAXY_CLUSTER_3_ID = 3000;
    public const GALAXY_CLUSTER_3_UUID = '708edca0-e2fd-495a-b268-a2bf49e9c67d';

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
                'default' => true,
                'published' => true,
                'deleted' => false
            ],
            [
                'id' => self::GALAXY_CLUSTER_2_ID,
                'galaxy_id' => GalaxiesFixture::GALAXY_2_ID,
                'uuid' => self::GALAXY_CLUSTER_2_UUID,
                'description' => 'Test description fixture cluster 2',
                'source' => 'test-fixture-source',
                'type' => 'test-fixture-type',
                'authors' => '["test-fixture-author"]',
                'collection_uuid' => GalaxiesFixture::GALAXY_2_UUID,
                'value' => 'test-fixture-cluster-2',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'orgc_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'default' => false,
                'published' => false,
                'deleted' => true
            ],
            [
                'id' => self::GALAXY_CLUSTER_3_ID,
                'galaxy_id' => GalaxiesFixture::GALAXY_2_ID,
                'uuid' => self::GALAXY_CLUSTER_2_UUID,
                'description' => 'Test description fixture cluster 3',
                'source' => 'test-fixture-source',
                'type' => 'test-fixture-type',
                'authors' => '["test-fixture-author"]',
                'collection_uuid' => GalaxiesFixture::GALAXY_2_UUID,
                'value' => 'test-fixture-cluster-3',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'orgc_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'default' => false,
                'published' => true,
                'deleted' => false
            ]
        ];
        parent::init();
    }
}
