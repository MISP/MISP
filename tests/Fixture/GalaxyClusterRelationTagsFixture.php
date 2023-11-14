<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class GalaxyClusterRelationTagsFixture extends TestFixture
{
    public $connection = 'test';

    public const GALAXY_CLUSTER_RELATION_TAG_1_ID = 1000;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::GALAXY_CLUSTER_RELATION_TAG_1_ID,
                'galaxy_cluster_relation_id' => GalaxyClusterRelationsFixture::GALAXY_CLUSTER_RELATION_1_ID,
                'tag_id' => TagsFixture::TAG_1_ID,
            ]
        ];
        parent::init();
    }
}
