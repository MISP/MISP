<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class GalaxyClusterRelationTagsFixture extends TestFixture
{
    public $connection = 'test';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [];
        parent::init();
    }
}
