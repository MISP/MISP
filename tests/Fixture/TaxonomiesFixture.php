<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TaxonomiesFixture extends TestFixture
{
    public $connection = 'test';

    public const TAXONOMY_1_ID = 1000;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::TAXONOMY_1_ID,
                'namespace' => 'test',
                'description' => 'Test Taxonomy',
                'version' => '1',
                'enabled' => true,
                'exclusive' => false,
                'required' => false,
                'highlighted' => false,
            ]
        ];
        parent::init();
    }
}
